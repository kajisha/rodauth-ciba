// Independently verify synthetic tokens issued by the installed Ruby gem.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { calculateJwkThumbprint, createLocalJWKSet, jwtVerify } from 'jose';

const vectors = JSON.parse(await readFile(process.argv[2] ?? new URL('./fixtures/gem-edwards-id-tokens.json', import.meta.url), 'utf8'));
assert.equal(vectors.length, 4);
const combinations = new Set();
for (const vector of vectors) {
  assert.ok(['Ed25519', 'EdDSA'].includes(vector.alg));
  assert.equal(typeof vector.jwt_access_token, 'boolean');
  combinations.add(`${vector.alg}:${vector.jwt_access_token}`);
  for (const key of vector.jwks.keys) {
    assert.equal(key.d, undefined);
    assert.equal(key.k, undefined);
  }
  const keys = createLocalJWKSet(vector.jwks);
  const options = { algorithms: [vector.alg], issuer: 'https://op.example.test',
    audience: 'demo-client', currentDate: new Date(vector.checked_at * 1000) };
  const { payload, protectedHeader } = await jwtVerify(vector.id_token, keys, options);
  assert.equal(payload.sub, '1');
  assert.equal(payload.at_hash, createHash('sha512').update(vector.access_token).digest().subarray(0, 32).toString('base64url'));
  const key = vector.jwks.keys.find((item) => item.kid === protectedHeader.kid && item.alg === vector.alg);
  assert.equal(key.kty, 'OKP');
  assert.equal(key.crv, 'Ed25519');
  assert.equal(await calculateJwkThumbprint(key), protectedHeader.kid);
  const parts = vector.id_token.split('.');
  parts[1] = Buffer.from(JSON.stringify({ ...payload, sub: 'attacker' })).toString('base64url');
  await assert.rejects(jwtVerify(parts.join('.'), keys, options), { code: 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED' });
  await assert.rejects(jwtVerify(vector.id_token, keys, { ...options, audience: 'other' }), { code: 'ERR_JWT_CLAIM_VALIDATION_FAILED' });
  console.log(`PASS: jose verified gem ${vector.alg}, ${vector.jwt_access_token ? 'JWT' : 'opaque'} access token, JWKS thumbprint, at_hash; tampering rejected`);
}
assert.equal(combinations.size, 4);
