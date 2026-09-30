// Input is a disposable test export containing an ephemeral recipient key.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { importJWK, compactDecrypt, jwtVerify } from 'jose';
const fixture = JSON.parse(await readFile(process.argv[2], 'utf8'));
assert.equal(fixture.vectors.length, 72);
const combinations = new Map();
for (const vector of fixture.vectors) {
  assert.ok(['RS256', 'Ed25519', 'EdDSA'].includes(vector.signature));
  assert.ok(['RSA-OAEP', 'RSA-OAEP-256'].includes(vector.algorithm));
  assert.ok(['A128GCM', 'A192GCM', 'A256GCM', 'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512'].includes(vector.encryption));
  const key = await importJWK(fixture.recipient, vector.algorithm);
  const { plaintext, protectedHeader } = await compactDecrypt(vector.token, key,
    { keyManagementAlgorithms: [vector.algorithm], contentEncryptionAlgorithms: [vector.encryption] });
  assert.equal(protectedHeader.cty, 'JWT');
  assert.equal(protectedHeader.kid, 'recipient');
  const { payload } = await jwtVerify(Buffer.from(plaintext), await importJWK(vector.verification_key, vector.signature),
    { algorithms: [vector.signature], issuer: 'https://op.example.test', audience: 'support', currentDate: new Date(vector.checked_at * 1000) });
  assert.equal(payload.sub, '1');
  const parts = vector.token.split('.');
  const bytes = Buffer.from(parts[3], 'base64url'); bytes[0] ^= 1;
  parts[3] = bytes.toString('base64url');
  await assert.rejects(compactDecrypt(parts.join('.'), key), { code: 'ERR_JWE_DECRYPTION_FAILED' });
  const combination = `${vector.signature}/${vector.algorithm}/${vector.encryption}`;
  combinations.set(combination, (combinations.get(combination) ?? 0) + 1);
}
assert.equal(combinations.size, 36);
for (const [name, count] of combinations) {
  assert.equal(count, 2);
  console.log(`PASS ${name}: gem issuance/refresh decrypted by jose, inner signature verified, ciphertext tampering rejected`);
}
