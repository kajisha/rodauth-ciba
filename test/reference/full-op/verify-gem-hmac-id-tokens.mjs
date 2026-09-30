// Public synthetic fixtures use a fixed test client secret, never deployment credentials.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { jwtVerify } from 'jose';
const vectors = JSON.parse(await readFile(process.argv[2] ?? new URL('./fixtures/gem-hmac-id-tokens.json', import.meta.url), 'utf8'));
assert.equal(vectors.length, 24);
const secret = new TextEncoder().encode('c'.repeat(64));
const wrong = new TextEncoder().encode('o'.repeat(64));
const combinations = new Map();
for (const vector of vectors) {
  assert.ok(['HS256', 'HS384', 'HS512'].includes(vector.algorithm));
  assert.ok(['client_secret_basic', 'client_secret_post'].includes(vector.method));
  assert.equal(typeof vector.hashed, 'boolean');
  const options = { algorithms: [vector.algorithm], issuer: 'https://op.example.test', audience: 'support', currentDate: new Date(vector.checked_at * 1000) };
  const { payload } = await jwtVerify(vector.token, secret, options);
  assert.equal(payload.sub, '1');
  const hash = createHash(`sha${vector.algorithm.slice(2)}`).update(vector.access_token).digest();
  assert.equal(payload.at_hash, hash.subarray(0, hash.length / 2).toString('base64url'));
  await assert.rejects(jwtVerify(vector.token, wrong, options), { code: 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED' });
  const combination = `${vector.algorithm}/${vector.method}/${vector.hashed ? 'hashed' : 'plaintext'} storage`;
  combinations.set(combination, (combinations.get(combination) ?? 0) + 1);
}
assert.equal(combinations.size, 12);
for (const [combination, count] of combinations) {
  assert.equal(count, 2);
  console.log(`PASS ${combination}: gem initial/refresh ID Tokens verified with client secret; OP key rejected; at_hash matched`);
}
