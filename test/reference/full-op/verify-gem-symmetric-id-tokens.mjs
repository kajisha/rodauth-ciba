import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { compactDecrypt, importJWK, jwtVerify } from 'jose';

const { public_key: publicKey, vectors } = JSON.parse(await readFile(process.argv[2], 'utf8'));
assert.equal(vectors.length, 84);
const signatureKey = await importJWK(publicKey, 'RS256');
const combinations = new Map();
for (const v of vectors) {
  const bits = Number(v.algorithm === 'dir' ? (v.method.match(/HS(\d+)$/)?.[1] || v.method.match(/^A(\d+)/)[1]) : v.algorithm.match(/^A(\d+)/)[1]);
  const length = bits / 8;
  const key = createHash(length <= 32 ? 'sha256' : length <= 48 ? 'sha384' : 'sha512').update(v.secret, 'utf8').digest().subarray(0, length);
  const { plaintext, protectedHeader } = await compactDecrypt(v.token, key,
    { keyManagementAlgorithms: [v.algorithm], contentEncryptionAlgorithms: [v.method] });
  assert.equal(protectedHeader.cty, 'JWT');
  assert.equal(protectedHeader.kid, undefined);
  if (v.algorithm.endsWith('GCMKW')) {
    assert.equal(Buffer.from(protectedHeader.iv, 'base64url').length, 12);
    assert.equal(Buffer.from(protectedHeader.tag, 'base64url').length, 16);
    for (const field of ['iv', 'tag']) {
      const parts = v.token.split('.');
      const header = JSON.parse(Buffer.from(parts[0], 'base64url'));
      const changed = Buffer.from(header[field], 'base64url'); changed[0] ^= 1;
      header[field] = changed.toString('base64url');
      parts[0] = Buffer.from(JSON.stringify(header)).toString('base64url');
      await assert.rejects(compactDecrypt(parts.join('.'), key));
    }
    for (const index of [1, 3, 4]) {
      const parts = v.token.split('.');
      const changed = Buffer.from(parts[index], 'base64url'); changed[0] ^= 1;
      parts[index] = changed.toString('base64url');
      await assert.rejects(compactDecrypt(parts.join('.'), key));
    }
  }
  const { payload } = await jwtVerify(Buffer.from(plaintext).toString('utf8'), signatureKey,
    { algorithms: ['RS256'], issuer: v.issuer, audience: v.audience, currentDate: new Date(v.checked_at * 1000) });
  assert.equal(payload.sub, v.subject);
  await assert.rejects(compactDecrypt(v.token, Buffer.alloc(length, 1)));
  const combination = `${v.algorithm}/${v.method}`;
  combinations.set(combination, (combinations.get(combination) || 0) + 1);
}
assert.equal(combinations.size, 42);
for (const [combination, count] of combinations) {
  assert.equal(count, 2);
  console.log(`PASS ${combination}: gem issuance/refresh decrypted with derived client key, inner RS256 verified, wrong key rejected`);
}
