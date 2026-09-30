import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { compactDecrypt, importJWK, importPKCS8, jwtVerify, generateKeyPair } from 'jose';

const { public_key: publicKey, vectors } = JSON.parse(await readFile(process.argv[2], 'utf8'));
assert.equal(vectors.length, 192);
const signatureKey = await importJWK(publicKey, 'RS256');
const combinations = new Map();
const wrongKeys = new Map();
for (const crv of ['P-256', 'P-384', 'P-521', 'X25519']) {
  wrongKeys.set(crv, (await generateKeyPair('ECDH-ES', { crv })).privateKey);
}
for (const v of vectors) {
  const recipient = await importPKCS8(v.recipient_pem, v.algorithm);
  const { plaintext, protectedHeader } = await compactDecrypt(v.token, recipient,
    { keyManagementAlgorithms: [v.algorithm], contentEncryptionAlgorithms: [v.method] });
  assert.equal(protectedHeader.cty, 'JWT');
  assert.equal(protectedHeader.epk.crv, v.curve);
  assert.equal(protectedHeader.epk.d, undefined);
  const { payload } = await jwtVerify(Buffer.from(plaintext).toString('utf8'), signatureKey,
    { algorithms: ['RS256'], issuer: 'https://op.example.test', audience: 'support', currentDate: new Date(v.checked_at * 1000) });
  assert.equal(payload.sub, v.subject);
  await assert.rejects(compactDecrypt(v.token, wrongKeys.get(v.curve)));
  const parts = v.token.split('.');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url'));
  const x = Buffer.from(header.epk.x, 'base64url'); x[0] ^= 1;
  header.epk.x = x.toString('base64url');
  parts[0] = Buffer.from(JSON.stringify(header)).toString('base64url');
  await assert.rejects(compactDecrypt(parts.join('.'), recipient));
  const combination = `${v.curve}/${v.algorithm}/${v.method}`;
  combinations.set(combination, (combinations.get(combination) || 0) + 1);
}
assert.equal(combinations.size, 96);
for (const [combination, count] of combinations) {
  assert.equal(count, 2);
  console.log(`PASS ${combination}: gem initial/refresh decrypted, inner RS256 verified, wrong recipient and changed epk rejected`);
}
