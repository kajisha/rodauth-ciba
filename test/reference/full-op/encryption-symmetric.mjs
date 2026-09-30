import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { generateKeyPair, exportJWK, compactDecrypt, jwtVerify } from 'jose';
import { Provider } from 'oidc-provider';

// Public synthetic secret. Derivation follows the pinned provider's client model.
const secret = 'c'.repeat(64);
const algorithms = ['dir', 'A128KW', 'A192KW', 'A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW'];
const methods = ['A128GCM', 'A192GCM', 'A256GCM', 'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512'];
const cases = algorithms.flatMap(alg => methods.flatMap(enc => [false, true].map(remote => ({ alg, enc, remote, id: `${alg}-${enc}-${remote}` }))));
const signing = await generateKeyPair('RS256', { extractable: true });
const grantType = 'urn:openid:params:grant-type:ciba';
let provider;
let keyRequests = 0;
const server = createServer((req, res) => {
  if (req.url === '/unused-jwks') { keyRequests++; res.writeHead(503); res.end('{}'); }
  else provider.callback()(req, res);
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const issuer = `http://127.0.0.1:${server.address().port}`;
try {
  provider = new Provider(issuer, {
    fetch: (url, options) => fetch(url, url === `${issuer}/unused-jwks` ? { ...options, dispatcher: undefined } : options),
    enabledJWA: { idTokenEncryptionAlgValues: algorithms, idTokenEncryptionEncValues: methods },
    jwks: { keys: [{ ...await exportJWK(signing.privateKey), alg: 'RS256', use: 'sig', kid: 'op' }] },
    clients: cases.map(({ alg, enc, id, remote }) => ({ client_id: id, client_secret: secret, ...(remote ? { jwks_uri: `${issuer}/unused-jwks` } : {}),
      token_endpoint_auth_method: 'client_secret_basic', grant_types: [grantType, 'refresh_token'], response_types: [],
      backchannel_token_delivery_mode: 'poll', id_token_signed_response_alg: 'RS256',
      id_token_encrypted_response_alg: alg, id_token_encrypted_response_enc: enc })),
    features: { encryption: { enabled: true }, devInteractions: { enabled: false }, ciba: { enabled: true, deliveryModes: ['poll'],
      processLoginHint: async () => 'customer', validateRequestContext: async () => {}, validateBindingMessage: async () => {},
      verifyUserCode: async () => {}, triggerAuthenticationDevice: async () => {} } },
    findAccount: async (_ctx, accountId) => ({ accountId, claims: async () => ({ sub: accountId }) }),
  });
  const metadata = await (await fetch(`${issuer}/.well-known/openid-configuration`)).json();
  for (const { alg, enc, id, remote } of cases) {
    assert.ok(metadata.id_token_encryption_alg_values_supported.includes(alg));
    const post = async (url, body) => {
      const response = await fetch(url, { method: 'POST', headers: {
        authorization: `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}`,
        'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body) });
      const result = await response.json();
      assert.equal(response.status, 200, JSON.stringify(result));
      return result;
    };
    const started = await post(metadata.backchannel_authentication_endpoint, { scope: 'openid offline_access', login_hint: 'customer' });
    const grant = new provider.Grant({ clientId: id, accountId: 'customer' });
    grant.addOIDCScope('openid offline_access'); await grant.save();
    await provider.backchannelResult(started.auth_req_id, grant);
    const issued = await post(metadata.token_endpoint, { grant_type: grantType, auth_req_id: started.auth_req_id });
    const refreshed = await post(metadata.token_endpoint, { grant_type: 'refresh_token', refresh_token: issued.refresh_token });
    const bits = alg === 'dir' ? Number(enc.match(/HS(\d+)$/)?.[1] || enc.match(/^A(\d+)/)[1]) : Number(alg.match(/^A(\d+)/)[1]);
    const bytes = bits / 8;
    const key = createHash(bytes <= 32 ? 'sha256' : bytes <= 48 ? 'sha384' : 'sha512').update(secret, 'utf8').digest().subarray(0, bytes);
    for (const tokens of [issued, refreshed]) {
      const { plaintext, protectedHeader } = await compactDecrypt(tokens.id_token, key,
        { keyManagementAlgorithms: [alg], contentEncryptionAlgorithms: [enc] });
      assert.equal(protectedHeader.cty, 'JWT');
      assert.equal(protectedHeader.kid, undefined);
      const { payload } = await jwtVerify(Buffer.from(plaintext).toString('utf8'), signing.publicKey,
        { algorithms: ['RS256'], issuer, audience: id });
      assert.equal(payload.sub, 'customer');
      await assert.rejects(compactDecrypt(tokens.id_token, Buffer.alloc(bytes, 1)));
    }
    assert.equal(keyRequests, 0);
    console.log(`PASS ${alg}/${enc}/${remote ? 'unavailable JWKS URI' : 'no JWKS'}: no recipient key fetch; client-secret-derived key decrypts issuance/refresh; wrong key rejected; inner RS256 verified`);
  }
} finally {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}
