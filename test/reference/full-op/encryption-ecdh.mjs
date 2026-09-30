import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPair, exportJWK, compactDecrypt, jwtVerify } from 'jose';
import { Provider } from 'oidc-provider';

const algorithms = ['ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW'];
const methods = ['A128GCM', 'A192GCM', 'A256GCM', 'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512'];
const curves = ['P-256', 'P-384', 'P-521', 'X25519'];
const signing = await generateKeyPair('RS256', { extractable: true });
const recipients = await Promise.all(curves.map(async crv => ({ crv, ...await generateKeyPair('ECDH-ES', { crv, extractable: true }) })));
const cases = [];
for (const recipient of recipients) {
  for (const alg of algorithms) {
    for (const enc of methods) {
      const id = `${recipient.crv}-${alg}-${enc}`;
      cases.push({ ...recipient, alg, enc, id,
        jwk: { ...await exportJWK(recipient.publicKey), kid: id, alg, use: 'enc' } });
    }
  }
}
const secret = 'c'.repeat(64);
const grantType = 'urn:openid:params:grant-type:ciba';
let provider;
const server = createServer((req, res) => provider.callback()(req, res));
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const issuer = `http://127.0.0.1:${server.address().port}`;
try {
  provider = new Provider(issuer, {
    enabledJWA: { idTokenEncryptionAlgValues: algorithms, idTokenEncryptionEncValues: methods },
    jwks: { keys: [{ ...await exportJWK(signing.privateKey), alg: 'RS256', use: 'sig', kid: 'op' }] },
    clients: cases.map(({ alg, enc, id, jwk }) => ({ client_id: id, client_secret: secret,
      token_endpoint_auth_method: 'client_secret_basic', grant_types: [grantType, 'refresh_token'], response_types: [],
      backchannel_token_delivery_mode: 'poll', id_token_signed_response_alg: 'RS256',
      id_token_encrypted_response_alg: alg, id_token_encrypted_response_enc: enc, jwks: { keys: [jwk] } })),
    features: { encryption: { enabled: true }, devInteractions: { enabled: false }, ciba: { enabled: true, deliveryModes: ['poll'],
      processLoginHint: async () => 'customer', validateRequestContext: async () => {}, validateBindingMessage: async () => {},
      verifyUserCode: async () => {}, triggerAuthenticationDevice: async () => {} } },
    findAccount: async (_ctx, accountId) => ({ accountId, claims: async () => ({ sub: accountId }) }),
  });
  const metadata = await (await fetch(`${issuer}/.well-known/openid-configuration`)).json();
  const ephemeralKeys = new Set();
  for (const { alg, enc, id, crv, privateKey } of cases) {
    assert.ok(metadata.id_token_encryption_alg_values_supported.includes(alg));
    const post = async (url, params) => {
      const response = await fetch(url, { method: 'POST', headers: {
        authorization: `Basic ${Buffer.from(`${encodeURIComponent(id)}:${secret}`).toString('base64')}`,
        'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(params) });
      const result = await response.json();
      assert.equal(response.status, 200, JSON.stringify(result));
      return result;
    };
    const started = await post(metadata.backchannel_authentication_endpoint, { scope: 'openid offline_access', login_hint: 'customer' });
    const grant = new provider.Grant({ clientId: id, accountId: 'customer' });
    grant.addOIDCScope('openid offline_access'); await grant.save();
    await provider.backchannelResult(started.auth_req_id, grant);
    const initial = await post(metadata.token_endpoint, { grant_type: grantType, auth_req_id: started.auth_req_id });
    const renewed = await post(metadata.token_endpoint, { grant_type: 'refresh_token', refresh_token: initial.refresh_token });
    for (const tokens of [initial, renewed]) {
      const { plaintext, protectedHeader } = await compactDecrypt(tokens.id_token, privateKey,
        { keyManagementAlgorithms: [alg], contentEncryptionAlgorithms: [enc] });
      assert.equal(protectedHeader.kid, id);
      assert.equal(protectedHeader.cty, 'JWT');
      assert.equal(protectedHeader.epk.crv, crv);
      assert.equal(protectedHeader.epk.d, undefined);
      const ephemeral = JSON.stringify(protectedHeader.epk);
      assert.ok(!ephemeralKeys.has(ephemeral)); ephemeralKeys.add(ephemeral);
      assert.equal(tokens.id_token.split('.')[1] === '', alg === 'ECDH-ES');
      const { payload } = await jwtVerify(Buffer.from(plaintext).toString('utf8'), signing.publicKey,
        { algorithms: ['RS256'], issuer, audience: id });
      assert.equal(payload.sub, 'customer');
    }
    console.log(`PASS ${crv}/${alg}/${enc}: initial/refresh recipient decryption and inner signature; fresh public epk; encrypted-key shape`);
  }
} finally {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}
