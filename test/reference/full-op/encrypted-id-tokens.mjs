import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPair, exportJWK, compactDecrypt, jwtVerify } from 'jose';
import { Provider } from 'oidc-provider';

const algorithms = ['RS256', 'Ed25519', 'EdDSA'];
const keys = await Promise.all(algorithms.map(async (alg) => ({ alg, ...await generateKeyPair(alg, { extractable: true }) })));
const recipient = await generateKeyPair('RSA-OAEP-256', { extractable: true });
const genericRecipient = await generateKeyPair('RSA-OAEP-256', { extractable: true });
const genericRecipientJwk = { ...await exportJWK(genericRecipient.publicKey), kid: 'generic' };
const recipientJwk = { ...await exportJWK(recipient.publicKey), kid: 'recipient', use: 'enc', alg: 'RSA-OAEP-256' };
const grantType = 'urn:openid:params:grant-type:ciba';
const secret = 'c'.repeat(64);
let provider;
const server = createServer((req, res) => provider.callback()(req, res));
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const issuer = `http://127.0.0.1:${server.address().port}`;
try {
  provider = new Provider(issuer, {
    enabledJWA: { idTokenSigningAlgValues: algorithms },
    jwks: { keys: await Promise.all(keys.map(async ({ alg, privateKey }) =>
      ({ ...await exportJWK(privateKey), alg, use: 'sig', kid: alg }))) },
    clients: algorithms.map((alg) => ({ client_id: alg, client_secret: secret,
      token_endpoint_auth_method: 'client_secret_basic', grant_types: [grantType, 'refresh_token'], response_types: [],
      backchannel_token_delivery_mode: 'poll', id_token_signed_response_alg: alg,
      id_token_encrypted_response_alg: 'RSA-OAEP-256', id_token_encrypted_response_enc: 'A256GCM', jwks: { keys: [genericRecipientJwk, recipientJwk] } })),
    features: { encryption: { enabled: true }, devInteractions: { enabled: false }, ciba: { enabled: true, deliveryModes: ['poll'],
      processLoginHint: async () => 'customer', validateRequestContext: async () => {}, validateBindingMessage: async () => {},
      verifyUserCode: async () => {}, triggerAuthenticationDevice: async () => {} } },
    findAccount: async (_ctx, accountId) => ({ accountId, claims: async () => ({ sub: accountId }) }),
  });
  const metadata = await (await fetch(`${issuer}/.well-known/openid-configuration`)).json();
  for (const { alg, publicKey } of keys) {
    const post = async (url, body) => {
      const response = await fetch(url, { method: 'POST', headers: {
        authorization: `Basic ${Buffer.from(`${alg}:${secret}`).toString('base64')}`,
        'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body) });
      const result = await response.json();
      assert.equal(response.status, 200, JSON.stringify(result));
      return result;
    };
    const accepted = await post(metadata.backchannel_authentication_endpoint, { scope: 'openid offline_access', login_hint: 'customer' });
    const grant = new provider.Grant({ clientId: alg, accountId: 'customer' });
    grant.addOIDCScope('openid offline_access'); await grant.save();
    await provider.backchannelResult(accepted.auth_req_id, grant);
    const issued = await post(metadata.token_endpoint, { grant_type: grantType, auth_req_id: accepted.auth_req_id });
    const refreshed = await post(metadata.token_endpoint, { grant_type: 'refresh_token', refresh_token: issued.refresh_token });
    for (const tokens of [issued, refreshed]) {
      assert.equal(tokens.id_token.split('.').length, 5);
      const { plaintext, protectedHeader } = await compactDecrypt(tokens.id_token, recipient.privateKey,
        { keyManagementAlgorithms: ['RSA-OAEP-256'], contentEncryptionAlgorithms: ['A256GCM'] });
      assert.equal(protectedHeader.cty, 'JWT');
      assert.equal(protectedHeader.kid, 'recipient');
      const { payload } = await jwtVerify(Buffer.from(plaintext).toString('utf8'), publicKey, { algorithms: [alg], issuer, audience: alg });
      assert.equal(payload.sub, 'customer');
    }
    console.log(`PASS ${alg}: CIBA issuance and refresh encrypt signed ID Tokens with recipient RSA-OAEP-256/A256GCM; decrypted inner signatures verified; explicit alg/use preferred over earlier generic key`);
  }
} finally {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
}
