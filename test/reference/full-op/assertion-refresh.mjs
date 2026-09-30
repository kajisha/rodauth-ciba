import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { SignJWT, exportJWK } from 'jose';
import { Provider } from 'oidc-provider';

const grantType = 'urn:openid:params:grant-type:ciba';
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...await exportJWK(publicKey), kid: 'client', alg: 'RS256', use: 'sig' };
const secret = 's'.repeat(32);
let provider;
const server = createServer((req, res) => provider.callback()(req, res));
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const issuer = `http://127.0.0.1:${server.address().port}`;
try {
  provider = new Provider(issuer, {
    clients: ['private_key_jwt', 'client_secret_jwt'].map((method) => ({
      client_id: method, grant_types: [grantType, 'refresh_token'], response_types: [],
      token_endpoint_auth_method: method, backchannel_token_delivery_mode: 'poll',
      ...(method === 'private_key_jwt' ? { jwks: { keys: [jwk] } } : { client_secret: secret }),
    })),
    features: { devInteractions: { enabled: false }, ciba: { enabled: true, deliveryModes: ['poll'],
      processLoginHint: async (_ctx, hint) => hint === 'customer' ? hint : undefined,
      validateRequestContext: async () => {}, validateBindingMessage: async () => {},
      verifyUserCode: async () => {}, triggerAuthenticationDevice: async () => {} } },
    findAccount: async (_ctx, accountId) => ({ accountId, claims: async () => ({ sub: accountId }) }),
  });
  const metadata = await (await fetch(`${issuer}/.well-known/openid-configuration`)).json();
  for (const method of ['private_key_jwt', 'client_secret_jwt']) {
    const assertion = (aud = issuer) => new SignJWT({ iss: method, sub: method, aud,
      iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 60, jti: randomUUID() })
      .setProtectedHeader(method === 'private_key_jwt' ? { alg: 'RS256', kid: 'client' } : { alg: 'HS256' })
      .sign(method === 'private_key_jwt' ? privateKey : new TextEncoder().encode(secret));
    const post = async (url, params, signed) => {
      const response = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ ...params, client_id: method,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: signed }) });
      return { status: response.status, body: await response.json() };
    };
    const started = await post(metadata.backchannel_authentication_endpoint,
      { scope: 'openid offline_access', login_hint: 'customer' }, await assertion());
    assert.equal(started.status, 200, JSON.stringify(started.body));
    const consent = new provider.Grant({ accountId: 'customer', clientId: method });
    consent.addOIDCScope('openid offline_access');
    await consent.save();
    await provider.backchannelResult(started.body.auth_req_id, consent);
    const issued = await post(metadata.token_endpoint, { grant_type: grantType, auth_req_id: started.body.auth_req_id }, await assertion());
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    const params = { grant_type: 'refresh_token', refresh_token: issued.body.refresh_token };
    assert(params.refresh_token);
    const wrong = await post(metadata.token_endpoint, params, await assertion('https://wrong.example.test'));
    assert.equal(wrong.body.error, 'invalid_client');
    const signed = await assertion();
    const refreshed = await post(metadata.token_endpoint, params, signed);
    assert.equal(refreshed.status, 200, JSON.stringify(refreshed.body));
    assert(refreshed.body.access_token);
    const replay = await post(metadata.token_endpoint, params, signed);
    assert.equal(replay.body.error, 'invalid_client');
    console.log(`PASS ${method}: issuer-audience CIBA issuance and refresh; wrong audience and assertion replay rejected`);
  }
} finally {
  server.closeAllConnections?.();
  await new Promise((resolve) => server.close(resolve));
}
