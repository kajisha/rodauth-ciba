import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPair, exportJWK, SignJWT, jwtVerify } from 'jose';
import { Provider } from 'oidc-provider';
const algorithms = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'HS256', 'HS384', 'HS512', 'Ed25519', 'EdDSA'];
const secret = 'c'.repeat(64);
const material = await Promise.all(algorithms.map(async (alg) => alg.startsWith('HS')
  ? { alg, privateKey: new TextEncoder().encode(secret), publicKey: new TextEncoder().encode(secret), wrong: new TextEncoder().encode('o'.repeat(64)) }
  : { alg, ...await generateKeyPair(alg, { extractable: true }), wrong: (await generateKeyPair(alg)).privateKey }));
const grantType = 'urn:openid:params:grant-type:ciba';
let provider;
const server = createServer((req, res) => provider.callback()(req, res));
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const issuer = `http://127.0.0.1:${server.address().port}`;
try {
  provider = new Provider(issuer, {
    enabledJWA: { idTokenSigningAlgValues: algorithms },
    jwks: { keys: await Promise.all(material.filter(({ alg }) => !alg.startsWith('HS')).map(async ({ alg, privateKey }) =>
      ({ ...await exportJWK(privateKey), alg, use: 'sig', kid: alg }))) },
    clients: algorithms.map((alg) => ({ client_id: alg, client_secret: secret, token_endpoint_auth_method: 'client_secret_basic',
      grant_types: [grantType], response_types: [], backchannel_token_delivery_mode: 'poll', id_token_signed_response_alg: alg })),
    features: { devInteractions: { enabled: false }, ciba: { enabled: true, deliveryModes: ['poll'],
      processLoginHint: async () => 'customer', validateRequestContext: async () => {}, validateBindingMessage: async () => {},
      verifyUserCode: async () => {}, triggerAuthenticationDevice: async () => {} } },
    findAccount: async (_ctx, accountId) => ({ accountId, claims: async () => ({ sub: accountId }) }),
  });
  const metadata = await (await fetch(`${issuer}/.well-known/openid-configuration`)).json();
  for (const { alg, privateKey, publicKey, wrong } of material) {
    const post = async (url, body) => {
      const response = await fetch(url, { method: 'POST', headers: { authorization: `Basic ${Buffer.from(`${alg}:${secret}`).toString('base64')}`,
        'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body) });
      return { status: response.status, body: await response.json() };
    };
    const accepted = await post(metadata.backchannel_authentication_endpoint, { scope: 'openid', login_hint: 'customer' });
    assert.equal(accepted.status, 200, JSON.stringify(accepted));
    const grant = new provider.Grant({ clientId: alg, accountId: 'customer' });
    grant.addOIDCScope('openid'); await grant.save();
    await provider.backchannelResult(accepted.body.auth_req_id, grant);
    const issued = await post(metadata.token_endpoint, { grant_type: grantType, auth_req_id: accepted.body.auth_req_id });
    assert.equal(issued.status, 200, JSON.stringify(issued));
    const { payload, protectedHeader } = await jwtVerify(issued.body.id_token, publicKey, { algorithms: [alg], issuer, audience: alg });
    assert.equal(payload.sub, 'customer');
    if (alg.startsWith('Ed')) assert.equal(payload.at_hash, undefined); // Reference token-endpoint default omits this optional claim.
    const expired = await new SignJWT({ ...payload, iat: Math.floor(Date.now() / 1000) - 7200, exp: Math.floor(Date.now() / 1000) - 3600 })
      .setProtectedHeader(protectedHeader).sign(privateKey);
    for (const hint of [issued.body.id_token, expired]) {
      const result = await post(metadata.backchannel_authentication_endpoint, { scope: 'openid', id_token_hint: hint });
      assert.equal(result.status, 200, `${alg}: ${JSON.stringify(result)}`);
      const pending = await post(metadata.token_endpoint, { grant_type: grantType, auth_req_id: result.body.auth_req_id });
      assert.equal(pending.body.error, 'authorization_pending');
    }
    const forged = await new SignJWT(payload).setProtectedHeader(protectedHeader).sign(wrong);
    const rejected = await post(metadata.backchannel_authentication_endpoint, { scope: 'openid', id_token_hint: forged });
    assert.equal(rejected.status, 400, alg); assert.equal(rejected.body.error, 'invalid_request');
    console.log(`PASS ${alg}: actual issuance, verified ID Token, current/expired hint remain pending, wrong key rejected`);
  }
} finally {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
}
