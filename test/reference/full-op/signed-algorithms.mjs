import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { Provider } from 'oidc-provider';

const algorithms = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'Ed25519', 'EdDSA'];
const material = await Promise.all(algorithms.map(async (alg) => ({ alg, ...await generateKeyPair(alg) })));
let provider;
const server = createServer((req, res) => provider.callback()(req, res));
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const issuer = `http://127.0.0.1:${server.address().port}`;
try {
  provider = new Provider(issuer, {
    enabledJWA: { requestObjectSigningAlgValues: algorithms },
    clients: await Promise.all(material.map(async ({ alg, publicKey }) => ({
      client_id: alg, client_secret: 'test-secret', token_endpoint_auth_method: 'client_secret_basic',
      grant_types: ['urn:openid:params:grant-type:ciba'], response_types: [],
      backchannel_token_delivery_mode: 'poll', backchannel_authentication_request_signing_alg: alg,
      jwks: { keys: [{ ...await exportJWK(publicKey), kid: alg, alg, use: 'sig' }] },
    }))),
    features: { devInteractions: { enabled: false }, requestObjects: { enabled: true },
      ciba: { enabled: true, deliveryModes: ['poll'], processLoginHint: async () => 'customer',
        validateRequestContext: async () => {}, validateBindingMessage: async () => {},
        verifyUserCode: async () => {}, triggerAuthenticationDevice: async () => {} } },
    findAccount: async (_ctx, accountId) => ({ accountId, claims: async () => ({ sub: accountId }) }),
  });
  const metadata = await (await fetch(`${issuer}/.well-known/openid-configuration`)).json();
  for (const { alg, privateKey } of material) {
    assert(metadata.backchannel_authentication_request_signing_alg_values_supported.includes(alg));
    const now = Math.floor(Date.now() / 1000);
    const claims = { iss: alg, aud: issuer, iat: now, nbf: now - 1, exp: now + 120,
      jti: alg, scope: 'openid', login_hint: 'customer' };
    const start = async (token) => {
      const response = await fetch(metadata.backchannel_authentication_endpoint, { method: 'POST',
        headers: { authorization: `Basic ${Buffer.from(`${alg}:test-secret`).toString('base64')}`,
          'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ request: token }) });
      return { status: response.status, body: await response.json() };
    };
    const signed = await new SignJWT(claims).setProtectedHeader({ alg, kid: alg }).sign(privateKey);
    assert.equal((await start(signed)).status, 200, alg);
    if (alg === 'RS256') {
      for (const [changes, expected] of [
        [{ jti: "" }, 200], [{ jti: null }, 400], [{ jti: 123 }, 400],
        [{ iat: now + 3600 }, 200],
        [{ iat: now + 0.5, nbf: now - 0.5, exp: now + 120.5 }, 200],
        [{ iat: `${now}` }, 400], [{ iat: null }, 400],
        [{ nbf: now + 3600.5 }, 400], [{ exp: now - 3600.5 }, 400],
      ]) {
        const token = await new SignJWT({ ...claims, ...changes }).setProtectedHeader({ alg, kid: alg }).sign(privateKey);
        const result = await start(token);
        assert.equal(result.status, expected, JSON.stringify({ changes, result }));
        if (expected === 400) assert.equal(result.body.error, 'invalid_request');
      }
      console.log('PASS signed request jti: empty string accepted, null/non-string rejected');
      console.log('PASS signed request NumericDate: fractional dates and future iat accepted; malformed iat, future nbf and expired exp rejected');
    }
    const wrong = await generateKeyPair(alg);
    const forged = await new SignJWT(claims).setProtectedHeader({ alg, kid: alg }).sign(wrong.privateKey);
    assert.equal((await start(forged)).body.error, 'invalid_request', alg);
    console.log(`PASS signed CIBA ${alg}: configured algorithm/key accepted, different signing key rejected`);
  }
} finally {
  server.closeAllConnections?.();
  await new Promise((resolve) => server.close(resolve));
}
