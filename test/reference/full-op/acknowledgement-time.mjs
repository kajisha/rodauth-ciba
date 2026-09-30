// Real HTTP routes, deterministic application time advances (no wall-clock sleeps).
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync } from 'node:crypto';
import { Provider, errors } from 'oidc-provider';
const originalNow = Date.now;
let now = Math.floor(originalNow() / 1000);
Date.now = () => now * 1000;
let provider;
let dispatchDelay = 3;
const server = createServer((req, res) => provider.callback()(req, res));
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const issuer = `http://127.0.0.1:${server.address().port}`;
const grant = 'urn:openid:params:grant-type:ciba';
try {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  provider = new Provider(issuer, {
    jwks: { keys: [{ ...privateKey.export({ format: 'jwk' }), kid: 'clock', use: 'sig', alg: 'RS256' }] },
    clients: [{ client_id: 'client', client_secret: 'test-secret', grant_types: [grant],
      response_types: [], token_endpoint_auth_method: 'client_secret_basic', backchannel_token_delivery_mode: 'poll' }],
    features: { devInteractions: { enabled: false }, ciba: {
      enabled: true, deliveryModes: ['poll'],
      processLoginHint: async (_ctx, hint) => {
        if (hint === 'policy-denied') throw new errors.OIDCProviderError(403, 'access_denied');
        if (hint === 'default-denied') throw new errors.AccessDenied();
        now += 7;
        return 'customer';
      },
      validateRequestContext: async () => {}, validateBindingMessage: async () => {},
      verifyUserCode: async () => {},
      triggerAuthenticationDevice: async () => { now += dispatchDelay; },
    } },
    findAccount: async (_ctx, accountId) => ({ accountId, claims: async () => ({ sub: accountId }) }),
  });
  provider.on('server_error', (_ctx, error) => console.error(error));
  const metadata = await (await fetch(`${issuer}/.well-known/openid-configuration`)).json();
  for (const [url, body] of [
    [metadata.backchannel_authentication_endpoint, { scope: 'openid', login_hint: 'customer' }],
    [metadata.token_endpoint, { grant_type: grant, auth_req_id: 'unknown' }],
  ]) {
    const missing = await fetch(url, { method: 'POST', headers: {
      'content-type': 'application/x-www-form-urlencoded',
    }, body: new URLSearchParams(body) });
    assert.equal(missing.status, 400);
    assert.equal(missing.headers.get('cache-control'), 'no-store');
    assert.equal(missing.headers.get('www-authenticate'), null);
    assert.equal((await missing.json()).error, 'invalid_request');
    const rejected = await fetch(url, { method: 'POST', headers: {
      authorization: `Basic ${Buffer.from('client:wrong-secret').toString('base64')}`,
      'content-type': 'application/x-www-form-urlencoded',
    }, body: new URLSearchParams(body) });
    assert.equal(rejected.status, 401);
    assert.equal(rejected.headers.get('cache-control'), 'no-store');
    assert.equal(rejected.headers.get('pragma'), null);
    assert.equal((await rejected.json()).error, 'invalid_client');
  }
  console.log('PASS missing identity: both endpoints return 400 invalid_request without authentication challenge');
  console.log('PASS wrong client credentials: both endpoints return 401 invalid_client with no-store (no Pragma header)');
  const post = async (url, body) => {
    const response = await fetch(url, { method: 'POST', headers: {
      authorization: `Basic ${Buffer.from('client:test-secret').toString('base64')}`,
      'content-type': 'application/x-www-form-urlencoded',
    }, body: new URLSearchParams(body) });
    return { status: response.status, body: await response.json() };
  };
  for (const [hint, status] of [['policy-denied', 403], ['default-denied', 400]]) {
    const before = now;
    const denied = await post(metadata.backchannel_authentication_endpoint,
      { scope: 'openid', login_hint: hint });
    assert.equal(denied.status, status);
    assert.equal(denied.body.error, 'access_denied');
    assert.equal(denied.body.auth_req_id, undefined);
    assert.equal(now, before); // No dispatch callback time advance.
  }
  console.log('PASS policy denial: explicit application error returns 403; default AccessDenied returns 400; neither dispatches');
  for (dispatchDelay of [3, 25]) {
    const started = now;
    const response = await post(metadata.backchannel_authentication_endpoint,
      { scope: 'openid', login_hint: 'customer', requested_expiry: '20' });
    assert.equal(response.status, 200, JSON.stringify(response));
    assert.equal(response.body.expires_in, 20);
    assert.equal(response.body.interval, undefined);
    const source = await provider.BackchannelAuthenticationRequest.find(response.body.auth_req_id, { ignoreExpiration: true });
    assert.equal(source.iat, started + 7);
    assert.equal(source.exp, started + 27);
    const token = await post(metadata.token_endpoint, { grant_type: grant, auth_req_id: response.body.auth_req_id });
    assert.equal(token.status, 400);
    assert.equal(token.body.error, dispatchDelay < 20 ? 'authorization_pending' : 'expired_token');
    console.log(`PASS acknowledgement: hint +7s, dispatch +${dispatchDelay}s, issued +7s, expiry +27s, expires_in=20, poll=${token.body.error}`);
  }
} finally {
  Date.now = originalNow;
  await new Promise((resolve) => server.close(resolve));
}
