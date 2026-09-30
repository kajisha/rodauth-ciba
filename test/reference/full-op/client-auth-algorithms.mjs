import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { Provider } from 'oidc-provider';
const algorithms = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'HS256', 'HS384', 'HS512', 'Ed25519', 'EdDSA'];
const material = await Promise.all(algorithms.map(async (alg) => alg.startsWith('HS')
  ? { alg, privateKey: new TextEncoder().encode('s'.repeat(64)), wrong: new TextEncoder().encode('o'.repeat(64)) }
  : { alg, ...await generateKeyPair(alg), wrong: (await generateKeyPair(alg)).privateKey }));
const cases = material.flatMap((entry) => [
  { ...entry, clientId: entry.alg },
  ...(['Ed25519', 'EdDSA'].includes(entry.alg) ? [{ ...entry, clientId: `${entry.alg}-remote`, remote: true }] : []),
]);
const remoteKeys = new Map(await Promise.all(cases.filter((entry) => entry.remote).map(async ({ alg, clientId, publicKey }) =>
  [`/jwks/${clientId}`, { keys: [{ ...await exportJWK(publicKey), kid: alg, alg, use: 'sig' }] }])));
const keyRequests = [];
let provider;
const server = createServer((req, res) => {
  if (remoteKeys.has(req.url)) {
    keyRequests.push(req.url);
    res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-cache' });
    res.end(JSON.stringify(remoteKeys.get(req.url)));
  } else provider.callback()(req, res);
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const issuer = `http://127.0.0.1:${server.address().port}`;
try {
  provider = new Provider(issuer, {
    enabledJWA: { clientAuthSigningAlgValues: algorithms },
    // Only these owned fixture URLs bypass special-use-IP rejection.
    fetch: (url, options) => fetch(url, [...remoteKeys.keys()].some((path) => url === `${issuer}${path}`)
      ? { ...options, dispatcher: undefined } : options),
    clients: await Promise.all(cases.map(async ({ alg, publicKey, clientId, remote }) => ({
      client_id: clientId, client_secret: 's'.repeat(64), token_endpoint_auth_method: alg.startsWith('HS') ? 'client_secret_jwt' : 'private_key_jwt',
      token_endpoint_auth_signing_alg: alg, grant_types: ['urn:openid:params:grant-type:ciba'], response_types: [],
      backchannel_token_delivery_mode: 'poll',
      ...(remote ? { jwks_uri: `${issuer}/jwks/${clientId}` } : publicKey ? { jwks: { keys: [{ ...await exportJWK(publicKey), kid: alg, alg, use: 'sig' }] } } : {}),
    }))),
    features: { devInteractions: { enabled: false }, ciba: { enabled: true, deliveryModes: ['poll'],
      processLoginHint: async () => 'customer', validateRequestContext: async () => {},
      validateBindingMessage: async () => {}, verifyUserCode: async () => {}, triggerAuthenticationDevice: async () => {} } },
    findAccount: async (_ctx, accountId) => ({ accountId, claims: async () => ({ sub: accountId }) }),
  });
  const metadata = await (await fetch(`${issuer}/.well-known/openid-configuration`)).json();
  assert.deepEqual([...metadata.token_endpoint_auth_signing_alg_values_supported].sort(), [...algorithms].sort());
  for (const { alg, privateKey, wrong, clientId, remote } of cases) {
    const send = async (endpoint, body, key = privateKey) => {
      const now = Math.floor(Date.now() / 1000);
      const token = await new SignJWT({ iss: clientId, sub: clientId, aud: issuer, iat: now, exp: now + 60, jti: randomUUID() })
        .setProtectedHeader({ alg, ...(alg.startsWith('HS') ? {} : { kid: alg }) }).sign(key);
      const response = await fetch(endpoint, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ ...body, client_id: clientId, client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: token }) });
      return { status: response.status, body: await response.json() };
    };
    const start = { scope: 'openid', login_hint: 'customer' };
    assert.equal((await send(metadata.backchannel_authentication_endpoint, start, wrong)).status, 401, alg);
    const accepted = await send(metadata.backchannel_authentication_endpoint, start);
    assert.equal(accepted.status, 200, `${alg}: ${JSON.stringify(accepted)}`);
    const poll = { grant_type: 'urn:openid:params:grant-type:ciba', auth_req_id: accepted.body.auth_req_id };
    assert.equal((await send(metadata.token_endpoint, poll, wrong)).status, 401, alg);
    const pending = await send(metadata.token_endpoint, poll);
    assert.equal(pending.status, 400, alg);
    assert.equal(pending.body.error, 'authorization_pending', alg);
    if (remote) assert(keyRequests.includes(`/jwks/${clientId}`));
    console.log(`PASS ${clientId}: advertised client assertion authenticates both endpoints; wrong key rejected at both`);
  }
} finally {
  server.closeAllConnections?.();
  await new Promise((resolve) => server.close(resolve));
}
