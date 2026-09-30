import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPair, exportJWK, compactDecrypt, jwtVerify } from 'jose';
import { Provider } from 'oidc-provider';

const encryptionAlgorithm = process.argv[2] || 'RSA-OAEP-256';
const curve = process.argv[3] || 'P-256';
assert.ok(['RSA-OAEP-256', 'ECDH-ES', 'ECDH-ES+A256KW'].includes(encryptionAlgorithm));
const recipientOptions = { extractable: true, ...(encryptionAlgorithm.startsWith('ECDH') ? { crv: curve } : {}) };
console.log(`CONFIG recipient encryption: ${encryptionAlgorithm}, ${curve}`);
const signing = await generateKeyPair('RS256', { extractable: true });
const oldKey = await generateKeyPair(encryptionAlgorithm, recipientOptions);
const newKey = await generateKeyPair(encryptionAlgorithm, recipientOptions);
const jwk = async (key, kid) => ({ ...await exportJWK(key.publicKey), kid, use: 'enc', alg: encryptionAlgorithm });
let state = { keys: [await jwk(oldKey, 'old')], status: 200, body: undefined };
const requests = [];
let provider;
const server = createServer((req, res) => {
  if (req.url === '/recipient-jwks') {
    requests.push([req.method, req.headers.authorization]);
    res.writeHead(state.status, { 'content-type': 'application/json', 'cache-control': 'max-age=2' });
    res.end(state.body ?? JSON.stringify({ keys: state.keys }));
  } else provider.callback()(req, res);
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const issuer = `http://127.0.0.1:${server.address().port}`;
const endpoint = `${issuer}/recipient-jwks`;
const grantType = 'urn:openid:params:grant-type:ciba';
const secret = 'c'.repeat(64);
try {
  provider = new Provider(issuer, {
    ...(encryptionAlgorithm.startsWith("ECDH") ? { enabledJWA: { idTokenEncryptionAlgValues: [encryptionAlgorithm] } } : {}),
    fetch: (url, options) => fetch(url, url === endpoint ? { ...options, dispatcher: undefined } : options),
    jwks: { keys: [{ ...await exportJWK(signing.privateKey), alg: 'RS256', use: 'sig', kid: 'op' }] },
    clients: [{ client_id: 'remote', client_secret: secret, token_endpoint_auth_method: 'client_secret_basic',
      grant_types: [grantType, 'refresh_token'], response_types: [], backchannel_token_delivery_mode: 'poll',
      id_token_signed_response_alg: 'RS256', id_token_encrypted_response_alg: encryptionAlgorithm,
      id_token_encrypted_response_enc: 'A256GCM', jwks_uri: endpoint }],
    features: { encryption: { enabled: true }, devInteractions: { enabled: false },
      registration: { enabled: true, initialAccessToken: 'local-registration' }, registrationManagement: { enabled: true },
      ciba: { enabled: true, deliveryModes: ['poll'],
      processLoginHint: async () => 'customer', validateRequestContext: async () => {}, validateBindingMessage: async () => {},
      verifyUserCode: async () => {}, triggerAuthenticationDevice: async () => {} } },
    findAccount: async (_ctx, accountId) => ({ accountId, claims: async () => ({ sub: accountId }) }),
  });
  const metadata = await (await fetch(`${issuer}/.well-known/openid-configuration`)).json();
  const post = async (url, params) => {
    const response = await fetch(url, { method: 'POST', headers: { authorization: `Basic ${Buffer.from(`remote:${secret}`).toString('base64')}`,
      'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(params) });
    return { status: response.status, body: await response.json() };
  };
  const verify = async (response, key, kid) => {
    assert.equal(response.status, 200, JSON.stringify(response));
    const { plaintext, protectedHeader } = await compactDecrypt(response.body.id_token, key.privateKey,
      { keyManagementAlgorithms: [encryptionAlgorithm], contentEncryptionAlgorithms: ['A256GCM'] });
    assert.equal(protectedHeader.kid, kid);
    const { payload } = await jwtVerify(Buffer.from(plaintext), signing.publicKey, { algorithms: ['RS256'], issuer, audience: 'remote' });
    assert.equal(payload.sub, 'customer');
  };
  const accepted = await post(metadata.backchannel_authentication_endpoint, { scope: 'openid offline_access', login_hint: 'customer' });
  assert.equal(accepted.status, 200, JSON.stringify(accepted));
  const grant = new provider.Grant({ clientId: 'remote', accountId: 'customer' });
  grant.addOIDCScope('openid offline_access'); await grant.save();
  await provider.backchannelResult(accepted.body.auth_req_id, grant);
  const issued = await post(metadata.token_endpoint, { grant_type: grantType, auth_req_id: accepted.body.auth_req_id });
  await verify(issued, oldKey, 'old');
  assert.equal(requests.length, 1);
  const renew = () => post(metadata.token_endpoint, { grant_type: 'refresh_token', refresh_token: issued.body.refresh_token });
  state.keys = [await jwk(newKey, 'new')];
  await verify(await renew(), oldKey, 'old');
  assert.equal(requests.length, 1);
  const observed = performance.now();
  await new Promise(resolve => setTimeout(resolve, 3100));
  await verify(await renew(), oldKey, 'old');
  assert.equal(requests.length, 1);
  console.log('PASS real cache TTL: max-age=2 still retains old recipient after3 seconds');
  await new Promise(resolve => setTimeout(resolve, 60000));
  await verify(await renew(), newKey, 'new');
  assert.equal(requests.length, 2);
  assert.ok(requests.every(([method, authorization]) => method === 'GET' && authorization === undefined));
  console.log(`PASS real cache TTL: without cache mutation, new recipient retrieved after ${Math.round(performance.now() - observed)}ms; no credentials forwarded`);
} finally {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
}
