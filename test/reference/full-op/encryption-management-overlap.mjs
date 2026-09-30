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
let barrier;
const bounded = async promise => {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('barrier timeout')), 10000); })]); }
  finally { clearTimeout(timer); }
};
const server = createServer((req, res) => {
  if (req.url === '/recipient-jwks') {
    requests.push([req.method, req.headers.authorization]);
    res.writeHead(state.status, { 'content-type': 'application/json', 'cache-control': 'max-age=3600' });
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
    findAccount: async (_ctx, accountId) => {
      if (barrier) { const current = barrier; barrier = undefined; current.enter(); await bounded(current.release); }
      return { accountId, claims: async () => ({ sub: accountId }) };
    },
  });
  const metadata = await (await fetch(`${issuer}/.well-known/openid-configuration`)).json();
  for (const phase of ['initial', 'refresh']) {
    const registration = { grant_types: [grantType, 'refresh_token'], response_types: [],
      token_endpoint_auth_method: 'client_secret_basic', backchannel_token_delivery_mode: 'poll',
      id_token_signed_response_alg: 'RS256', id_token_encrypted_response_alg: encryptionAlgorithm,
      id_token_encrypted_response_enc: 'A256GCM', jwks: { keys: [await jwk(oldKey, 'old')] } };
    const registered = await fetch(metadata.registration_endpoint, { method: 'POST',
      headers: { authorization: 'Bearer local-registration', 'content-type': 'application/json' }, body: JSON.stringify(registration) });
    assert.equal(registered.status, 201);
    const client = await registered.json();
    const post = async (url, params) => {
      const response = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${Buffer.from(`${client.client_id}:${client.client_secret}`).toString('base64')}` }, body: new URLSearchParams(params) });
      const body = await response.json(); assert.equal(response.status, 200, JSON.stringify(body)); return body;
    };
    const started = await post(metadata.backchannel_authentication_endpoint, { scope: 'openid offline_access', login_hint: 'customer' });
    const grant = new provider.Grant({ clientId: client.client_id, accountId: 'customer' });
    grant.addOIDCScope('openid offline_access'); await grant.save();
    await provider.backchannelResult(started.auth_req_id, grant);
    let params = { grant_type: grantType, auth_req_id: started.auth_req_id };
    if (phase === 'refresh') {
      const initial = await post(metadata.token_endpoint, params);
      params = { grant_type: 'refresh_token', refresh_token: initial.refresh_token };
    }
    let entered, release;
    const reached = new Promise(resolve => { entered = resolve; });
    const released = new Promise(resolve => { release = resolve; });
    barrier = { enter: entered, release: released };
    const pending = post(metadata.token_endpoint, params);
    try {
      await bounded(reached);
      const response = await fetch(client.registration_client_uri, { method: 'PUT', headers: {
        authorization: `Bearer ${client.registration_access_token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ ...registration, client_id: client.client_id, client_secret: client.client_secret,
          jwks: { keys: [await jwk(newKey, 'new')] } }) });
      assert.equal(response.status, 200, await response.text());
    } finally { release(); }
    const inFlight = await bounded(pending);
    const verify = async (tokens, key, kid) => {
      const result = await compactDecrypt(tokens.id_token, key.privateKey);
      assert.equal(result.protectedHeader.kid, kid);
      const { payload } = await jwtVerify(Buffer.from(result.plaintext), signing.publicKey,
        { algorithms: ['RS256'], issuer, audience: client.client_id });
      assert.equal(payload.sub, 'customer');
    };
    await verify(inFlight, oldKey, 'old');
    const subsequent = await post(metadata.token_endpoint, { grant_type: 'refresh_token', refresh_token: inFlight.refresh_token });
    await verify(subsequent, newKey, 'new');
    console.log(`PASS concurrent ${phase}: management committed before token generation, in-flight client snapshot uses old recipient; next request uses new recipient`);
  }
} finally {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}
