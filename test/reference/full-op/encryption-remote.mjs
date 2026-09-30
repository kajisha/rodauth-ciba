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
  const client = await provider.Client.find('remote');
  client.asymmetricKeyStore.freshUntil = 0;
  await verify(await renew(), newKey, 'new');
  assert.equal(requests.length, 2);
  console.log('PASS encryption remote keys: live cache retains old recipient; forced expiry retrieves and encrypts to new recipient');
  client.asymmetricKeyStore.freshUntil = 0;
  state.status = 503;
  const failed = await renew();
  assert.equal(failed.status, 400, JSON.stringify(failed));
  assert.equal(failed.body.error, 'invalid_client_metadata');
  assert.equal(requests.length, 3);
  await verify(await renew(), newKey, 'new');
  assert.equal(requests.length, 3);
  console.log('OBSERVED encryption remote failure: first 503 returns invalid_client_metadata; next refresh uses retained key without refetch while endpoint still fails');
  state.status = 200;
  state.body = 'invalid JSON';
  client.asymmetricKeyStore.freshUntil = 0;
  for (let i = 0; i < 2; i++) {
    const malformed = await renew();
    assert.equal(malformed.status, 400, JSON.stringify(malformed));
    assert.equal(malformed.body.error, 'invalid_client_metadata');
  }
  assert.equal(requests.length, 5);
  state.body = undefined;
  await verify(await renew(), newKey, 'new');
  assert.equal(requests.length, 6);
  assert.ok(requests.every(([method, authorization]) => method === 'GET' && authorization === undefined));
  console.log('PASS encryption remote malformed JSON: repeated failure refetches; repaired endpoint recovers; recipient GET carries no client credentials');

  const registration = { grant_types: [grantType, 'refresh_token'], response_types: [],
    token_endpoint_auth_method: 'client_secret_basic', backchannel_token_delivery_mode: 'poll',
    id_token_signed_response_alg: 'RS256', id_token_encrypted_response_alg: encryptionAlgorithm,
    id_token_encrypted_response_enc: 'A256GCM', jwks: { keys: [await jwk(oldKey, 'old')] } };
  const registered = await fetch(metadata.registration_endpoint, { method: 'POST',
    headers: { authorization: 'Bearer local-registration', 'content-type': 'application/json' }, body: JSON.stringify(registration) });
  assert.equal(registered.status, 201);
  const managed = await registered.json();
  const managedPost = async (url, params) => {
    const result = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${Buffer.from(`${managed.client_id}:${managed.client_secret}`).toString('base64')}` }, body: new URLSearchParams(params) });
    const body = await result.json();
    assert.equal(result.status, 200, JSON.stringify(body));
    return body;
  };
  const startManaged = await managedPost(metadata.backchannel_authentication_endpoint, { scope: 'openid offline_access', login_hint: 'customer' });
  const managedGrant = new provider.Grant({ clientId: managed.client_id, accountId: 'customer' });
  managedGrant.addOIDCScope('openid offline_access'); await managedGrant.save();
  await provider.backchannelResult(startManaged.auth_req_id, managedGrant);
  const before = await managedPost(metadata.token_endpoint, { grant_type: grantType, auth_req_id: startManaged.auth_req_id });
  const verifyManaged = async (tokens, key, kid) => {
    const decrypted = await compactDecrypt(tokens.id_token, key.privateKey);
    assert.equal(decrypted.protectedHeader.kid, kid);
    const signed = await jwtVerify(Buffer.from(decrypted.plaintext), signing.publicKey, { algorithms: ['RS256'], issuer, audience: managed.client_id });
    assert.equal(signed.payload.sub, 'customer');
  };
  await verifyManaged(before, oldKey, 'old');
  const replacement = { ...registration, client_id: managed.client_id, client_secret: managed.client_secret, jwks: { keys: [await jwk(newKey, 'new')] } };
  const update = (params) => fetch(managed.registration_client_uri, { method: 'PUT',
    headers: { authorization: `Bearer ${managed.registration_access_token}`, 'content-type': 'application/json' }, body: JSON.stringify(params) });
  const invalid = await update({ ...replacement, id_token_encrypted_response_enc: 'invalid' });
  assert.equal(invalid.status, 400);
  assert.equal((await invalid.json()).error, 'invalid_client_metadata');
  await verifyManaged(await managedPost(metadata.token_endpoint, { grant_type: 'refresh_token', refresh_token: before.refresh_token }), oldKey, 'old');
  const updated = await update(replacement);
  const updatedBody = await updated.json();
  assert.equal(updated.status, 200, JSON.stringify(updatedBody));
  managed.registration_access_token = updatedBody.registration_access_token;
  await verifyManaged(await managedPost(metadata.token_endpoint, { grant_type: 'refresh_token', refresh_token: before.refresh_token }), newKey, 'new');
  await verifyManaged(before, oldKey, 'old');
  console.log('PASS encryption management: invalid update preserves old recipient; successful replacement changes refresh recipient while original token remains decryptable');
  const defaulted = { ...replacement };
  delete defaulted.id_token_encrypted_response_enc;
  const defaultUpdate = await update(defaulted);
  assert.equal(defaultUpdate.status, 200);
  const defaultMetadata = await defaultUpdate.json();
  assert.equal(defaultMetadata.id_token_encrypted_response_enc, 'A128CBC-HS256');
  managed.registration_access_token = defaultMetadata.registration_access_token;
  const defaultTokens = await managedPost(metadata.token_endpoint, { grant_type: 'refresh_token', refresh_token: before.refresh_token });
  const defaultHeader = JSON.parse(Buffer.from(defaultTokens.id_token.split('.')[0], 'base64url'));
  assert.equal(defaultHeader.enc, 'A128CBC-HS256');
  await verifyManaged(defaultTokens, newKey, 'new');
  const plain = { ...replacement };
  delete plain.id_token_encrypted_response_alg;
  delete plain.id_token_encrypted_response_enc;
  const plainUpdate = await update(plain);
  assert.equal(plainUpdate.status, 200);
  const plainMetadata = await plainUpdate.json();
  assert.equal(plainMetadata.id_token_encrypted_response_alg, undefined);
  assert.equal(plainMetadata.id_token_encrypted_response_enc, undefined);
  const plainTokens = await managedPost(metadata.token_endpoint, { grant_type: 'refresh_token', refresh_token: before.refresh_token });
  assert.equal(plainTokens.id_token.split('.').length, 3);
  const plainClaims = await jwtVerify(plainTokens.id_token, signing.publicKey, { algorithms: ['RS256'], issuer, audience: managed.client_id });
  assert.equal(plainClaims.payload.sub, 'customer');
  console.log('PASS encryption management defaults/removal: omitted enc defaults to CBC; removing both fields returns signed output on existing refresh credentials');
} finally {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
}
