// Published provider, real HTTP registration and use of the resulting client.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync, sign } from 'node:crypto';
import { Provider, errors } from 'oidc-provider';

const grantType = 'urn:openid:params:grant-type:ciba';
const initialToken = 'local-reference-registration-only';
const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
let provider;
const server = createServer((req, res) => provider.callback()(req, res));
await new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', resolve);
});
const issuer = `http://127.0.0.1:${server.address().port}`;
try {
  assert.throws(() => new Provider(issuer, {
    features: { ciba: { enabled: true, deliveryModes: ['push'] } },
  }), /only poll and ping CIBA delivery modes are supported/);
  console.log('PASS provider configuration rejects push delivery mode');
  provider = new Provider(issuer, {
    enabledJWA: { clientAuthSigningAlgValues: ['RS256', 'RS512'], idTokenSigningAlgValues: ['RS256', 'HS256', 'HS384', 'HS512'] },
    scopes: ['openid', 'offline_access', 'read'],
    subjectTypes: ['public', 'pairwise'],
    acrValues: ['first', 'second'],
    jwks: { keys: [{ ...privateKey.export({ format: 'jwk' }), kid: 'registration', alg: 'RS256', use: 'sig' }] },
    features: {
      devInteractions: { enabled: false },
      registration: { enabled: true, initialAccessToken: initialToken },
      registrationManagement: { enabled: true },
      requestObjects: { enabled: true },
      richAuthorizationRequests: {
        enabled: true, types: { support_data: { validate: async () => {} } },
      },
      resourceIndicators: {
        enabled: true,
        getResourceServerInfo: async (_ctx, resource) => {
          if (resource !== 'https://api.example.test') throw new errors.InvalidTarget();
          return { scope: 'read', audience: resource };
        },
      },
      ciba: {
        enabled: true, deliveryModes: ['poll', 'ping'],
        processLoginHint: async (_ctx, hint) => hint === 'customer' ? hint : undefined,
        // Context/binding checks are app no-ops; code policy is explicit below.
        validateRequestContext: async () => {},
        validateBindingMessage: async () => {},
        verifyUserCode: async (ctx, _account, code) => {
          if (ctx.oidc.client.backchannelUserCodeParameter && code !== 'approved-code') throw new errors.InvalidUserCode();
        },
        triggerAuthenticationDevice: async () => {},
      },
    },
    findAccount: async (_ctx, accountId) => ({ accountId, claims: async () => ({ sub: accountId }) }),
  });
  const discovery = await (await fetch(`${issuer}/.well-known/openid-configuration`)).json();
  assert(discovery.registration_endpoint);
  assert(!discovery.token_endpoint_auth_methods_supported.includes("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
  const base = {
    grant_types: [grantType], response_types: [],
    token_endpoint_auth_method: 'client_secret_basic', backchannel_token_delivery_mode: 'poll',
  };
  async function register(metadata, token = initialToken) {
    const response = await fetch(discovery.registration_endpoint, {
      method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify(metadata),
    });
    return { status: response.status, body: await response.json() };
  }
  assert.equal((await register(base, 'wrong')).status, 401);
  for (const value of ['first', true, {}, [1], ['unknown']]) {
    const result = await register({ ...base, default_acr_values: value });
    assert.equal(result.status, 400, JSON.stringify(result.body));
    assert.equal(result.body.error, 'invalid_client_metadata');
  }
  for (const value of [[], ['second', 'first', 'second']]) {
    const result = await register({ ...base, default_acr_values: value });
    assert.equal(result.status, 201, JSON.stringify(result.body));
    assert.deepEqual(result.body.default_acr_values, [...new Set(value)]);
    const read = await fetch(result.body.registration_client_uri, {
      headers: { authorization: `Bearer ${result.body.registration_access_token}` },
    });
    assert.equal(read.status, 200);
    assert.deepEqual((await read.json()).default_acr_values, [...new Set(value)]);
  }
  console.log('PASS DCR default_acr_values validates supported strings and preserves unique preference order');

  for (const value of ['true', 'false', 0, 1, [], {}]) {
    const result = await register({ ...base, require_auth_time: value });
    assert.equal(result.status, 400, JSON.stringify(result.body));
    assert.equal(result.body.error, 'invalid_client_metadata');
  }
  for (const value of [true, false]) {
    const result = await register({ ...base, require_auth_time: value });
    assert.equal(result.status, 201, JSON.stringify(result.body));
    assert.equal(result.body.require_auth_time, value);
    const read = await fetch(result.body.registration_client_uri, {
      headers: { authorization: `Bearer ${result.body.registration_access_token}` },
    });
    assert.equal(read.status, 200);
    assert.equal((await read.json()).require_auth_time, value);
  }
  console.log('PASS DCR require_auth_time accepts and retains only boolean values');
  for (const value of [-1, 1.5, '60', true, [], {}, Number.MAX_SAFE_INTEGER + 1]) {
    const result = await register({ ...base, default_max_age: value });
    assert.equal(result.status, 400, JSON.stringify(result.body));
    assert.equal(result.body.error, 'invalid_client_metadata');
  }
  for (const value of [0, 60, Number.MAX_SAFE_INTEGER]) {
    const result = await register({ ...base, default_max_age: value });
    assert.equal(result.status, 201, JSON.stringify(result.body));
    assert.equal(result.body.default_max_age, value);
  }
  console.log('PASS DCR default_max_age accepts only nonnegative safe integers');
  const supplied = await register({ ...base, internal_admin: true, id: 999, client_secret: 'attacker-chosen' });
  assert.equal(supplied.status, 201, JSON.stringify(supplied.body));
  assert.equal(supplied.body.internal_admin, undefined);
  assert.equal(supplied.body.id, undefined);
  assert.equal(typeof supplied.body.client_secret, 'string');
  assert.notEqual(supplied.body.client_secret, 'attacker-chosen');
  console.log('PASS DCR metadata: unknown internal fields ignored and supplied secret replaced by OP-generated secret');
  const registered = await register(base);
  assert.equal(registered.status, 201, JSON.stringify(registered.body));
  assert.deepEqual(registered.body.redirect_uris, []);
  assert.equal(registered.body.client_name, undefined);
  assert.equal(registered.body.backchannel_token_delivery_mode, 'poll');
  assert.equal(typeof registered.body.client_secret, 'string');
  console.log('PASS DCR poll: authenticated registration, no redirect URI/client name required, generated confidential credentials');
  for (const algorithm of ['HS256', 'HS384', 'HS512']) {
    const hmacClient = await register({ ...base, id_token_signed_response_alg: algorithm });
    assert.equal(hmacClient.status, 201, JSON.stringify(hmacClient.body));
    assert.ok(Buffer.byteLength(hmacClient.body.client_secret) >= Number(algorithm.slice(2)) / 8);
  }
  console.log('PASS HMAC ID Token DCR generates a sufficiently long client secret for HS256/HS384/HS512');

  const disabledEncryption = await register({ ...base, id_token_encrypted_response_alg: 'RSA-OAEP-256', id_token_encrypted_response_enc: 'A256GCM', jwks_uri: 'https://recipient.example.test/jwks' });
  assert.equal(disabledEncryption.status, 201);
  assert.equal(disabledEncryption.body.id_token_encrypted_response_alg, undefined);
  assert.equal(disabledEncryption.body.id_token_encrypted_response_enc, undefined);
  const ignoredEncryptionClient = await provider.Client.find(disabledEncryption.body.client_id);
  assert.equal(ignoredEncryptionClient.idTokenEncryptedResponseAlg, undefined);
  assert.equal(ignoredEncryptionClient.idTokenEncryptedResponseEnc, undefined);
  console.log('PASS encryption disabled: DCR accepts registration but ignores encryption metadata in response and stored client');
  const invalid = [
    ['assertion type used as authentication method', { ...base, token_endpoint_auth_method: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' }],
    ['missing delivery mode', { ...base, backchannel_token_delivery_mode: undefined }],
    ['unsupported push', { ...base, backchannel_token_delivery_mode: 'push' }],
    ['missing ping endpoint', { ...base, backchannel_token_delivery_mode: 'ping' }],
    ['HTTP ping endpoint', { ...base, backchannel_token_delivery_mode: 'ping', backchannel_client_notification_endpoint: 'http://example.test/ping' }],
    ['string user-code boolean', { ...base, backchannel_user_code_parameter: 'true' }],
    ['pairwise with basic authentication', { ...base, subject_type: 'pairwise', jwks_uri: 'https://example.test/jwks' }],
  ];
  for (const [label, metadata] of invalid) {
    const result = await register(metadata);
    assert.equal(result.status, 400, `${label}: ${JSON.stringify(result.body)}`);
    assert.equal(result.body.error, 'invalid_client_metadata', label);
    console.log(`PASS DCR rejects ${label}`);
  }
  // Signed authentication requests do not waive pairwise client-auth requirements.
  const signedBasic = { ...base, subject_type: 'public', jwks_uri: 'https://example.test/jwks',
    backchannel_authentication_request_signing_alg: 'RS256' };
  const publicSigned = await register(signedBasic);
  assert.equal(publicSigned.status, 201, JSON.stringify(publicSigned.body));
  const pairwiseSigned = await register({ ...signedBasic, subject_type: 'pairwise' });
  assert.equal(pairwiseSigned.status, 400, JSON.stringify(pairwiseSigned.body));
  assert.equal(pairwiseSigned.body.error, 'invalid_client_metadata');
  assert.match(pairwiseSigned.body.error_description, /must utilize private_key_jwt or self_signed_tls_client_auth/);
  console.log('PASS signed-request Basic client: public accepted, pairwise rejected by authentication-method policy');

  const ping = await register({ ...base, backchannel_token_delivery_mode: 'ping', backchannel_client_notification_endpoint: 'https://example.test/ping', backchannel_user_code_parameter: true });
  assert.equal(ping.status, 201, JSON.stringify(ping.body));
  assert.equal(ping.body.backchannel_user_code_parameter, true);
  console.log('PASS DCR ping: HTTPS endpoint and boolean user-code metadata accepted (delivery not exercised)');

  const requestKey = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const composed = await register({ ...base, backchannel_token_delivery_mode: 'ping',
    backchannel_client_notification_endpoint: 'https://example.test/ping', backchannel_user_code_parameter: true,
    backchannel_authentication_request_signing_alg: 'RS256',
    jwks: { keys: [{ ...requestKey.publicKey.export({ format: 'jwk' }), alg: 'RS256', use: 'sig', kid: 'request' }] },
  });
  assert.equal(composed.status, 201, JSON.stringify(composed.body));
  for (const [code, expected] of [['wrong', 400], ['approved-code', 200]]) {
    const now = Math.floor(Date.now() / 1000);
    const jwtInput = [ { alg: 'RS256', kid: 'request' }, {
      iss: composed.body.client_id, aud: issuer, iat: now, nbf: now - 1, exp: now + 120, jti: `composed-${code}`,
      scope: 'openid', login_hint: 'customer', user_code: code, client_notification_token: 'dynamic-notification-secret-12345',
    } ].map((part) => Buffer.from(JSON.stringify(part)).toString('base64url')).join('.');
    const jwt = `${jwtInput}.${sign('sha256', Buffer.from(jwtInput), requestKey.privateKey).toString('base64url')}`;
    const response = await fetch(discovery.backchannel_authentication_endpoint, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${Buffer.from(`${composed.body.client_id}:${composed.body.client_secret}`).toString('base64')}` },
      body: new URLSearchParams({ request: jwt }),
    });
    const body = await response.json();
    assert.equal(response.status, expected, JSON.stringify(body));
    if (expected === 400) assert.equal(body.error, 'invalid_user_code');
    else assert.equal(typeof body.auth_req_id, 'string');
  }
  console.log('PASS DCR composition: registered ping/signature/user-code client authenticates signed request; application rejects incorrect code (no completion/delivery)');

  for (const types of ['support_data', [1], [''], ['unregistered'], {}]) {
    const result = await register({ ...base, authorization_details_types: types });
    assert.equal(result.status, 400, JSON.stringify(result.body));
    assert.equal(result.body.error, 'invalid_client_metadata');
  }
  const rich = await register({ ...base, authorization_details_types: ['support_data'] });
  assert.equal(rich.status, 201, JSON.stringify(rich.body));
  assert.deepEqual(rich.body.authorization_details_types, ['support_data']);
  const richRequest = () => fetch(discovery.backchannel_authentication_endpoint, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${Buffer.from(`${rich.body.client_id}:${rich.body.client_secret}`).toString('base64')}` },
    body: new URLSearchParams({ scope: 'openid read', login_hint: 'customer', resource: 'https://api.example.test',
      authorization_details: JSON.stringify([{ type: 'support_data', actions: ['read'] }]) }),
  });
  const allowedRich = await richRequest();
  assert.equal(allowedRich.status, 200, await allowedRich.text());
  const removeTypes = await fetch(rich.body.registration_client_uri, {
    method: 'PUT', headers: { authorization: `Bearer ${rich.body.registration_access_token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ ...base, client_id: rich.body.client_id }),
  });
  const removedTypes = await removeTypes.json();
  assert.equal(removeTypes.status, 200, JSON.stringify(removedTypes));
  assert.deepEqual(removedTypes.authorization_details_types, []);
  const deniedRich = await richRequest();
  assert.equal(deniedRich.status, 400);
  assert.equal((await deniedRich.json()).error, 'invalid_authorization_details');
  console.log('PASS DCR RAR: validated type array, registered request accepted, replacement omission clears types and rejects later RAR request');

  async function post(endpoint, params) {
    const response = await fetch(endpoint, {
      method: 'POST', headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${Buffer.from(`${registered.body.client_id}:${registered.body.client_secret}`).toString('base64')}`,
      }, body: new URLSearchParams(params),
    });
    return { status: response.status, body: await response.json() };
  }
  const authKey = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const publicJwk = authKey.publicKey.export({ format: 'jwk' });
  const invalidSets = [{}, { keys: null }, { keys: {} }, { keys: [null] },
    { keys: [{ kty: 'oct', k: 'c2VjcmV0' }] }, { keys: [{ ...publicJwk, n: '' }] },
    { keys: [{ ...publicJwk, kid: 1 }] }, { keys: [{ ...publicJwk, x5c: [1] }] },
    ...['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'].map((field) => ({ keys: [{ ...publicJwk, [field]: 'private-fixture' }] })),
  ];
  for (const jwks of invalidSets) {
    const result = await register({ ...base, token_endpoint_auth_method: 'private_key_jwt', jwks });
    assert.equal(result.status, 400, JSON.stringify(result));
    assert.equal(result.body.error, 'invalid_client_metadata');
  }
  assert.equal((await register({ ...base, token_endpoint_auth_method: 'private_key_jwt', jwks: { keys: [] } })).status, 201);
  console.log('PASS DCR JWKS: malformed structure, symmetric keys, private RSA fields and malformed metadata rejected; empty set accepted');
  const authClient = await register({ ...base, token_endpoint_auth_method: 'private_key_jwt',
    token_endpoint_auth_signing_alg: 'RS512',
    jwks: { keys: [{ ...authKey.publicKey.export({ format: 'jwk' }), kid: 'auth', use: 'sig' }] },
  });
  assert.equal(authClient.status, 201, JSON.stringify(authClient.body));
  for (const algorithm of ['none', 'HS256', 'unknown', 1, ['RS256']]) {
    const invalid = await register({ ...base, token_endpoint_auth_method: 'private_key_jwt',
      token_endpoint_auth_signing_alg: algorithm,
      jwks: { keys: [authKey.publicKey.export({ format: 'jwk' })] } });
    assert.equal(invalid.status, 400, JSON.stringify(invalid));
    assert.equal(invalid.body.error, 'invalid_client_metadata');
  }
  assert.equal((await register({ ...base, token_endpoint_auth_signing_alg: 'RS256' })).status, 400);
  let assertionSequence = 0;
  function assertion(audience, key = authKey.privateKey, algorithm = 'RS512') {
    const now = Math.floor(Date.now() / 1000);
    const input = [{ alg: algorithm, kid: 'auth' }, {
      iss: authClient.body.client_id, sub: authClient.body.client_id, aud: audience,
      iat: now, exp: now + 60, jti: `dynamic-auth-${++assertionSequence}`,
    }].map((part) => Buffer.from(JSON.stringify(part)).toString('base64url')).join('.');
    return `${input}.${sign(algorithm === 'RS512' ? 'sha512' : 'sha256', Buffer.from(input), key).toString('base64url')}`;
  }
  async function assertedPost(endpoint, jwt, params) {
    const response = await fetch(endpoint, { method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ ...params, client_id: authClient.body.client_id,
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: jwt }),
    });
    return { status: response.status, body: await response.json() };
  }
  const beginParams = { scope: 'openid', login_hint: 'customer' };
  for (const jwt of [assertion('https://wrong.example.test'), assertion(issuer, privateKey), assertion(issuer, authKey.privateKey, 'RS256')]) {
    const bad = await assertedPost(discovery.backchannel_authentication_endpoint, jwt, beginParams);
    assert.equal(bad.body.error, 'invalid_client', JSON.stringify(bad));
  }
  const firstAssertion = assertion(issuer);
  const authStarted = await assertedPost(discovery.backchannel_authentication_endpoint, firstAssertion, beginParams);
  assert.equal(authStarted.status, 200, JSON.stringify(authStarted));
  assert.equal((await assertedPost(discovery.backchannel_authentication_endpoint, firstAssertion, beginParams)).body.error, 'invalid_client');
  const authGrant = new provider.Grant({ accountId: 'customer', clientId: authClient.body.client_id });
  authGrant.addOIDCScope('openid');
  await authGrant.save();
  await provider.backchannelResult(authStarted.body.auth_req_id, authGrant, { authTime: Math.floor(Date.now() / 1000) });
  const authTokens = await assertedPost(discovery.token_endpoint, assertion(issuer),
    { grant_type: grantType, auth_req_id: authStarted.body.auth_req_id });
  assert.equal(authTokens.status, 200, JSON.stringify(authTokens));
  console.log('PASS DCR private_key_jwt: registered RS512 enforced, invalid algorithm metadata and wrong key/audience/RS256/replay rejected; issuer audience accepted at start AND token endpoint');

  const started = await post(discovery.backchannel_authentication_endpoint, { scope: 'openid', login_hint: 'customer' });
  assert.equal(started.status, 200, JSON.stringify(started.body));
  const grant = new provider.Grant({ accountId: 'customer', clientId: registered.body.client_id });
  grant.addOIDCScope('openid');
  await grant.save();
  await provider.backchannelResult(started.body.auth_req_id, grant, { authTime: Math.floor(Date.now() / 1000) });
  const tokens = await post(discovery.token_endpoint, { grant_type: grantType, auth_req_id: started.body.auth_req_id });
  assert.equal(tokens.status, 200, JSON.stringify(tokens.body));
  assert.equal(typeof tokens.body.id_token, 'string');
  assert.equal(typeof tokens.body.access_token, 'string');
  console.log('PASS DCR-issued credentials: start, application completion and poll token issuance through actual HTTP endpoints');
  const managed = supplied.body;
  const managementHeaders = { authorization: `Bearer ${managed.registration_access_token}` };
  const read = await fetch(managed.registration_client_uri, { headers: managementHeaders });
  assert.equal(read.status, 200);
  const readBody = await read.json();
  assert.equal(readBody.registration_access_token, managed.registration_access_token);
  assert.equal(readBody.token_endpoint_auth_method, 'client_secret_basic');
  const isolated = (await register(base)).body;
  const isolatedHeaders = { authorization: `Bearer ${isolated.registration_access_token}` };
  const foreign = await fetch(registered.body.registration_client_uri, { headers: isolatedHeaders });
  assert.equal(foreign.status, 401);
  const invalidated = await fetch(isolated.registration_client_uri, { headers: isolatedHeaders });
  assert.equal(invalidated.status, 401);
  const partial = await fetch(managed.registration_client_uri, {
    method: 'PUT', headers: { ...managementHeaders, 'content-type': 'application/json' },
    body: JSON.stringify({ client_name: 'partial' }),
  });
  assert.equal(partial.status, 400);
  const update = await fetch(managed.registration_client_uri, {
    method: 'PUT', headers: { ...managementHeaders, 'content-type': 'application/json' },
    body: JSON.stringify({ ...base, client_id: managed.client_id, client_name: 'Managed client' }),
  });
  const updated = await update.json();
  assert.equal(update.status, 200, JSON.stringify(updated));
  assert.equal(updated.client_name, 'Managed client');
  assert.notEqual(updated.registration_access_token, managed.registration_access_token);
  assert.equal((await fetch(managed.registration_client_uri, { headers: managementHeaders })).status, 401);
  const replacement = await fetch(managed.registration_client_uri, {
    method: 'PUT', headers: { authorization: `Bearer ${updated.registration_access_token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ ...base, client_id: managed.client_id }),
  });
  const replaced = await replacement.json();
  assert.equal(replacement.status, 200, JSON.stringify(replaced));
  assert.equal(replaced.client_name, undefined);
  assert.equal(replaced.client_secret, managed.client_secret);
  assert.notEqual(replaced.registration_access_token, updated.registration_access_token);
  const removed = await fetch(managed.registration_client_uri, {
    method: 'DELETE', headers: { authorization: `Bearer ${replaced.registration_access_token}` },
  });
  assert.equal(removed.status, 204);
  console.log('PASS DCR management: issued bearer, read echo, cross-client rejection invalidates presented bearer, partial update rejection, replacement clears omitted name and preserves secret, default update rotation rejects old bearer, deletion');
  const pendingBeforeDelete = await post(discovery.backchannel_authentication_endpoint, { scope: 'openid', login_hint: 'customer' });
  assert.equal(pendingBeforeDelete.status, 200, JSON.stringify(pendingBeforeDelete.body));
  const deleteWithGrant = await fetch(registered.body.registration_client_uri, {
    method: 'DELETE', headers: { authorization: `Bearer ${registered.body.registration_access_token}` },
  });
  assert.equal(deleteWithGrant.status, 204);
  const afterDeletePoll = await post(discovery.token_endpoint, { grant_type: grantType, auth_req_id: pendingBeforeDelete.body.auth_req_id });
  const afterDeleteUserinfo = await fetch(discovery.userinfo_endpoint, { headers: { authorization: `Bearer ${tokens.body.access_token}` } });
  assert.equal(afterDeletePoll.status, 401);
  assert.equal(afterDeletePoll.body.error, 'invalid_client');
  assert.equal(afterDeleteUserinfo.status, 401);
  assert.equal((await afterDeleteUserinfo.json()).error, 'invalid_token');
  assert(await provider.Grant.find(grant.jti));
  assert(await provider.AccessToken.find(tokens.body.access_token));
  assert(await provider.BackchannelAuthenticationRequest.find(pendingBeforeDelete.body.auth_req_id));
  console.log('PASS DCR delete with existing grant: poll/UserInfo denied; memory adapter retains grant, access token and pending request records');
} finally {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
}
