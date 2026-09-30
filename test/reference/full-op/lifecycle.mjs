// Full HTTP OP, built-in nontransactional memory adapter, real token signing.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync, createPublicKey, verify, sign } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { Provider, errors } from 'oidc-provider';
import { CompactEncrypt, compactDecrypt } from 'jose';

const grantType = 'urn:openid:params:grant-type:ciba';
const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...privateKey.export({ format: 'jwk' }), kid: 'reference', use: 'sig', alg: 'RS256' };
const { privateKey: hintEncryptionKey, publicKey: hintEncryptionPublicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const { privateKey: requestKey, publicKey: requestPublicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
let provider;
let failClaims = false;
let failDevice = false;
let useGrantedResource = false;
let defaultResource;
let opaqueResourceTokens = false;
let rejectRequestContext = false;
const requestContexts = [];
const delivered = new Set();
const claimCalls = [];
const rarCalls = [];
const server = createServer((req, res) => provider.callback()(req, res));
await new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', resolve);
});
const issuer = `http://127.0.0.1:${server.address().port}`;
try {
  provider = new Provider(issuer, {
    scopes: ['openid', 'offline_access', 'read', 'write'],
    jwks: { keys: [jwk, { ...hintEncryptionKey.export({ format: 'jwk' }),
      kid: 'hint-encryption', use: 'enc', alg: 'RSA-OAEP-256' }] },
    claims: { email: null, email_verified: null },
    clients: ['client', 'other', 'coded', 'refresh', 'refresh-other'].map((client_id) => ({
      client_id, client_secret: 'reference-test-secret', grant_types: client_id.startsWith('refresh') ? [grantType, 'refresh_token'] : [grantType],
      response_types: [], redirect_uris: [], token_endpoint_auth_method: 'client_secret_basic',
      backchannel_token_delivery_mode: 'poll',
      backchannel_user_code_parameter: client_id === 'coded',
      authorization_details_types: ['client', 'refresh'].includes(client_id) ? ['support_data'] : [],
    })).concat([{
      client_id: 'signed', client_secret: 'reference-test-secret', grant_types: [grantType],
      response_types: [], redirect_uris: [], token_endpoint_auth_method: 'client_secret_basic',
      backchannel_token_delivery_mode: 'poll', backchannel_authentication_request_signing_alg: 'RS256',
      jwks: { keys: [{ ...requestPublicKey.export({ format: 'jwk' }), kid: 'request', use: 'sig', alg: 'RS256' }] },
    }]),
    features: {
      revocation: { enabled: true },
      requestObjects: { enabled: true },
      encryption: { enabled: true },
      introspection: {
        enabled: true,
        allowedPolicy: async (_ctx, client, token) => client.clientId === token.clientId,
      },
      richAuthorizationRequests: {
        enabled: true,
        types: {
          support_data: {
            validate: async (_ctx, detail) => {
              if (detail.actions?.some((action) => !['read', 'delete'].includes(action))) {
                throw new errors.InvalidAuthorizationDetails('unsupported support action');
              }
            },
          },
        },
        authorizationDetailsForGrantSource: async () => {
          rarCalls.push('source');
          return undefined;
        },
        // Test application's explicit policy: only the completed source permits
        // actions. A token-time parameter cannot add new actions to that source.
        authorizationDetailsForAccessToken: async (_ctx, _token, source) => {
          rarCalls.push('access');
          return source.rar;
        },
        authorizationDetailsForIntrospection: async (_ctx, token) => token.rar,
      },
      resourceIndicators: {
        enabled: true,
        useGrantedResource: async () => useGrantedResource,
        defaultResource: async (_ctx, _client, resources) => defaultResource ?? resources,
        getResourceServerInfo: async (_ctx, resource) => {
          if (!['https://api.example.test/a', 'https://api.example.test/b'].includes(resource)) {
            throw new errors.InvalidTarget();
          }
          return { scope: 'read write', audience: resource, accessTokenFormat: opaqueResourceTokens ? 'opaque' : 'jwt', jwt: { sign: { alg: 'RS256' } } };
        },
      },
      claimsParameter: { enabled: true },
      devInteractions: { enabled: false },
      ciba: {
        enabled: true, deliveryModes: ['poll'],
        processLoginHint: async (_ctx, hint) => hint === 'customer' ? hint : undefined,
        processLoginHintToken: async (ctx, hint) =>
          hint === 'opaque-customer-reference' && ctx.oidc.client.clientId === 'client' ? 'customer' : undefined,
        verifyUserCode: async (ctx, account, code) => {
          if (!ctx.oidc.client.backchannelUserCodeParameter) return;
          assert.equal(account.accountId, 'customer');
          if (code === undefined) throw new errors.MissingUserCode();
          if (code !== 'test-approval-code') throw new errors.InvalidUserCode();
        },
        validateRequestContext: async (ctx, value) => {
          requestContexts.push({ client: ctx.oidc.client.clientId, value });
          if (rejectRequestContext) throw new errors.InvalidRequest('test context rejected');
        },
        triggerAuthenticationDevice: async (_ctx, request) => {
          delivered.add(request.jti);
          if (failDevice) throw new Error('injected dispatch failure');
        },
      },
    },
    findAccount: async (_ctx, accountId) => ({
      accountId,
      claims: async (use, scope, claims, rejected) => {
        claimCalls.push({ use, scope, claims, rejected });
        if (failClaims) throw new Error('injected ID Token claims failure');
        return { sub: accountId, email: 'customer@example.test', email_verified: true };
      },
    }),
  });
  // Expected injected errors are asserted through the HTTP response below.
  provider.on('server_error', () => {});
  const metadata = await (await fetch(`${issuer}/.well-known/openid-configuration`)).json();
  const keys = await (await fetch(metadata.jwks_uri)).json();
  const key = keys.keys.find((entry) => entry.kid === 'reference');
  assert.deepEqual(metadata.backchannel_token_delivery_modes_supported, ['poll']);
  async function post(url, body, client = 'client') {
    const response = await fetch(url, {
      method: 'POST', headers: {
        authorization: `Basic ${Buffer.from(`${client}:reference-test-secret`).toString('base64')}`,
        'content-type': 'application/x-www-form-urlencoded',
      }, body: new URLSearchParams(Object.entries(body).flatMap(([name, value]) =>
        (Array.isArray(value) ? value : [value]).map((entry) => [name, entry]))),
    });
    const text = await response.text();
    return { status: response.status, body: text ? JSON.parse(text) : undefined };
  }
  async function start(extra = {}) {
    const response = await post(metadata.backchannel_authentication_endpoint,
      { scope: 'openid', login_hint: 'customer', ...extra });
    assert.equal(response.status, 200, JSON.stringify(response.body));
    assert(delivered.has(response.body.auth_req_id));
    return response.body.auth_req_id;
  }
  const poll = (id, client) => post(metadata.token_endpoint, { grant_type: grantType, auth_req_id: id }, client);
  async function expectError(id, error, client) {
    const response = await poll(id, client);
    assert.equal(response.status, 400, JSON.stringify(response.body));
    assert.equal(response.body.error, error);
  }
  async function approve(id, { allowed = [], rejected = [], resources = {}, rarConsent = [], completedRar } = {}) {
    const grant = new provider.Grant({ accountId: 'customer', clientId: 'client' });
    grant.addOIDCScope('openid');
    grant.addOIDCClaims(allowed);
    grant.rejectOIDCClaims(rejected);
    for (const [resource, scope] of Object.entries(resources)) grant.addResourceScope(resource, scope);
    for (const detail of rarConsent) grant.addRar(detail);
    await grant.save();
    const saved = await provider.Grant.find(grant.jti);
    assert.equal(saved.exp - saved.iat, 14 * 24 * 60 * 60);
    await provider.backchannelResult(id, grant, { authTime: Math.floor(Date.now() / 1000), rar: completedRar });
    return grant;
  }
  const contextual = await start({ request_context: 'support-session:demo' });
  assert.deepEqual(requestContexts.at(-1), { client: 'client', value: 'support-session:demo' });
  assert.equal((await provider.BackchannelAuthenticationRequest.find(contextual)).params.request_context, 'support-session:demo');
  await approve(contextual);
  const contextTokens = await poll(contextual);
  assert.equal(contextTokens.status, 200);
  assert.equal(verifiedJwt(contextTokens.body.id_token).request_context, undefined);
  const beforeContextFailure = delivered.size;
  rejectRequestContext = true;
  const badContext = await post(metadata.backchannel_authentication_endpoint,
    { scope: 'openid', login_hint: 'customer', request_context: 'rejected' });
  rejectRequestContext = false;
  assert.equal(badContext.status, 400);
  assert.equal(badContext.body.error, 'invalid_request');
  assert.equal(delivered.size, beforeContextFailure);
  const pending = await start();
  assert.equal(requestContexts.at(-1).value, undefined);
  console.log('PASS request_context: application callback receives supplied/omitted value, stored with request, rejection precedes device dispatch, no automatic ID claim');
  await expectError(pending, 'authorization_pending');
  await expectError(pending, 'authorization_pending');
  console.log('PASS pending: repeated HTTP polls return authorization_pending');

  const hinted = await post(metadata.backchannel_authentication_endpoint,
    { scope: 'openid', login_hint_token: 'opaque-customer-reference' });
  assert.equal(hinted.status, 200, JSON.stringify(hinted.body));
  const hintedSource = await provider.BackchannelAuthenticationRequest.find(hinted.body.auth_req_id);
  assert.equal(hintedSource.accountId, 'customer');
  assert.equal(hintedSource.params.login_hint_token, 'opaque-customer-reference');
  await approve(hinted.body.auth_req_id);
  const hintedResult = await poll(hinted.body.auth_req_id);
  assert.equal(hintedResult.status, 200);
  assert.equal(verifiedJwt(hintedResult.body.id_token).sub, 'customer');
  for (const [parameters, client, expected] of [
    [{ login_hint_token: 'unknown' }, 'client', 'unknown_user_id'],
    [{ login_hint_token: 'opaque-customer-reference' }, 'other', 'unknown_user_id'],
    [{ login_hint_token: 'opaque-customer-reference', login_hint: 'customer' }, 'client', 'invalid_request'],
  ]) {
    const result = await post(metadata.backchannel_authentication_endpoint, { scope: 'openid', ...parameters }, client);
    assert.equal(result.status, 400);
    assert.equal(result.body.error, expected);
  }
  console.log('PASS login_hint_token: application resolver, client policy, exclusive hints and resolved subject');

  const denied = await start();
  await provider.backchannelResult(denied, new errors.AccessDenied());
  await expectError(denied, 'access_denied');
  await expectError(denied, 'invalid_grant');
  console.log('PASS denial: access_denied then invalid_grant');

  // This generic result API also accepts errors whose semantics are not a
  // terminal poll completion. Observe this instead of copying its allowlist.
  for (const error of [new errors.TransactionFailed(), new errors.AuthorizationPending()]) {
    const id = await start();
    await provider.backchannelResult(id, error);
    await expectError(id, error.error);
    assert((await provider.BackchannelAuthenticationRequest.find(id)).consumed);
    await expectError(id, 'invalid_grant');
  }
  console.log('PASS generic completion errors: transaction_failed/pending both consumed once');

  // backchannelResult writes error_description, but the persisted model uses
  // errorDescription. Characterize the wire result before copying this API.
  for (const error of [new errors.TransactionFailed('application failure detail'),
    new errors.CustomOIDCProviderError('application_failure', 'application failure detail'),
    new errors.CustomOIDCProviderError('server_error'), new errors.InvalidToken(),
    new errors.InsufficientScope('application failure detail')]) {
    const id = await start();
    await provider.backchannelResult(id, error);
    const stored = await provider.BackchannelAuthenticationRequest.find(id);
    assert.equal(stored.errorDescription, undefined);
    const response = await poll(id);
    assert.equal(response.status, error.status);
    assert.equal(response.body.error, error.error);
    assert.notEqual(response.body.error_description, 'application failure detail');
    await expectError(id, 'invalid_grant');
    console.log('PASS completion error description boundary:', JSON.stringify(response.body));
  }

  failDevice = true;
  const dispatch = await post(metadata.backchannel_authentication_endpoint,
    { scope: 'openid', login_hint: 'customer' });
  failDevice = false;
  assert.equal(dispatch.status, 500);
  assert.equal(dispatch.body.error, 'server_error');
  assert.equal(dispatch.body.auth_req_id, undefined);
  const abandonedId = [...delivered].at(-1);
  const abandoned = await provider.BackchannelAuthenticationRequest.find(abandonedId);
  assert(abandoned);
  assert.equal(abandoned.consumed, undefined);
  await expectError(abandonedId, 'authorization_pending');
  console.log('PASS dispatch failure: persisted pending request survives without identifier in response');

  const success = await start({ nonce: 'start-correlation' });
  const grant = await approve(success);
  await expectError(success, 'invalid_grant', 'other');
  assert(await provider.Grant.find(grant.jti));
  const issued = await post(metadata.token_endpoint, {
    grant_type: grantType, auth_req_id: success, nonce: 'poll-tampering',
  });
  assert.equal(issued.status, 200, JSON.stringify(issued.body));
  const [header, payload, signature] = issued.body.id_token.split('.');
  assert.equal(JSON.parse(Buffer.from(header, 'base64url')).alg, 'RS256');
  assert(verify('RSA-SHA256', Buffer.from(`${header}.${payload}`),
    createPublicKey({ key, format: 'jwk' }), Buffer.from(signature, 'base64url')));
  const claims = JSON.parse(Buffer.from(payload, 'base64url'));
  assert.equal(claims.iss, issuer);
  assert.equal(claims.aud, 'client');
  assert.equal(claims.sub, 'customer');
  assert.equal(claims.nonce, 'start-correlation');
  assert(claims.exp > Date.now() / 1000);
  assert(await provider.AccessToken.find(issued.body.access_token));
  await expectError(success, 'invalid_grant');
  assert.equal(await provider.AccessToken.find(issued.body.access_token), undefined);
  assert.equal(await provider.Grant.find(grant.jti), undefined);
  console.log('PASS success/signature/client isolation/replay revocation');

  function signedHint(payload, header = { alg: 'RS256', kid: 'reference', typ: 'JWT' }) {
    const input = [header, payload].map((value) => Buffer.from(JSON.stringify(value)).toString('base64url')).join('.');
    return `${input}.${sign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url')}`;
  }
  const now = Math.floor(Date.now() / 1000);
  for (const hint of [issued.body.id_token, signedHint({ ...claims, iat: now - 7200, exp: now - 3600 }),
    signedHint({ ...claims, azp: 'other' }), signedHint({ ...claims, aud: ['client', 'other'] }),
    signedHint({ ...claims, iat: now + 3600 }),
    signedHint({ ...claims, iat: now - 0.5, exp: now - 0.5, nbf: now - 0.5 }),
    signedHint({ ...claims, iat: undefined, exp: undefined }),
    signedHint({ ...claims, exp: 'ignored for hint' }),
    signedHint(claims, { alg: 'RS256', kid: 'reference', typ: 'at+jwt' }),
    signedHint(claims, { alg: 'RS256', kid: 'reference', b64: true, crit: ['b64'] })]) {
    const response = await post(metadata.backchannel_authentication_endpoint, { scope: 'openid', id_token_hint: hint });
    assert.equal(response.status, 200, JSON.stringify(response.body));
    const source = await provider.BackchannelAuthenticationRequest.find(response.body.auth_req_id);
    assert.equal(source.accountId, 'customer');
    assert.equal(source.grantId, undefined); // The hint never constitutes approval.
    await expectError(response.body.auth_req_id, 'authorization_pending');
  }
  for (const changes of [
    { iss: 'https://other.example.test' }, { aud: 'other' }, { sub: undefined },
    { nbf: now + 3600 }, { iat: now + 3600, exp: undefined },
    { iat: null }, { nbf: 'invalid' }, { jti: 1 },
  ]) {
    const response = await post(metadata.backchannel_authentication_endpoint,
      { scope: 'openid', id_token_hint: signedHint({ ...claims, ...changes }) });
    assert.equal(response.status, 400, JSON.stringify(response.body));
    assert.equal(response.body.error, 'invalid_request');
  }
  const parts = issued.body.id_token.split('.');
  parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
  const tamperedHint = await post(metadata.backchannel_authentication_endpoint,
    { scope: 'openid', id_token_hint: parts.join('.') });
  assert.equal(tamperedHint.status, 400);
  assert.equal(tamperedHint.body.error, 'invalid_request');
  console.log('PASS id_token_hint: current/expired/multiple-audience hints remain pending; issuer/audience/subject/nbf/signature checked, azp not checked');

  // Test an actual nested JWE, not merely a malformed five-segment string.
  // The OP owns the decryption key; its hint validator still accepts JWS only.
  const encryptedHint = await new CompactEncrypt(Buffer.from(issued.body.id_token))
    .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM', cty: 'JWT', kid: 'hint-encryption' })
    .encrypt(hintEncryptionPublicKey);
  const decryptedHint = await compactDecrypt(encryptedHint, hintEncryptionKey);
  assert.equal(Buffer.from(decryptedHint.plaintext).toString(), issued.body.id_token);
  const beforeEncryptedHint = delivered.size;
  const encryptedHintResponse = await post(metadata.backchannel_authentication_endpoint,
    { scope: 'openid', id_token_hint: encryptedHint });
  assert.equal(encryptedHintResponse.status, 400, JSON.stringify(encryptedHintResponse.body));
  assert.equal(encryptedHintResponse.body.error, 'invalid_request');
  assert.equal(delivered.size, beforeEncryptedHint);
  console.log('PASS encrypted id_token_hint rejected before device dispatch despite valid nested JWE and OP decryption key');

  function signedRequest(changes = {}, signingKey = requestKey, headerChanges = {}) {
    const payload = { iss: 'signed', aud: issuer, exp: now + 300, iat: now, nbf: now - 1,
      jti: 'request-reference', scope: 'openid', login_hint: 'customer', requested_expiry: 123, ...changes };
    const header = { alg: 'RS256', kid: 'request', typ: 'oauth-authz-req+jwt', ...headerChanges };
    const input = [header, payload].map((value) => Buffer.from(JSON.stringify(value)).toString('base64url')).join('.');
    return `${input}.${sign('RSA-SHA256', Buffer.from(input), signingKey).toString('base64url')}`;
  }
  async function signedStart(body) {
    return post(metadata.backchannel_authentication_endpoint, body, 'signed');
  }
  assert(metadata.backchannel_authentication_request_signing_alg_values_supported.includes('RS256'));
  const requestJwt = signedRequest();
  const signedAccepted = await signedStart({ request: requestJwt });
  assert.equal(signedAccepted.status, 200, JSON.stringify(signedAccepted.body));
  assert.equal(signedAccepted.body.expires_in, 123);
  const signedSource = await provider.BackchannelAuthenticationRequest.find(signedAccepted.body.auth_req_id);
  assert.equal(signedSource.accountId, 'customer');
  assert.equal(signedSource.grantId, undefined);
  await expectError(signedAccepted.body.auth_req_id, 'authorization_pending', 'signed');
  const signedGrant = new provider.Grant({ accountId: 'customer', clientId: 'signed' });
  signedGrant.addOIDCScope('openid');
  await signedGrant.save();
  await provider.backchannelResult(signedAccepted.body.auth_req_id, signedGrant, { authTime: now });
  const signedIssued = await poll(signedAccepted.body.auth_req_id, 'signed');
  assert.equal(signedIssued.status, 200, JSON.stringify(signedIssued.body));
  assert.equal(verifiedJwt(signedIssued.body.id_token).aud, 'signed');
  const unauthenticated = await fetch(metadata.backchannel_authentication_endpoint, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ request: requestJwt, client_id: 'signed' }),
  });
  assert.equal(unauthenticated.status, 401);
  assert.equal((await unauthenticated.json()).error, 'invalid_client');
  // The default reference policy requires jti but does not consume a replay ledger.
  const repeatedRequest = await signedStart({ request: requestJwt });
  assert.equal(repeatedRequest.status, 200, JSON.stringify(repeatedRequest.body));
  assert.notEqual(repeatedRequest.body.auth_req_id, signedAccepted.body.auth_req_id);
  const outerIgnored = await signedStart({ request: requestJwt, login_hint: 'unknown', scope: 'untrusted' });
  assert.equal(outerIgnored.status, 200, JSON.stringify(outerIgnored.body));
  const stringExpiry = await signedStart({ request: signedRequest({ requested_expiry: '123' }) });
  assert.equal(stringExpiry.status, 200, JSON.stringify(stringExpiry.body));
  assert.equal(stringExpiry.body.expires_in, 123);
  const unsigned = await signedStart({ scope: 'openid', login_hint: 'customer' });
  assert.equal(unsigned.status, 400);
  assert.equal(unsigned.body.error, 'invalid_request');
  for (const change of [
    ...['iss', 'aud', 'exp', 'iat', 'nbf', 'jti'].map((name) => ({ [name]: undefined })),
    { iss: 'other' }, { aud: 'https://wrong.example' }, { exp: now - 3600 },
    { nbf: now + 3600 }, { client_id: 'other' }, { request: 'nested' }, { request_uri: 'https://example.test/jar' },
    { scope: undefined }, { login_hint: undefined },
  ]) {
    const result = await signedStart({ request: signedRequest(change), scope: 'openid', login_hint: 'customer' });
    assert.equal(result.status, 400, JSON.stringify({ change, result }));
    assert.equal(result.body.error, 'invalid_request', JSON.stringify({ change, result }));
  }
  for (const request of [signedRequest({}, privateKey), signedRequest({}, requestKey, { kid: 'unknown' })]) {
    const result = await signedStart({ request });
    assert.equal(result.status, 400, JSON.stringify(result.body));
    assert.equal(result.body.error, 'invalid_request');
  }
  // These weaker default checks are measured, not recommended application policy.
  for (const change of [{ iat: now + 3600 }, { jti: '' }]) {
    const result = await signedStart({ request: signedRequest(change) });
    assert.equal(result.status, 200, JSON.stringify({ change, result }));
  }
  console.log('PASS signed CIBA requests: registered algorithm/key, required claims, JWT-only parameters, numeric/string expiry; default jti reuse accepted');
  assert.equal(metadata.backchannel_user_code_parameter_supported, true);
  const beforeCode = delivered.size;
  for (const [code, error] of [[undefined, 'missing_user_code'], ['wrong', 'invalid_user_code']]) {
    const params = { scope: 'openid', login_hint: 'customer' };
    if (code !== undefined) params.user_code = code;
    const result = await post(metadata.backchannel_authentication_endpoint, params, 'coded');
    assert.equal(result.status, 400, JSON.stringify(result.body));
    assert.equal(result.body.error, error);
  }
  assert.equal(delivered.size, beforeCode);
  const coded = await post(metadata.backchannel_authentication_endpoint,
    { scope: 'openid', login_hint: 'customer', user_code: 'test-approval-code' }, 'coded');
  assert.equal(coded.status, 200, JSON.stringify(coded.body));
  await expectError(coded.body.auth_req_id, 'authorization_pending', 'coded');
  const codedGrant = new provider.Grant({ accountId: 'customer', clientId: 'coded' });
  codedGrant.addOIDCScope('openid');
  await codedGrant.save();
  await provider.backchannelResult(coded.body.auth_req_id, codedGrant, { authTime: now });
  const codedToken = await poll(coded.body.auth_req_id, 'coded');
  assert.equal(codedToken.status, 200, JSON.stringify(codedToken.body));
  assert.equal(verifiedJwt(codedToken.body.id_token).aud, 'coded');
  console.log('PASS user_code: application policy rejects missing/wrong code before dispatch; valid code still requires new approval');

  // claimsParameter is opt-in. A requested claim is not itself approval.
  for (const scenario of [
    { name: 'requested-only', request: { id_token: { email: null } }, allowed: [], rejected: [], idEmail: false, userEmail: false },
    { name: 'allowed-id-token', request: { id_token: { email: null } }, allowed: ['email'], rejected: [], idEmail: true, userEmail: false },
    { name: 'explicitly-rejected', request: { id_token: { email: null } }, allowed: ['email'], rejected: ['email'], idEmail: false, userEmail: false },
    { name: 'userinfo-only', request: { userinfo: { email: null } }, allowed: ['email'], rejected: [], idEmail: false, userEmail: true },
    { name: 'allowed-but-unrequested', request: { id_token: {} }, allowed: ['email'], rejected: [], idEmail: false, userEmail: false },
  ]) {
    const id = await start({ claims: JSON.stringify(scenario.request) });
    await approve(id, scenario);
    claimCalls.length = 0;
    const result = await post(metadata.token_endpoint, {
      grant_type: grantType, auth_req_id: id,
      claims: JSON.stringify({ id_token: { email: null, email_verified: null } }),
    });
    assert.equal(result.status, 200, JSON.stringify(result.body));
    const [h, p, sig] = result.body.id_token.split('.');
    assert.equal(JSON.parse(Buffer.from(h, 'base64url')).alg, 'RS256');
    assert(verify('RSA-SHA256', Buffer.from(`${h}.${p}`),
      createPublicKey({ key, format: 'jwk' }), Buffer.from(sig, 'base64url')));
    const tokenClaims = JSON.parse(Buffer.from(p, 'base64url'));
    assert.equal(Object.hasOwn(tokenClaims, 'email'), scenario.idEmail, scenario.name);
    assert.equal(Object.hasOwn(tokenClaims, 'email_verified'), false, scenario.name);
    assert.equal(Object.hasOwn(claimCalls.find((call) => call.use === 'id_token').claims, 'email'), scenario.idEmail);
    const userResponse = await fetch(metadata.userinfo_endpoint, {
      headers: { authorization: `Bearer ${result.body.access_token}` },
    });
    assert.equal(userResponse.status, 200);
    const userClaims = await userResponse.json();
    assert.equal(Object.hasOwn(userClaims, 'email'), scenario.userEmail, scenario.name);
    assert.equal(Object.hasOwn(userClaims, 'email_verified'), false, scenario.name);
    console.log(`PASS explicit claims: ${scenario.name}, target separation and poll tampering`);
  }
  for (const malformed of ['{', '[]', '{"id_token":[]}', '{"id_token":{"email":true}}']) {
    const response = await post(metadata.backchannel_authentication_endpoint,
      { scope: 'openid', login_hint: 'customer', claims: malformed });
    assert.equal(response.status, 400);
    assert.equal(response.body.error, 'invalid_request');
  }
  console.log('PASS claims malformed JSON/shape rejection');

  function verifiedJwt(token) {
    const [h, p, sig] = token.split('.');
    assert.equal(JSON.parse(Buffer.from(h, 'base64url')).alg, 'RS256');
    assert(verify('RSA-SHA256', Buffer.from(`${h}.${p}`),
      createPublicKey({ key, format: 'jwk' }), Buffer.from(sig, 'base64url')));
    return JSON.parse(Buffer.from(p, 'base64url'));
  }
  const resourceA = 'https://api.example.test/a';
  const resourceB = 'https://api.example.test/b';
  const targeted = await start({ scope: 'openid read write', resource: [resourceA, resourceB] });
  await approve(targeted, { resources: { [resourceA]: 'read', [resourceB]: 'write' } });
  const resourceResult = await post(metadata.token_endpoint,
    { grant_type: grantType, auth_req_id: targeted, resource: resourceA });
  assert.equal(resourceResult.status, 200, JSON.stringify(resourceResult.body));
  const accessClaims = verifiedJwt(resourceResult.body.access_token);
  assert.equal(accessClaims.aud, resourceA);
  assert.equal(accessClaims.scope, 'read');
  assert.equal(verifiedJwt(resourceResult.body.id_token).aud, 'client');
  assert.equal(resourceResult.body.scope, 'read');
  console.log('PASS resources: repeated start parameters, one selected audience, per-resource consent scope');
  const activeResource = await post(metadata.introspection_endpoint, { token: resourceResult.body.access_token });
  assert.equal(activeResource.status, 400, JSON.stringify(activeResource.body));
  assert.equal(activeResource.body.error, 'unsupported_token_type');
  await expectError(targeted, 'invalid_grant');
  const revokedResource = await post(metadata.introspection_endpoint, { token: resourceResult.body.access_token });
  assert.equal(revokedResource.status, 400);
  assert.equal(revokedResource.body.error, 'unsupported_token_type');
  console.log('PASS resource JWT introspection: structured token rejected before and after replay');

  const noPermission = await start({ scope: 'openid read', resource: resourceA });
  await approve(noPermission);
  const emptyResource = await post(metadata.token_endpoint,
    { grant_type: grantType, auth_req_id: noPermission, resource: resourceA });
  assert.equal(emptyResource.status, 200, JSON.stringify(emptyResource.body));
  assert.equal(verifiedJwt(emptyResource.body.access_token).aud, resourceA);
  assert.equal(verifiedJwt(emptyResource.body.access_token).scope, undefined);
  assert.equal(emptyResource.body.scope, '');
  console.log('PASS resources: no approved resource permission yields empty scope, never OIDC fallback');

  const unrequested = await start({ scope: 'openid read', resource: resourceA });
  await approve(unrequested, { resources: { [resourceA]: 'read', [resourceB]: 'read' } });
  const invalidResource = await post(metadata.token_endpoint,
    { grant_type: grantType, auth_req_id: unrequested, resource: resourceB });
  assert.equal(invalidResource.status, 400);
  assert.equal(invalidResource.body.error, 'invalid_target');
  assert((await provider.BackchannelAuthenticationRequest.find(unrequested)).consumed);
  console.log('PASS resources: poll cannot select unrequested target, failed resolution leaves consumption');

  const omitted = await start({ scope: 'openid read', resource: resourceA });
  await approve(omitted, { resources: { [resourceA]: 'read' } });
  const omittedResult = await poll(omitted);
  assert.equal(omittedResult.status, 200);
  const userinfoToken = await provider.AccessToken.find(omittedResult.body.access_token);
  assert.equal(userinfoToken.aud, undefined);
  assert.equal(userinfoToken.scope, 'openid');
  console.log('PASS resources: omitted token target follows default UserInfo policy');

  useGrantedResource = true;
  const selectedDefault = await start({ scope: 'openid read', resource: resourceA });
  await approve(selectedDefault, { resources: { [resourceA]: 'read' } });
  const selectedDefaultResult = await poll(selectedDefault);
  assert.equal(selectedDefaultResult.status, 200);
  assert.equal(verifiedJwt(selectedDefaultResult.body.access_token).aud, resourceA);
  const ambiguousDefault = await start({ scope: 'openid read', resource: [resourceA, resourceB] });
  await approve(ambiguousDefault, { resources: { [resourceA]: 'read', [resourceB]: 'read' } });
  await expectError(ambiguousDefault, 'invalid_target');
  defaultResource = resourceB;
  const explicitDefault = await start({ scope: 'openid read', resource: [resourceA, resourceB] });
  await approve(explicitDefault, { resources: { [resourceA]: 'read', [resourceB]: 'read' } });
  const explicitDefaultResult = await poll(explicitDefault);
  assert.equal(explicitDefaultResult.status, 200);
  assert.equal(verifiedJwt(explicitDefaultResult.body.access_token).aud, resourceB);
  useGrantedResource = false;
  defaultResource = undefined;
  console.log('PASS resources: opt-in omission selection, ambiguity rejection, explicit default selection');

  for (const badResource of ['relative', `${resourceA}#fragment`, 'https://unregistered.example.test/']) {
    const response = await post(metadata.backchannel_authentication_endpoint,
      { scope: 'openid read', login_hint: 'customer', resource: badResource });
    assert.equal(response.status, 400);
    assert.equal(response.body.error, 'invalid_target');
  }
  console.log('PASS resources: malformed/unknown target rejection');

  const requestedDetails = [{ type: 'support_data', actions: ['read', 'delete'] }];
  const approvedDetails = [{ type: 'support_data', actions: ['read'] }];
  opaqueResourceTokens = true;
  const missingRarTarget = await post(metadata.backchannel_authentication_endpoint,
    { scope: 'openid', login_hint: 'customer', authorization_details: JSON.stringify(requestedDetails) });
  assert.equal(missingRarTarget.status, 400);
  assert.equal(missingRarTarget.body.error, 'invalid_target');
  const disallowedRarClient = await post(metadata.backchannel_authentication_endpoint,
    { scope: 'openid', login_hint: 'customer', authorization_details: JSON.stringify(requestedDetails) }, 'other');
  assert.equal(disallowedRarClient.status, 400);
  assert.equal(disallowedRarClient.body.error, 'invalid_authorization_details');
  rarCalls.length = 0;
  const rarWithoutCompletion = await start({ resource: resourceA, authorization_details: JSON.stringify(requestedDetails) });
  const rarSource = await provider.BackchannelAuthenticationRequest.find(rarWithoutCompletion);
  assert.deepEqual(JSON.parse(rarSource.params.authorization_details), requestedDetails);
  assert.equal(rarSource.rar, undefined);
  await approve(rarWithoutCompletion, { rarConsent: approvedDetails });
  const noRarResult = await post(metadata.token_endpoint, { grant_type: grantType, auth_req_id: rarWithoutCompletion, resource: resourceA });
  assert.equal(noRarResult.status, 200, JSON.stringify(noRarResult.body));
  assert.equal(noRarResult.body.authorization_details, undefined);
  assert.deepEqual(rarCalls, []);
  console.log('PASS RAR: requested details and Grant.rar do not automatically become completed source permission');

  const rarCompleted = await start({ resource: resourceA, authorization_details: JSON.stringify(requestedDetails) });
  await approve(rarCompleted, { rarConsent: approvedDetails, completedRar: approvedDetails });
  const rarResult = await post(metadata.token_endpoint, {
    grant_type: grantType, auth_req_id: rarCompleted, resource: resourceA, authorization_details: JSON.stringify(requestedDetails),
  });
  assert.equal(rarResult.status, 200, JSON.stringify(rarResult.body));
  assert.deepEqual(rarResult.body.authorization_details, approvedDetails);
  assert.equal(verifiedJwt(rarResult.body.id_token).authorization_details, undefined);
  assert.deepEqual(rarCalls, ['access']);
  const rarIntrospection = await post(metadata.introspection_endpoint, { token: rarResult.body.access_token });
  assert.equal(rarIntrospection.status, 200, JSON.stringify(rarIntrospection.body));
  assert.deepEqual(rarIntrospection.body.authorization_details, approvedDetails);
  console.log('PASS RAR: explicit completion permission and application policy control token/introspection details');
  await expectError(rarCompleted, 'invalid_grant');
  const revokedRarIntrospection = await post(metadata.introspection_endpoint, { token: rarResult.body.access_token });
  assert.equal(revokedRarIntrospection.status, 200);
  assert.equal(revokedRarIntrospection.body.active, false);
  assert.equal(revokedRarIntrospection.body.authorization_details, undefined);
  console.log('PASS RAR: replay revocation removes active introspection and authorization details');

  for (const details of ['{}', '[{"type":"unknown"}]', '[{"type":"support_data","actions":"read"}]']) {
    const invalidDetails = await post(metadata.backchannel_authentication_endpoint,
      { scope: 'openid', login_hint: 'customer', authorization_details: details });
    assert.equal(invalidDetails.status, 400);
    assert.equal(invalidDetails.body.error, 'invalid_authorization_details');
  }
  console.log('PASS RAR: request shape, type registration and action-array checks');
  opaqueResourceTokens = false;

  // Default refresh policy requires BOTH registered grant type and offline_access.
  for (const [client, scope, expected] of [
    ['client', 'openid offline_access', false],
    ['refresh', 'openid', false],
    ['refresh', 'openid offline_access', true],
  ]) {
    const started = await post(metadata.backchannel_authentication_endpoint,
      { login_hint: 'customer', scope, nonce: 'refresh-original' }, client);
    assert.equal(started.status, 200, JSON.stringify(started.body));
    const consent = new provider.Grant({ accountId: 'customer', clientId: client });
    consent.addOIDCScope(scope);
    await consent.save();
    const authTime = Math.floor(Date.now() / 1000) - 20;
    await provider.backchannelResult(started.body.auth_req_id, consent, { authTime, acr: 'customer-login', amr: ['pwd'] });
    const issued = await poll(started.body.auth_req_id, client);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.equal(typeof issued.body.refresh_token === 'string', expected);
    if (!expected) continue;
    const refresh = (extra = {}, asClient = client) => post(metadata.token_endpoint,
      { grant_type: 'refresh_token', refresh_token: issued.body.refresh_token, ...extra }, asClient);
    const expanded = await refresh({ scope: 'openid read' });
    assert.equal(expanded.body.error, 'invalid_scope');
    const narrowed = await refresh({ scope: 'openid' });
    assert.equal(narrowed.status, 200, JSON.stringify(narrowed.body));
    assert.equal(narrowed.body.scope, 'openid');
    assert.equal(narrowed.body.refresh_token, issued.body.refresh_token);
    const idClaims = verifiedJwt(narrowed.body.id_token);
    assert.equal(idClaims.sub, 'customer');
    assert.equal(idClaims.nonce, 'refresh-original');
    const savedRefresh = await provider.RefreshToken.find(issued.body.refresh_token);
    assert.equal(savedRefresh.authTime, authTime);
    assert.equal(savedRefresh.acr, 'customer-login');
    assert.deepEqual(savedRefresh.amr, ['pwd']);
    // Stored authentication context is not automatically an emitted optional claim.
    assert.equal(idClaims.auth_time, undefined);
    assert.equal(idClaims.acr, undefined);
    assert.equal(idClaims.amr, undefined);
    const reused = await refresh();
    assert.equal(reused.status, 200, JSON.stringify(reused.body));
    assert.equal(reused.body.scope, 'openid offline_access');
    // Default fresh confidential-client RT is reusable; narrowing affects this AT only.
    assert.equal(reused.body.refresh_token, issued.body.refresh_token);
    await consent.destroy();
    const revoked = await refresh();
    assert.equal(revoked.status, 400);
    assert.equal(revoked.body.error, 'invalid_grant');
  }
  console.log('PASS refresh: default issuance gates, transient scope narrowing, reusable fresh token, original authentication context, saved consent revocation');

  async function issueRefresh() {
    const started = await post(metadata.backchannel_authentication_endpoint,
      { login_hint: 'customer', scope: 'openid offline_access' }, 'refresh');
    assert.equal(started.status, 200, JSON.stringify(started.body));
    const grant = new provider.Grant({ accountId: 'customer', clientId: 'refresh' });
    grant.addOIDCScope('openid offline_access');
    await grant.save();
    await provider.backchannelResult(started.body.auth_req_id, grant, { authTime: Math.floor(Date.now() / 1000) });
    const issued = await poll(started.body.auth_req_id, 'refresh');
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.equal(typeof issued.body.refresh_token, 'string');
    return { grant, token: issued.body.refresh_token, accessToken: issued.body.access_token, requestId: started.body.auth_req_id };
  }
  const refreshWith = (token, client = 'refresh') => post(metadata.token_endpoint,
    { grant_type: 'refresh_token', refresh_token: token }, client);
  const rotating = await issueRefresh();
  const stolen = await refreshWith(rotating.token, 'refresh-other');
  assert.equal(stolen.status, 400);
  assert.equal(stolen.body.error, 'invalid_grant');
  assert(await provider.Grant.find(rotating.grant.jti));
  assert.equal((await refreshWith(rotating.token)).status, 200);

  // Age the persisted fixture through the public model API. Keep the provider's
  // default policy: rotate when 70% of token TTL has passed, not rotate=true.
  const oldRefresh = await provider.RefreshToken.find(rotating.token);
  const refreshNow = Math.floor(Date.now() / 1000);
  oldRefresh.iat = refreshNow - 800;
  oldRefresh.exp = refreshNow + 200;
  await oldRefresh.save();
  const rotated = await refreshWith(rotating.token);
  assert.equal(rotated.status, 200, JSON.stringify(rotated.body));
  assert.notEqual(rotated.body.refresh_token, rotating.token);
  const consumedRefresh = await provider.RefreshToken.find(rotating.token);
  assert(consumedRefresh.consumed);
  const successor = await provider.RefreshToken.find(rotated.body.refresh_token);
  assert.equal(successor.grantId, rotating.grant.jti);
  assert.equal(successor.rotations, 1);
  assert.equal(successor.scope, 'openid offline_access');
  const foreignReplay = await refreshWith(rotating.token, 'refresh-other');
  assert.equal(foreignReplay.body.error, 'invalid_grant');
  assert(await provider.Grant.find(rotating.grant.jti));
  const replay = await refreshWith(rotating.token);
  assert.equal(replay.status, 400);
  assert.equal(replay.body.error, 'invalid_grant');
  assert.equal(await provider.Grant.find(rotating.grant.jti), undefined);
  assert.equal((await refreshWith(rotated.body.refresh_token)).body.error, 'invalid_grant');
  const revokedAccess = await post(metadata.introspection_endpoint,
    { token: rotated.body.access_token }, 'refresh');
  assert.equal(revokedAccess.body.active, false);

  const expiredRefresh = await issueRefresh();
  const expiredModel = await provider.RefreshToken.find(expiredRefresh.token);
  expiredModel.exp = Math.floor(Date.now() / 1000) - 1;
  await expiredModel.save();
  const expiredResult = await refreshWith(expiredRefresh.token);
  assert.equal(expiredResult.status, 400);
  assert.equal(expiredResult.body.error, 'invalid_grant');
  assert(await provider.Grant.find(expiredRefresh.grant.jti));
  console.log('PASS refresh: default age-based rotation, foreign-client isolation, replay revokes consent and successor/access tokens, expiry rejection');

  const refreshResourceRequest = await post(metadata.backchannel_authentication_endpoint, {
    login_hint: 'customer', scope: 'openid offline_access read write', resource: [resourceA, resourceB],
  }, 'refresh');
  assert.equal(refreshResourceRequest.status, 200, JSON.stringify(refreshResourceRequest.body));
  const refreshResourceGrant = new provider.Grant({ accountId: 'customer', clientId: 'refresh' });
  refreshResourceGrant.addOIDCScope('openid offline_access');
  refreshResourceGrant.addResourceScope(resourceA, 'read');
  refreshResourceGrant.addResourceScope(resourceB, 'write');
  await refreshResourceGrant.save();
  await provider.backchannelResult(refreshResourceRequest.body.auth_req_id, refreshResourceGrant,
    { authTime: Math.floor(Date.now() / 1000) });
  const firstResource = await post(metadata.token_endpoint, {
    grant_type: grantType, auth_req_id: refreshResourceRequest.body.auth_req_id, resource: resourceA,
  }, 'refresh');
  assert.equal(firstResource.status, 200, JSON.stringify(firstResource.body));
  assert.equal(firstResource.body.scope, 'read');
  assert.equal(typeof firstResource.body.refresh_token, 'string');
  const refreshResource = (extra) => post(metadata.token_endpoint, {
    grant_type: 'refresh_token', refresh_token: firstResource.body.refresh_token, ...extra,
  }, 'refresh');
  const secondResource = await refreshResource({ resource: resourceB });
  assert.equal(secondResource.status, 200, JSON.stringify(secondResource.body));
  assert.equal(secondResource.body.scope, 'write');
  assert.equal(verifiedJwt(secondResource.body.access_token).aud, resourceB);
  const oidcRefresh = await refreshResource({});
  assert.equal(oidcRefresh.status, 200, JSON.stringify(oidcRefresh.body));
  assert.equal(oidcRefresh.body.scope, 'openid offline_access');
  const unknownResource = await refreshResource({ resource: 'https://unrequested.example.test/' });
  assert.equal(unknownResource.status, 400);
  assert.equal(unknownResource.body.error, 'invalid_target');
  refreshResourceGrant.rejectResourceScope(resourceB, 'write');
  await refreshResourceGrant.save();
  const reducedConsent = await refreshResource({ resource: resourceB });
  assert.equal(reducedConsent.status, 200, JSON.stringify(reducedConsent.body));
  assert.equal(reducedConsent.body.scope, '');
  console.log('PASS refresh resource: original multi-resource permission survives first AT selection; each refresh filters current consent');

  const richStart = await post(metadata.backchannel_authentication_endpoint, {
    login_hint: 'customer', scope: 'openid offline_access read', resource: resourceA,
    claims: JSON.stringify({ id_token: { email: null } }),
    authorization_details: JSON.stringify(requestedDetails),
  }, 'refresh');
  assert.equal(richStart.status, 200, JSON.stringify(richStart.body));
  const richGrant = new provider.Grant({ accountId: 'customer', clientId: 'refresh' });
  richGrant.addOIDCScope('openid offline_access');
  richGrant.addOIDCClaims(['email']);
  richGrant.addResourceScope(resourceA, 'read');
  await richGrant.save();
  await provider.backchannelResult(richStart.body.auth_req_id, richGrant, { authTime: 123, rar: approvedDetails });
  const richInitial = await post(metadata.token_endpoint,
    { grant_type: grantType, auth_req_id: richStart.body.auth_req_id, resource: resourceA }, 'refresh');
  assert.equal(richInitial.status, 200, JSON.stringify(richInitial.body));
  assert.equal(verifiedJwt(richInitial.body.id_token).email, 'customer@example.test');
  const richSource = await provider.RefreshToken.find(richInitial.body.refresh_token);
  assert.deepEqual(richSource.rar, approvedDetails);
  richSource.iat = Math.floor(Date.now() / 1000) - 800;
  richSource.exp = Math.floor(Date.now() / 1000) + 200;
  await richSource.save();
  richGrant.rejectOIDCClaims(['email']);
  await richGrant.save();
  const richUpdate = await post(metadata.token_endpoint, {
    grant_type: 'refresh_token', refresh_token: richInitial.body.refresh_token, resource: resourceA,
    claims: JSON.stringify({ id_token: { email: null, email_verified: null } }),
    authorization_details: JSON.stringify(requestedDetails),
  }, 'refresh');
  assert.equal(richUpdate.status, 200, JSON.stringify(richUpdate.body));
  assert.deepEqual(richUpdate.body.authorization_details, approvedDetails);
  const richIdentity = verifiedJwt(richUpdate.body.id_token);
  assert.equal(richIdentity.email, undefined);
  assert.equal(richIdentity.email_verified, undefined);
  const richSuccessor = await provider.RefreshToken.find(richUpdate.body.refresh_token);
  assert.notEqual(richUpdate.body.refresh_token, richInitial.body.refresh_token);
  assert.deepEqual(richSuccessor.claims, richSource.claims);
  assert.deepEqual(richSuccessor.rar, approvedDetails);
  assert.equal(richSuccessor.authTime, 123);
  console.log('PASS refresh claims/RAR: rotation retains source, current rejected claims apply, refresh parameters cannot enlarge application-approved details');

  for (const hint of [undefined, 'refresh_token', 'access_token', 'unknown']) {
    const target = await issueRefresh();
    const revokeParams = { token: target.token, ...(hint === undefined ? {} : { token_type_hint: hint }) };
    const foreign = await post(metadata.revocation_endpoint, revokeParams, 'refresh-other');
    assert.equal(foreign.status, 400);
    assert.equal(foreign.body.error, 'invalid_request');
    assert(await provider.Grant.find(target.grant.jti));
    const revoked = await post(metadata.revocation_endpoint, revokeParams, 'refresh');
    assert.equal(revoked.status, 200);
    assert.equal(revoked.body, undefined);
    assert.equal(await provider.Grant.find(target.grant.jti), undefined);
    assert.equal((await refreshWith(target.token)).body.error, 'invalid_grant');
    const repeated = await post(metadata.revocation_endpoint, revokeParams, 'refresh');
    assert.equal(repeated.status, 200);
    assert.equal((await post(metadata.revocation_endpoint, revokeParams, 'refresh-other')).status, 200);
  }
  console.log('PASS refresh revocation: empty success, foreign-client isolation, missing/wrong/unknown hint fallback, grant-wide revocation and idempotence');

  for (const hint of [undefined, 'access_token', 'refresh_token', 'unknown']) {
    const target = await issueRefresh();
    const sibling = await refreshWith(target.token);
    assert.equal(sibling.status, 200);
    const params = { token: target.accessToken, ...(hint === undefined ? {} : { token_type_hint: hint }) };
    const foreign = await post(metadata.revocation_endpoint, params, 'refresh-other');
    assert.equal(foreign.status, 400);
    assert.equal(foreign.body.error, 'invalid_request');
    assert(await provider.Grant.find(target.grant.jti));
    const revoked = await post(metadata.revocation_endpoint, params, 'refresh');
    assert.equal(revoked.status, 200);
    assert.equal(revoked.body, undefined);
    assert(await provider.Grant.find(target.grant.jti));
    assert.equal((await refreshWith(target.token)).body.error, 'invalid_grant');
    const info = await post(metadata.introspection_endpoint, { token: sibling.body.access_token }, 'refresh');
    assert.equal(info.body.active, false);
    assert.equal((await post(metadata.revocation_endpoint, params, 'refresh-other')).status, 200);
    await expectError(target.requestId, 'invalid_grant', 'refresh');
    assert(await provider.Grant.find(target.grant.jti));
    const newRequest = await post(metadata.backchannel_authentication_endpoint,
      { scope: 'openid', login_hint: 'customer' }, 'refresh');
    assert.equal(newRequest.status, 200);
    await provider.backchannelResult(newRequest.body.auth_req_id, target.grant,
      { authTime: Math.floor(Date.now() / 1000) });
    assert.equal((await poll(newRequest.body.auth_req_id, 'refresh')).status, 200);
  }
  const structuredRevocation = await post(metadata.revocation_endpoint,
    { token: firstResource.body.access_token, token_type_hint: 'access_token' }, 'refresh');
  assert.equal(structuredRevocation.status, 400);
  assert.equal(structuredRevocation.body.error, 'unsupported_token_type');
  assert(await provider.Grant.find(refreshResourceGrant.jti));
  console.log('PASS access revocation: opaque AT revokes sibling ATs and refresh while retaining saved Grant; structured JWT rejected without revoking consent');

  const expiring = await start({ requested_expiry: '1' });
  await delay(2100);
  await expectError(expiring, 'expired_token');
  console.log('PASS expiry through HTTP');

  const failing = await start();
  const failingGrant = await approve(failing);
  failClaims = true;
  const failed = await poll(failing);
  failClaims = false;
  assert.equal(failed.status, 500);
  assert.equal(failed.body.error, 'server_error');
  const request = await provider.BackchannelAuthenticationRequest.find(failing);
  assert(request.consumed);
  await expectError(failing, 'invalid_grant');
  assert.equal(await provider.Grant.find(failingGrant.jti), undefined);
  console.log('PASS issuance failure: consumed survives, retry revokes grant');
  console.log('PASS full oidc-provider v9.12.2 HTTP lifecycle; built-in memory adapter, no browser/notification delivery');
} finally {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
}
