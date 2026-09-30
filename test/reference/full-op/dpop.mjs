// CIBA sender constraints measured against the complete published OP.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHash, generateKeyPairSync, randomUUID, randomBytes } from 'node:crypto';
import { SignJWT, exportJWK, calculateJwkThumbprint } from 'jose';
import { Provider } from 'oidc-provider';

const grantType = 'urn:openid:params:grant-type:ciba';
const { privateKey: signingKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const proofKeys = Array.from({ length: 2 }, () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' }));
const jwks = await Promise.all(proofKeys.map(({ publicKey }) => exportJWK(publicKey)));
const thumbprints = await Promise.all(jwks.map((key) => calculateJwkThumbprint(key)));
let provider;
const server = createServer((req, res) => provider.callback()(req, res));
await new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', resolve);
});
const issuer = `http://127.0.0.1:${server.address().port}`;
try {
  const configuration = {
    jwks: { keys: [{ ...signingKey.export({ format: 'jwk' }), kid: 'op', use: 'sig', alg: 'RS256' }] },
    scopes: ['openid', 'offline_access'],
    features: {
      devInteractions: { enabled: false },
      registration: { enabled: true, initialAccessToken: 'local-dpop-registration' },
      registrationManagement: { enabled: true },
      introspection: { enabled: true },
      revocation: { enabled: true },
      dPoP: { enabled: true, requireNonce: () => false },
      ciba: { enabled: true, deliveryModes: ['poll'],
        processLoginHint: async (_ctx, hint) => hint === 'customer' ? hint : undefined,
        validateRequestContext: async () => {}, validateBindingMessage: async () => {}, verifyUserCode: async () => {},
        triggerAuthenticationDevice: async () => {} },
    },
    findAccount: async (_ctx, accountId) => ({ accountId, claims: async () => ({ sub: accountId }) }),
  };
  provider = new Provider(issuer, configuration);
  const metadata = await (await fetch(`${issuer}/.well-known/openid-configuration`)).json();
  assert(metadata.dpop_signing_alg_values_supported.includes('ES256'));
  assert.equal(typeof metadata.introspection_endpoint, 'string');
  // This version advertises the endpoint, but no introspection auth-method list.
  assert.equal(metadata.introspection_endpoint_auth_methods_supported, undefined);
  const base = { grant_types: [grantType, 'refresh_token'], response_types: [],
    token_endpoint_auth_method: 'client_secret_basic', backchannel_token_delivery_mode: 'poll' };
  async function register(extra) {
    const response = await fetch(metadata.registration_endpoint, { method: 'POST', headers: {
      authorization: 'Bearer local-dpop-registration', 'content-type': 'application/json',
    }, body: JSON.stringify({ ...base, ...extra }) });
    return { status: response.status, body: await response.json(), headers: response.headers };
  }
  for (const value of ['true', 'false', 0, 1, [], {}]) {
    const result = await register({ dpop_bound_access_tokens: value });
    assert.equal(result.status, 400, JSON.stringify(result.body));
    assert.equal(result.body.error, 'invalid_client_metadata');
  }
  for (const extra of [{}, { dpop_bound_access_tokens: false }]) {
    const result = await register(extra);
    assert.equal(result.status, 201);
    assert.equal(result.body.dpop_bound_access_tokens, false);
  }
  const registered = await register({ dpop_bound_access_tokens: true });
  assert.equal(registered.status, 201, JSON.stringify(registered.body));
  const client = registered.body;
  const clientId = client.client_id;
  assert.equal(client.dpop_bound_access_tokens, true);
  console.log('PASS DCR DPoP: strict booleans, omitted/false default, true stored for issued client');
  async function proof(url, method = 'POST', index = 0, changes = {}) {
    return new SignJWT({ htm: method, htu: url, iat: Math.floor(Date.now() / 1000), jti: randomUUID(), ...changes })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: jwks[index] }).sign(proofKeys[index].privateKey);
  }
  async function post(url, params, dpop) {
    const response = await fetch(url, { method: 'POST', headers: {
      authorization: `Basic ${Buffer.from(`${clientId}:${client.client_secret}`).toString('base64')}`,
      'content-type': 'application/x-www-form-urlencoded', ...(dpop ? { dpop } : {}),
    }, body: new URLSearchParams(params) });
    const text = await response.text();
    return { status: response.status, body: text ? JSON.parse(text) : undefined, headers: response.headers };
  }
  const started = await post(metadata.backchannel_authentication_endpoint,
    { scope: 'openid offline_access', login_hint: 'customer' });
  assert.equal(started.status, 200, JSON.stringify(started.body));
  const id = started.body.auth_req_id;
  const poll = (dpop) => post(metadata.token_endpoint, { grant_type: grantType, auth_req_id: id }, dpop);
  assert.equal((await poll()).body.error, 'invalid_grant');
  const pending = await poll(await proof(metadata.token_endpoint));
  assert.equal(pending.body.error, 'authorization_pending');
  const consent = new provider.Grant({ accountId: 'customer', clientId });
  consent.addOIDCScope('openid offline_access');
  await consent.save();
  await provider.backchannelResult(id, consent);
  for (const changes of [{ htm: 'GET' }, { htu: `${issuer}/wrong` }, { iat: 1 }, { jti: '' }]) {
    const rejected = await poll(await proof(metadata.token_endpoint, 'POST', 0, changes));
    assert.equal(rejected.status, 400, JSON.stringify(rejected.body));
    assert.equal(rejected.body.error, 'invalid_dpop_proof');
    assert.equal((await provider.BackchannelAuthenticationRequest.find(id)).consumed, undefined);
  }
  const issued = await poll(await proof(metadata.token_endpoint));
  assert.equal(issued.status, 200, JSON.stringify(issued.body));
  assert.equal(issued.body.token_type, 'DPoP');
  const access = await provider.AccessToken.find(issued.body.access_token);
  assert.equal(access.jkt, thumbprints[0]);
  const introspected = await post(metadata.introspection_endpoint, { token: issued.body.access_token });
  assert.equal(introspected.status, 200);
  assert.equal(introspected.body.active, true);
  assert.equal(introspected.body.token_type, 'DPoP');
  assert.deepEqual(introspected.body.cnf, { jkt: thumbprints[0] });
  assert.equal((await post(metadata.introspection_endpoint, { token: 'not-issued' })).body.active, false);
  console.log('PASS CIBA DPoP: start without proof; poll requires proof; random jti accepted; invalid method/URI/time/jti do not consume approval; AT bound to proof key');

  async function userinfo(scheme, index, changes = {}) {
    const ath = createHash('sha256').update(issued.body.access_token).digest('base64url');
    return fetch(metadata.userinfo_endpoint, { headers: {
      authorization: `${scheme} ${issued.body.access_token}`,
      ...(index === undefined ? {} : { dpop: await proof(metadata.userinfo_endpoint, 'GET', index, { ath, ...changes }) }),
    } });
  }
  assert.equal((await userinfo('Bearer')).status, 401);
  assert.equal((await userinfo('DPoP', 1)).status, 401);
  assert.equal((await userinfo('DPoP', 0, { ath: 'wrong' })).status, 401);
  const info = await userinfo('DPoP', 0);
  assert.equal(info.status, 200);
  assert.equal((await info.json()).sub, 'customer');
  const repeatedJti = randomUUID();
  assert.equal((await userinfo('DPoP', 0, { jti: repeatedJti })).status, 200);
  assert.equal((await userinfo('DPoP', 0, { jti: repeatedJti })).status, 401);
  console.log('PASS UserInfo: bearer presentation, wrong proof key and wrong ath rejected; matching proof accepted');
  console.log('PASS UserInfo rejects reuse of the same proof jti');
  const postAth = createHash('sha256').update(issued.body.access_token).digest('base64url');
  const postInfo = (signed) => fetch(metadata.userinfo_endpoint, { method: 'POST', headers: {
    authorization: `DPoP ${issued.body.access_token}`, dpop: signed,
    'content-type': 'application/x-www-form-urlencoded',
  }, body: '' });
  assert.equal((await postInfo(await proof(metadata.userinfo_endpoint, 'GET', 0, { ath: postAth }))).status, 401);
  const postProof = await proof(metadata.userinfo_endpoint, 'POST', 0, { ath: postAth });
  const posted = await postInfo(postProof);
  assert.equal(posted.status, 200);
  assert.equal((await posted.json()).sub, 'customer');
  assert.equal((await postInfo(postProof)).status, 401);
  console.log('PASS POST UserInfo: method binding, matching proof and replay rejection');

  const refresh = await provider.RefreshToken.find(issued.body.refresh_token);
  assert.equal(refresh.jkt, undefined); // Confidential-client authentication binds RT use.
  const params = { grant_type: 'refresh_token', refresh_token: issued.body.refresh_token };
  assert.equal((await post(metadata.token_endpoint, params)).body.error, 'invalid_grant');
  const newProof = await proof(metadata.token_endpoint, 'POST', 1);
  const renewed = await post(metadata.token_endpoint, params, newProof);
  assert.equal(renewed.status, 200, JSON.stringify(renewed.body));
  assert.equal(renewed.body.token_type, 'DPoP');
  assert.equal((await provider.AccessToken.find(renewed.body.access_token)).jkt, thumbprints[1]);
  const replay = await post(metadata.token_endpoint, params, newProof);
  assert.equal(replay.status, 400);
  assert.equal(replay.body.error, 'invalid_grant');
  console.log('PASS confidential refresh: RT has no jkt, current proof is required, new key accepted for new AT, repeated proof rejected');
  const refreshedInfo = await post(metadata.introspection_endpoint, { token: renewed.body.access_token });
  assert.equal(refreshedInfo.body.active, true);
  assert.deepEqual(refreshedInfo.body.cnf, { jkt: thumbprints[1] });
  assert.equal((await post(metadata.revocation_endpoint, { token: issued.body.access_token })).status, 200);
  const revokedInfo = await post(metadata.introspection_endpoint, { token: issued.body.access_token });
  assert.deepEqual(revokedInfo.body, { active: false });
  console.log('PASS introspection: active DPoP cnf reflects issuance/refresh key; unknown and revoked tokens inactive');
  const headers = { authorization: `Bearer ${client.registration_access_token}`, 'content-type': 'application/json' };
  const invalid = await fetch(client.registration_client_uri, { method: 'PUT', headers,
    body: JSON.stringify({ ...base, client_id: clientId, dpop_bound_access_tokens: 'false' }) });
  assert.equal(invalid.status, 400);
  const retained = await fetch(client.registration_client_uri, { headers });
  assert.equal(retained.status, 200);
  assert.equal((await retained.json()).dpop_bound_access_tokens, true);
  const cleared = await fetch(client.registration_client_uri, { method: 'PUT', headers,
    body: JSON.stringify({ ...base, client_id: clientId }) });
  assert.equal(cleared.status, 200);
  assert.equal((await cleared.json()).dpop_bound_access_tokens, false);
  console.log('PASS DCR management: invalid boolean preserves credential/policy; omission resets DPoP requirement to false');
  provider = new Provider(issuer, { ...configuration,
    clients: [{ ...base, client_id: clientId, client_secret: client.client_secret, dpop_bound_access_tokens: true }],
    features: { ...configuration.features,
      dPoP: { enabled: true, nonceSecret: randomBytes(32), requireNonce: () => true } } });
  async function approvedNonceRequest() {
    const request = await post(metadata.backchannel_authentication_endpoint, { scope: 'openid', login_hint: 'customer' });
    assert.equal(request.status, 200);
    const consent = new provider.Grant({ accountId: 'customer', clientId });
    consent.addOIDCScope('openid');
    await consent.save();
    await provider.backchannelResult(request.body.auth_req_id, consent);
    return { grant_type: grantType, auth_req_id: request.body.auth_req_id };
  }
  const nonceParams = await approvedNonceRequest();
  const challenge = await post(metadata.token_endpoint, nonceParams, await proof(metadata.token_endpoint));
  assert.equal(challenge.status, 400);
  assert.equal(challenge.body.error, 'use_dpop_nonce');
  const nonce = challenge.headers.get('dpop-nonce');
  assert.equal(typeof nonce, 'string');
  assert(nonce.length > 0);
  assert.equal((await provider.BackchannelAuthenticationRequest.find(nonceParams.auth_req_id)).consumed, undefined);
  for (const [value, expected] of [[true, 'invalid_dpop_proof'], ['bad', 'use_dpop_nonce']]) {
    const result = await post(metadata.token_endpoint, nonceParams, await proof(metadata.token_endpoint, 'POST', 0, { nonce: value }));
    assert.equal(result.status, 400);
    assert.equal(result.body.error, expected);
  }
  const ancientProof = await proof(metadata.token_endpoint, 'POST', 0, { nonce, iat: 1 });
  const zeroIat = await post(metadata.token_endpoint, nonceParams,
    await proof(metadata.token_endpoint, 'POST', 0, { nonce, iat: 0 }));
  assert.equal(zeroIat.status, 400);
  assert.equal(zeroIat.body.error, 'invalid_dpop_proof');
  const withNonce = await post(metadata.token_endpoint, nonceParams, ancientProof);
  assert.equal(withNonce.status, 200, JSON.stringify(withNonce.body));
  const nonceToken = withNonce.body.access_token;
  const ath = createHash('sha256').update(nonceToken).digest('base64url');
  const noUiNonce = await fetch(metadata.userinfo_endpoint, { headers: { authorization: `DPoP ${nonceToken}`,
    dpop: await proof(metadata.userinfo_endpoint, 'GET', 0, { ath }) } });
  assert.equal(noUiNonce.status, 401);
  assert.equal((await noUiNonce.json()).error, 'use_dpop_nonce');
  assert(noUiNonce.headers.get('dpop-nonce'));
  const infoNonce = await fetch(metadata.userinfo_endpoint, { headers: { authorization: `DPoP ${nonceToken}`,
    dpop: await proof(metadata.userinfo_endpoint, 'GET', 0, { ath, nonce, iat: 1 }) } });
  assert.equal(infoNonce.status, 200); // Same server nonce works across endpoints.
  assert.equal((await infoNonce.json()).sub, 'customer');
  const replayNonce = await post(metadata.token_endpoint, await approvedNonceRequest(), ancientProof);
  assert.equal(replayNonce.status, 400);
  assert.equal(replayNonce.body.error, 'invalid_grant');
  console.log('PASS nonce: token400/UserInfo401 challenges; valid nonce waives old iat, spans endpoints, but never permits proof replay');
  provider = new Provider(issuer, { ...configuration,
    clients: [{ ...base, client_id: clientId, client_secret: client.client_secret, dpop_bound_access_tokens: true }],
    features: { ...configuration.features,
      dPoP: { enabled: true, nonceSecret: randomBytes(32), requireNonce: () => false } } });
  const optionalNonceParams = await approvedNonceRequest();
  const oldOptional = await post(metadata.token_endpoint, optionalNonceParams,
    await proof(metadata.token_endpoint, 'POST', 0, { iat: 1 }));
  assert.equal(oldOptional.status, 400);
  assert.equal(oldOptional.body.error, 'use_dpop_nonce');
  assert(oldOptional.headers.get('dpop-nonce'));
  const freshOptional = await post(metadata.token_endpoint, optionalNonceParams, await proof(metadata.token_endpoint));
  assert.equal(freshOptional.status, 200, JSON.stringify(freshOptional.body));
  assert(freshOptional.headers.get('dpop-nonce'));
  console.log('PASS optional nonce: old proof gets challenge; fresh proof without nonce succeeds and returns nonce');
  provider = new Provider(issuer, { ...configuration,
    features: { ...configuration.features, dPoP: { enabled: false } } });
  for (const value of [true, 'true']) {
    const ignored = await register({ dpop_bound_access_tokens: value });
    assert.equal(ignored.status, 201, JSON.stringify(ignored.body));
    assert.equal(ignored.body.dpop_bound_access_tokens, undefined);
  }
  console.log('PASS disabled DPoP: registration ignores unsupported dpop_bound_access_tokens metadata');
  provider = new Provider(issuer, { ...configuration, features: { ...configuration.features,
    dPoP: { enabled: false }, introspection: { enabled: false } } });
  const disabledMetadata = await (await fetch(`${issuer}/.well-known/openid-configuration`)).json();
  for (const key of ['introspection_endpoint', 'introspection_endpoint_auth_methods_supported',
    'introspection_endpoint_auth_signing_alg_values_supported', 'dpop_signing_alg_values_supported']) {
    assert.equal(disabledMetadata[key], undefined);
  }
  console.log('PASS Discovery: enabled introspection/DPoP metadata present, disabled extensions omitted');
} finally {
  server.closeAllConnections?.();
  await new Promise((resolve) => server.close(resolve));
}
