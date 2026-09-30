// Real TLS client certificates, not forwarded certificate headers.
import assert from 'node:assert/strict';
import { createServer, request } from 'node:https';
import { createServer as createHttpServer } from 'node:http';
import { X509Certificate, createHash, generateKeyPairSync, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Provider } from 'oidc-provider';
import { createLocalJWKSet, jwtVerify, SignJWT, calculateJwkThumbprint } from 'jose';

const directory = process.env.CIBA_TEST_MTLS_DIRECTORY;
assert(directory, 'generate fixtures with mtls-certificates.rb and set CIBA_TEST_MTLS_DIRECTORY');
const read = (name) => readFileSync(join(directory, name));
const cert = new X509Certificate(read('client.pem'));
const otherCert = new X509Certificate(read('same-key-other-cert.pem'));
assert(cert.publicKey.equals(otherCert.publicKey));
const thumbprint = createHash('sha256').update(cert.raw).digest('base64url');
let provider;
const server = createServer({ key: read('server-key.pem'), cert: read('server.pem'),
  ca: read('client.pem'), requestCert: true, rejectUnauthorized: false },
  (req, res) => provider.callback()(req, res));
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const issuer = `https://127.0.0.1:${server.address().port}`;
const aliasServer = createServer({ key: read('server-key.pem'), cert: read('server.pem'),
  ca: read('client.pem'), requestCert: true, rejectUnauthorized: false },
  (req, res) => provider.callback()(req, res));
await new Promise((resolve) => aliasServer.listen(0, '127.0.0.1', resolve));
const aliasOrigin = `https://127.0.0.1:${aliasServer.address().port}`;
let publishAliases = false;
const aliasKeys = ['backchannel_authentication_endpoint', 'token_endpoint', 'introspection_endpoint', 'userinfo_endpoint'];
const grantType = 'urn:openid:params:grant-type:ciba';
const methods = ['tls_client_auth', 'self_signed_tls_client_auth'];
const certificateJwk = (value) => ({ ...value.publicKey.export({ format: 'jwk' }), x5c: [value.raw.toString('base64')] });
let remoteKeys = [certificateJwk(cert)];
let remoteStatus = 200;
let remoteBody;
let remoteHits = 0;
const jwksServer = createHttpServer((_req, res) => {
  remoteHits++;
  res.writeHead(remoteStatus, { 'content-type': 'application/json', 'cache-control': 'max-age=3600' });
  res.end(remoteBody ?? JSON.stringify({ keys: remoteKeys }));
});
await new Promise((resolve) => jwksServer.listen(0, '127.0.0.1', resolve));
const remoteUri = `http://127.0.0.1:${jwksServer.address().port}/jwks`;
try {
  provider = new Provider(issuer, {
    clientAuthMethods: methods,
    subjectTypes: ['public', 'pairwise'],
    pairwiseIdentifier: async (_ctx, accountId, client) => createHash('sha256')
      .update(JSON.stringify([client.sectorIdentifier, accountId])).digest('hex'),
    fetch: (url, options) => fetch(url, url === remoteUri ? { ...options, dispatcher: undefined } : options),
    clients: methods.map((method) => ({ client_id: method, grant_types: [grantType, 'refresh_token'],
      response_types: [], backchannel_token_delivery_mode: 'poll', token_endpoint_auth_method: method,
      tls_client_certificate_bound_access_tokens: true,
      ...(method === 'tls_client_auth' ? { tls_client_auth_subject_dn: 'CN=client' } : {
        jwks: { keys: [{ ...cert.publicKey.export({ format: 'jwk' }), x5c: [cert.raw.toString('base64')] }] } }),
    })),
    features: { devInteractions: { enabled: false }, introspection: { enabled: true },
      registration: { enabled: true, initialAccessToken: 'local-mtls-registration' },
      registrationManagement: { enabled: true },
      dPoP: { enabled: true, requireNonce: () => false },
      mTLS: { enabled: true, tlsClientAuth: true, selfSignedTlsClientAuth: true, certificateBoundAccessTokens: true,
        getCertificate: (ctx) => {
          const raw = ctx.req.socket.getPeerCertificate().raw;
          return raw ? new X509Certificate(raw).toString() : undefined;
        },
        certificateAuthorized: (ctx) => ctx.req.socket.authorized,
        certificateSubjectMatches: (ctx, property, expected) => property === 'tls_client_auth_subject_dn' &&
          new X509Certificate(ctx.req.socket.getPeerCertificate().raw).subject === expected,
      },
      ciba: { enabled: true, deliveryModes: ['poll'], processLoginHint: async (_ctx, hint) => hint === 'customer' ? hint : undefined,
        validateRequestContext: async () => {}, validateBindingMessage: async () => {},
        verifyUserCode: async () => {}, triggerAuthenticationDevice: async () => {} } },
    findAccount: async (_ctx, accountId) => ({ accountId, claims: async () => ({ sub: accountId }) }),
  });
  // Aliases are application metadata and transport, not an automatic provider route.
  provider.use(async (ctx, next) => {
    await next();
    if (publishAliases && ctx.oidc.route === 'discovery') {
      ctx.body.mtls_endpoint_aliases = Object.fromEntries(aliasKeys.map((key) =>
        [key, `${aliasOrigin}${new URL(ctx.body[key]).pathname}`]));
    }
  });
  const send = (url, params, certificate = 'client.pem', headers = {}, method = params ? 'POST' : 'GET') => new Promise((resolve, reject) => {
    const body = params ? (headers['content-type'] === 'application/json' ? JSON.stringify(params) : new URLSearchParams(params).toString()) : undefined;
    const outgoing = request(url, { method, ca: read('server.pem'), agent: false,
      ...(certificate ? { key: read('client-key.pem'), cert: read(certificate) } : {}),
      headers: { ...(body ? { 'content-type': 'application/x-www-form-urlencoded', 'content-length': Buffer.byteLength(body) } : {}), ...headers } }, (response) => {
      let data = '';
      response.setEncoding('utf8').on('data', (chunk) => { data += chunk; });
      response.on('end', () => resolve({ status: response.statusCode, body: data ? JSON.parse(data) : undefined }));
    });
    outgoing.on('error', reject);
    outgoing.end(body);
  });
  const baseline = (await send(`${issuer}/.well-known/openid-configuration`, null, null)).body;
  assert.equal(baseline.mtls_endpoint_aliases, undefined);
  publishAliases = true;
  const discovered = (await send(`${issuer}/.well-known/openid-configuration`, null, null)).body;
  assert.equal(discovered.issuer, issuer);
  for (const key of aliasKeys) {
    assert.equal(new URL(discovered[key]).origin, issuer);
    assert.equal(new URL(discovered.mtls_endpoint_aliases[key]).origin, aliasOrigin);
  }
  const metadata = { ...discovered, ...discovered.mtls_endpoint_aliases };
  const signingKeys = createLocalJWKSet((await send(metadata.jwks_uri, null, null)).body);
  assert.equal(metadata.tls_client_certificate_bound_access_tokens, true);
  const registrationHeaders = { authorization: 'Bearer local-mtls-registration', 'content-type': 'application/json' };
  const registrationBase = { grant_types: [grantType, 'refresh_token'], response_types: [],
    backchannel_token_delivery_mode: 'poll', token_endpoint_auth_method: 'tls_client_auth', tls_client_auth_subject_dn: 'CN=client' };
  const register = (params) => send(metadata.registration_endpoint, params, null, registrationHeaders);
  for (const value of ['true', 'false', 1, 0, [], {}]) {
    const result = await register({ ...registrationBase, tls_client_certificate_bound_access_tokens: value });
    assert.equal(result.status, 400);
    assert.equal(result.body.error, 'invalid_client_metadata');
  }
  for (const params of [
    { ...registrationBase, tls_client_auth_subject_dn: undefined },
    { ...registrationBase, tls_client_auth_subject_dn: 1 },
    { ...registrationBase, tls_client_auth_san_dns: 'client.example' },
    { ...registrationBase, token_endpoint_auth_method: 'self_signed_tls_client_auth' },
  ]) assert.equal((await register(params)).status, 400);
  const omitted = await register(registrationBase);
  assert.equal(omitted.status, 201);
  assert.equal(omitted.body.tls_client_certificate_bound_access_tokens, false);
  const conflicting = await register({ ...registrationBase,
    tls_client_certificate_bound_access_tokens: true, dpop_bound_access_tokens: true });
  assert.equal(conflicting.status, 400);
  assert.equal(conflicting.body.error, 'invalid_client_metadata');
  for (const method of methods) {
    assert(metadata.token_endpoint_auth_methods_supported.includes(method));
    const registeredParams = { ...registrationBase, token_endpoint_auth_method: method, tls_client_certificate_bound_access_tokens: true,
      ...(method === 'self_signed_tls_client_auth' ? { jwks: { keys: [{ ...cert.publicKey.export({ format: 'jwk' }), x5c: [cert.raw.toString('base64')] }] } } : {}) };
    const registration = await register(registeredParams);
    assert.equal(registration.status, 201, JSON.stringify(registration.body));
    const registered = registration.body;
    const clientId = registered.client_id;
    if (method === 'self_signed_tls_client_auth') assert.equal(registered.tls_client_auth_subject_dn, undefined);
    const startParams = { client_id: clientId, scope: 'openid offline_access', login_hint: 'customer' };
    assert.equal((await send(metadata.backchannel_authentication_endpoint, startParams, null)).body.error, 'invalid_client');
    // A presented HTTP header is never used as a substitute for the TLS peer.
    assert.equal((await send(metadata.backchannel_authentication_endpoint, startParams, null,
      { 'x-ssl-client-cert': encodeURIComponent(cert.toString()), 'x-ssl-client-verify': 'SUCCESS' })).body.error, 'invalid_client');
    if (method === 'self_signed_tls_client_auth') {
      assert.equal((await send(metadata.backchannel_authentication_endpoint, startParams, 'same-key-other-cert.pem')).body.error, 'invalid_client');
    }
    const started = await send(metadata.backchannel_authentication_endpoint, startParams);
    assert.equal(started.status, 200, JSON.stringify(started.body));
    const consent = new provider.Grant({ accountId: 'customer', clientId });
    consent.addOIDCScope('openid offline_access');
    await consent.save();
    await provider.backchannelResult(started.body.auth_req_id, consent);
    const issued = await send(metadata.token_endpoint, { client_id: clientId, grant_type: grantType, auth_req_id: started.body.auth_req_id });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    const identity = await jwtVerify(issued.body.id_token, signingKeys, {issuer, audience:clientId});
    assert.equal(Object.hasOwn(identity.payload, "cnf"), false);
    const inspected = await send(metadata.introspection_endpoint, { client_id: clientId, token: issued.body.access_token });
    assert.equal(inspected.body.active, true);
    assert.deepEqual(inspected.body.cnf, { 'x5t#S256': thumbprint });
    const authorization = { authorization: `Bearer ${issued.body.access_token}` };
    assert.equal((await send(metadata.userinfo_endpoint, null, null, authorization)).status, 401);
    assert.equal((await send(metadata.userinfo_endpoint, null, 'same-key-other-cert.pem', authorization)).status, 401);
    const info = await send(metadata.userinfo_endpoint, null, 'client.pem', authorization);
    assert.equal(info.status, 200);
    assert.equal(info.body.sub, 'customer');
    const refreshed = await send(metadata.token_endpoint, { client_id: clientId, grant_type: 'refresh_token', refresh_token: issued.body.refresh_token });
    assert.equal(refreshed.status, 200, JSON.stringify(refreshed.body));
    const renewedIdentity = await jwtVerify(refreshed.body.id_token, signingKeys, {issuer, audience:clientId});
    assert.equal(Object.hasOwn(renewedIdentity.payload, "cnf"), false);
    const managementHeaders = { authorization: `Bearer ${registered.registration_access_token}`, 'content-type': 'application/json' };
    const replacement = { ...registeredParams, client_id: clientId };
    assert.equal((await send(registered.registration_client_uri, { ...replacement, tls_client_certificate_bound_access_tokens: 'false' }, null, managementHeaders, 'PUT')).status, 400);
    assert.equal((await send(registered.registration_client_uri, null, null, managementHeaders)).body.tls_client_certificate_bound_access_tokens, true);
    delete replacement.tls_client_certificate_bound_access_tokens;
    const replaced = await send(registered.registration_client_uri, replacement, null, managementHeaders, 'PUT');
    assert.equal(replaced.status, 200, JSON.stringify(replaced.body));
    assert.equal(replaced.body.tls_client_certificate_bound_access_tokens, false);
    const unbound = await send(metadata.token_endpoint, { client_id: clientId, grant_type: 'refresh_token', refresh_token: refreshed.body.refresh_token });
    assert.equal(unbound.status, 200, JSON.stringify(unbound.body));
    const unboundInfo = await send(metadata.userinfo_endpoint, null, null, { authorization: `Bearer ${unbound.body.access_token}` });
    assert.equal(unboundInfo.status, 200);
    assert.equal((await send(metadata.userinfo_endpoint, null, null, authorization)).status, 401);
    console.log(`PASS ${method}: real TLS CIBA/refresh, exact certificate cnf, UserInfo certificate binding; absent/header-only certificate rejected`);
  }
  for (const method of methods) {
    const registration = await register({ ...registrationBase, token_endpoint_auth_method: method,
      tls_client_certificate_bound_access_tokens:false, dpop_bound_access_tokens:true,
      ...(method === 'self_signed_tls_client_auth' ? {jwks:{keys:[certificateJwk(cert)]}} : {}) });
    assert.equal(registration.status,201,JSON.stringify(registration.body));
    const clientId=registration.body.client_id;
    const key=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
    const proof=async (htu,htm='POST',token)=>new SignJWT({htu,htm,iat:Math.floor(Date.now()/1000),jti:randomUUID(),
      ...(token ? {ath:createHash('sha256').update(token).digest('base64url')} : {})})
      .setProtectedHeader({alg:'ES256',typ:'dpop+jwt',jwk:key.publicKey.export({format:'jwk'})}).sign(key.privateKey);
    const started=await send(metadata.backchannel_authentication_endpoint,{client_id:clientId,scope:'openid offline_access',login_hint:'customer'});
    assert.equal(started.status,200,JSON.stringify(started.body));
    const consent=new provider.Grant({accountId:'customer',clientId});consent.addOIDCScope('openid offline_access');await consent.save();
    await provider.backchannelResult(started.body.auth_req_id,consent);
    const params={client_id:clientId,grant_type:grantType,auth_req_id:started.body.auth_req_id};
    assert.equal((await send(metadata.token_endpoint,params,null,{dpop:await proof(metadata.token_endpoint)})).status,401);
    assert.equal((await send(metadata.token_endpoint,params)).status,400);
    assert.equal((await send(metadata.token_endpoint,params,'client.pem',{dpop:await proof(discovered.token_endpoint)})).status,400);
    const issued=await send(metadata.token_endpoint,params,'client.pem',{dpop:await proof(metadata.token_endpoint)});
    assert.equal(issued.status,200,JSON.stringify(issued.body));
    const identity=await jwtVerify(issued.body.id_token,signingKeys,{issuer,audience:clientId});
    assert.equal(Object.hasOwn(identity.payload,'cnf'),false);
    const introspected=await send(metadata.introspection_endpoint,{client_id:clientId,token:issued.body.access_token});
    assert.equal(introspected.body.active,true);
    const expectedBinding={jkt:await calculateJwkThumbprint(key.publicKey.export({format:'jwk'}))};
    assert.deepEqual(introspected.body.cnf,expectedBinding);
    assert.equal((await send(metadata.userinfo_endpoint,null,'client.pem',{authorization:`Bearer ${issued.body.access_token}`})).status,401);
    const info=await send(metadata.userinfo_endpoint,null,null,{authorization:`DPoP ${issued.body.access_token}`,
      dpop:await proof(metadata.userinfo_endpoint,'GET',issued.body.access_token)});
    assert.equal(info.status,200,JSON.stringify(info.body));assert.equal(info.body.sub,identity.payload.sub);
    const refresh={client_id:clientId,grant_type:'refresh_token',refresh_token:issued.body.refresh_token};
    assert.equal((await send(metadata.token_endpoint,refresh,null,{dpop:await proof(metadata.token_endpoint)})).status,401);
    assert.equal((await send(metadata.token_endpoint,refresh)).status,400);
    const renewed=await send(metadata.token_endpoint,refresh,'client.pem',{dpop:await proof(metadata.token_endpoint)});
    assert.equal(renewed.status,200,JSON.stringify(renewed.body));assert.equal(renewed.body.token_type,'DPoP');
    const renewedBinding=await send(metadata.introspection_endpoint,{client_id:clientId,token:renewed.body.access_token});
    assert.deepEqual(renewedBinding.body.cnf,expectedBinding);
    console.log(`PASS ${method}: real TLS alias authentication plus DPoP issuance/UserInfo/refresh; no certificate token binding`);
  }
  const remoteRegistration = await register({ ...registrationBase, token_endpoint_auth_method: 'self_signed_tls_client_auth', jwks_uri: remoteUri, subject_type: 'pairwise' });
  assert.equal(remoteRegistration.status, 201, JSON.stringify(remoteRegistration.body));
  const remoteId = remoteRegistration.body.client_id;
  const remoteStart = (certificate) => send(metadata.backchannel_authentication_endpoint,
    { client_id: remoteId, scope: 'openid', login_hint: 'customer' }, certificate);
  const pairwiseStart = await remoteStart('client.pem');
  assert.equal(pairwiseStart.status, 200);
  const pairwiseConsent = new provider.Grant({ accountId: 'customer', clientId: remoteId });
  pairwiseConsent.addOIDCScope('openid');
  await pairwiseConsent.save();
  await provider.backchannelResult(pairwiseStart.body.auth_req_id, pairwiseConsent);
  const pairwiseTokens = await send(metadata.token_endpoint, { client_id: remoteId, grant_type: grantType, auth_req_id: pairwiseStart.body.auth_req_id });
  assert.equal(pairwiseTokens.status, 200, JSON.stringify(pairwiseTokens.body));
  const pairwiseClaims = JSON.parse(Buffer.from(pairwiseTokens.body.id_token.split('.')[1], 'base64url'));
  const expectedSubject = createHash('sha256').update(JSON.stringify([new URL(remoteUri).host, 'customer'])).digest('hex');
  assert.equal(pairwiseClaims.sub, expectedSubject);
  const pairwiseInfo = await send(metadata.userinfo_endpoint, null, 'client.pem', { authorization: `Bearer ${pairwiseTokens.body.access_token}` });
  assert.equal(pairwiseInfo.body.sub, expectedSubject);
  console.log('PASS pairwise self-signed mTLS: remote x5c ownership, CIBA issuance and matching UserInfo subject');
  assert.equal(remoteHits, 1);
  remoteKeys = [certificateJwk(otherCert)];
  assert.equal((await remoteStart('same-key-other-cert.pem')).body.error, 'invalid_client');
  assert.equal((await remoteStart('client.pem')).status, 200);
  assert.equal(remoteHits, 1);
  // Force expiry of the actual provider cache; do not replace its fetch/verification.
  const remoteClient = await provider.Client.find(remoteId);
  remoteClient.asymmetricKeyStore.freshUntil = 0;
  assert.equal((await remoteStart('same-key-other-cert.pem')).status, 200);
  assert.equal((await remoteStart('client.pem')).body.error, 'invalid_client');
  assert.equal(remoteHits, 2);
  remoteClient.asymmetricKeyStore.freshUntil = 0;
  remoteStatus = 503;
  const remoteFailure = await remoteStart('same-key-other-cert.pem');
  console.log(`REMOTE_FAILURE ${remoteFailure.status} ${JSON.stringify(remoteFailure.body)}`);
  assert.equal(remoteFailure.status, 400);
  assert.equal(remoteFailure.body.error, 'invalid_client_metadata');
  // Reference sets freshness before status validation, retaining previous keys.
  assert.equal((await remoteStart('same-key-other-cert.pem')).status, 200);
  console.log('OBSERVED reference retains previous certificate in fresh cache after a failed refresh');
  remoteStatus = 200;
  for (const [body, status, error] of [
    ['not json', 400, 'invalid_client_metadata'],
    ['{"keys":[]}', 401, 'invalid_client'],
    ['{"keys":{}}', 400, 'invalid_client_metadata'],
  ]) {
    remoteClient.asymmetricKeyStore.freshUntil = 0;
    remoteBody = body;
    const result = await remoteStart('same-key-other-cert.pem');
    assert.equal(result.status, status, JSON.stringify(result.body));
    assert.equal(result.body.error, error);
  }
  console.log('PASS remote x5c rotation: fresh cache retained, expiry replaces exact certificate, same key is insufficient, HTTP failure rejects authentication');
  console.log('PASS application mTLS aliases: absent by default, separate real TLS listener, canonical issuer unchanged, complete flow uses discovered aliases');
  console.log('PASS mTLS DCR: strict boolean, one PKI subject, required self-signed keys, defaults and management replacement');
  console.log('PASS mTLS capability true does not force per-client binding; false policy issues unbound tokens while old tokens stay bound');
} finally {
  jwksServer.closeAllConnections?.();
  await new Promise((resolve) => jwksServer.close(resolve));
  aliasServer.closeAllConnections?.();
  await new Promise((resolve) => aliasServer.close(resolve));
  server.closeAllConnections?.();
  await new Promise((resolve) => server.close(resolve));
}
