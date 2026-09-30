// Real HTTP, published provider. Only these owned JWKS URLs bypass its IP guard.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync, sign, createHmac, verify } from 'node:crypto';
import { Provider } from 'oidc-provider';

const key = () => generateKeyPairSync('rsa', { modulusLength: 2048 });
const opKey = key();
const oldKey = key();
const newKey = key();
const hits = { '/old': 0, '/new': 0 };
let currentKey = oldKey;
let provider;
let allowReceiver = false;
const server = createServer((req, res) => {
  if (Object.hasOwn(hits, req.url)) {
    hits[req.url]++;
    res.setHeader('content-type', 'application/json');
    res.setHeader('cache-control', 'max-age=3600');
    const selected = req.url === '/old' ? currentKey : newKey;
    res.end(JSON.stringify({ keys: [{ ...selected.publicKey.export({ format: 'jwk' }),
      kid: selected === oldKey ? 'old' : 'new', use: 'sig', alg: 'RS256' }] }));
  } else provider.callback()(req, res);
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const issuer = `http://127.0.0.1:${server.address().port}`;
const grant = 'urn:openid:params:grant-type:ciba';
const alternate = createServer(server.listeners('request')[0]);
await new Promise((resolve) => alternate.listen(0, '127.0.0.1', resolve));
const alternateIssuer = `http://127.0.0.1:${alternate.address().port}`;
try {
  provider = new Provider(issuer, {
    subjectTypes: ['public', 'pairwise'],
    scopes: ['openid', 'offline_access'],
    // Explicit app policy: the provider has no default pairwise identifier.
    pairwiseIdentifier: async (_ctx, accountId, client) => createHmac('sha256', 'pairwise-fixture-secret')
      .update(JSON.stringify([client.sectorIdentifier, accountId])).digest('hex'),
    fetch: (url, options) => fetch(url, allowReceiver && [`${issuer}/old`, `${issuer}/new`, `${alternateIssuer}/new`].includes(url)
      ? { ...options, dispatcher: undefined } : options),
    jwks: { keys: [{ ...opKey.privateKey.export({ format: 'jwk' }), kid: 'op', use: 'sig', alg: 'RS256' }] },
    features: { devInteractions: { enabled: false },
      registration: { enabled: true, initialAccessToken: 'registration-fixture' },
      registrationManagement: { enabled: true },
      ciba: { enabled: true, deliveryModes: ['poll'], processLoginHint: async () => 'customer',
        validateBindingMessage: async () => {}, validateRequestContext: async () => {},
        verifyUserCode: async () => {}, triggerAuthenticationDevice: async () => {} },
    },
    findAccount: async (_ctx, accountId) => ({ accountId, claims: async () => ({ sub: accountId }) }),
  });
  const discovery = await (await fetch(`${issuer}/.well-known/openid-configuration`)).json();
  const params = { grant_types: [grant], response_types: [], token_endpoint_auth_method: 'private_key_jwt',
    backchannel_token_delivery_mode: 'poll', jwks_uri: `${issuer}/old` };
  const registered = await fetch(discovery.registration_endpoint, { method: 'POST',
    headers: { authorization: 'Bearer registration-fixture', 'content-type': 'application/json' },
    body: JSON.stringify(params) });
  const client = await registered.json();
  assert.equal(registered.status, 201, JSON.stringify(client));
  let sequence = 0;
  async function start(selected, targetClient = client, endpoint = discovery.backchannel_authentication_endpoint, extra = {}) {
    const now = Math.floor(Date.now() / 1000);
    const input = [{ alg: 'RS256', kid: selected === oldKey ? 'old' : 'new' },
      { iss: targetClient.client_id, sub: targetClient.client_id, aud: issuer, iat: now, exp: now + 60, jti: `remote-${++sequence}` }]
      .map((part) => Buffer.from(JSON.stringify(part)).toString('base64url')).join('.');
    const assertion = `${input}.${sign('sha256', Buffer.from(input), selected.privateKey).toString('base64url')}`;
    const response = await fetch(endpoint, { method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: targetClient.client_id, scope: 'openid', login_hint: 'customer', ...extra,
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: assertion }) });
    return { status: response.status, body: await response.json() };
  }
  const denied = await start(oldKey);
  assert.notEqual(denied.status, 200);
  assert.equal(hits['/old'], 0);
  allowReceiver = true;
  const accepted = await start(oldKey);
  assert.equal(accepted.status, 200, JSON.stringify(accepted));
  assert.equal((await start(oldKey)).status, 200);
  assert.equal(hits['/old'], 1);
  currentKey = newKey;
  assert.equal((await start(newKey)).body.error, 'invalid_client');
  assert.equal((await start(oldKey)).status, 200);
  assert.equal(hits['/old'], 1);
  const update = await fetch(client.registration_client_uri, { method: 'PUT',
    headers: { authorization: `Bearer ${client.registration_access_token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ ...params, client_id: client.client_id, jwks_uri: `${issuer}/new` }) });
  assert.equal(update.status, 200, await update.text());
  assert.equal((await start(oldKey)).body.error, 'invalid_client');
  const rotated = await start(newKey);
  assert.equal(rotated.status, 200, JSON.stringify(rotated));
  assert.equal(hits['/old'], 1);
  assert.equal(hits['/new'], 1);
  console.log('PASS remote registered JWKS: default loopback refusal; cache reuse; unknown kid does not refresh fresh cache; management URL replacement rejects old key and accepts new key');
  console.log(`Initial blocked lookup: ${denied.status} ${denied.body.error}`);
  async function pairwiseRegister(changes = {}) {
    const response = await fetch(discovery.registration_endpoint, { method: 'POST',
      headers: { authorization: 'Bearer registration-fixture', 'content-type': 'application/json' },
      body: JSON.stringify({ ...params, jwks_uri: `${issuer}/new`, subject_type: 'pairwise', ...changes }) });
    return { status: response.status, body: await response.json() };
  }
  for (const changes of [
    { token_endpoint_auth_method: 'client_secret_basic' },
    { jwks_uri: undefined, jwks: { keys: [newKey.publicKey.export({ format: 'jwk' })] } },
    { grant_types: [grant, 'authorization_code'], response_types: ['code'], redirect_uris: ['https://rp.example.test/cb'] },
  ]) {
    const invalid = await pairwiseRegister(changes);
    assert.equal(invalid.status, 400, JSON.stringify(invalid));
    assert.equal(invalid.body.error, 'invalid_client_metadata');
  }
  const subjects = [];
  for (let i = 0; i < 2; i++) {
    const registration = await pairwiseRegister({ grant_types: [grant, 'refresh_token'] });
    assert.equal(registration.status, 201, JSON.stringify(registration));
    const targetClient = registration.body;
    const begun = await start(newKey, targetClient, discovery.backchannel_authentication_endpoint, { scope: 'openid offline_access' });
    assert.equal(begun.status, 200, JSON.stringify(begun));
    const consent = new provider.Grant({ accountId: 'customer', clientId: targetClient.client_id });
    consent.addOIDCScope('openid offline_access');
    await consent.save();
    await provider.backchannelResult(begun.body.auth_req_id, consent, { authTime: Math.floor(Date.now() / 1000) });
    const issued = await start(newKey, targetClient, discovery.token_endpoint,
      { grant_type: grant, auth_req_id: begun.body.auth_req_id, scope: 'openid offline_access' });
    assert.equal(issued.status, 200, JSON.stringify(issued));
    const [header, payload, signature] = issued.body.id_token.split('.');
    assert(verify('sha256', Buffer.from(`${header}.${payload}`), opKey.publicKey, Buffer.from(signature, 'base64url')));
    const claims = JSON.parse(Buffer.from(payload, 'base64url'));
    assert.equal(claims.aud, targetClient.client_id);
    assert.equal(claims.iss, issuer);
    assert.notEqual(claims.sub, 'customer');
    subjects.push(claims.sub);
    assert.equal(typeof issued.body.refresh_token, 'string');
    const renewed = await start(newKey, targetClient, discovery.token_endpoint,
      { grant_type: 'refresh_token', refresh_token: issued.body.refresh_token, scope: 'openid offline_access' });
    assert.equal(renewed.status, 200, JSON.stringify(renewed));
    const [rh, rp, rs] = renewed.body.id_token.split('.');
    assert(verify('sha256', Buffer.from(`${rh}.${rp}`), opKey.publicKey, Buffer.from(rs, 'base64url')));
    assert.equal(JSON.parse(Buffer.from(rp, 'base64url')).sub, claims.sub);
    const info = await fetch(discovery.userinfo_endpoint, { headers: { authorization: `Bearer ${renewed.body.access_token}` } });
    const infoBody = await info.json();
    assert.equal(info.status, 200, JSON.stringify(infoBody));
    assert.equal(infoBody.sub, claims.sub);
    assert.equal(infoBody.offline_access, undefined);
    assert.equal((await provider.RefreshToken.find(renewed.body.refresh_token)).accountId, 'customer');
    if (i === 0) {
      const pending = await start(newKey, targetClient);
      assert.equal(pending.status, 200, JSON.stringify(pending));
      const replacement = { ...targetClient, jwks_uri: `${alternateIssuer}/new` };
      for (const field of ['registration_access_token', 'registration_client_uri', 'client_secret_expires_at', 'client_id_issued_at']) delete replacement[field];
      const update = await fetch(targetClient.registration_client_uri, { method: 'PUT',
        headers: { authorization: `Bearer ${targetClient.registration_access_token}`, 'content-type': 'application/json' },
        body: JSON.stringify(replacement) });
      assert.equal(update.status, 200, await update.text());
      const oldInfo = await fetch(discovery.userinfo_endpoint, { headers: { authorization: `Bearer ${renewed.body.access_token}` } });
      const oldInfoBody = await oldInfo.json();
      const after = await start(newKey, targetClient, discovery.token_endpoint,
        { grant_type: 'refresh_token', refresh_token: renewed.body.refresh_token, scope: 'openid offline_access' });
      assert.equal(after.status, 200, JSON.stringify(after));
      const [ah, ap, as] = after.body.id_token.split('.');
      assert(verify('sha256', Buffer.from(`${ah}.${ap}`), opKey.publicKey, Buffer.from(as, 'base64url')));
      const newSubject = JSON.parse(Buffer.from(ap, 'base64url')).sub;
      assert.notEqual(newSubject, claims.sub);
      assert.equal(oldInfo.status, 200, JSON.stringify(oldInfoBody));
      assert.equal(oldInfoBody.sub, newSubject);
      assert.notEqual(oldInfoBody.sub, claims.sub);
      console.log('PASS sector management update: existing opaque UserInfo and refreshed ID Token use new sector subject while original signed ID Token is unchanged');
      const pendingRecord = await provider.BackchannelAuthenticationRequest.find(pending.body.auth_req_id);
      assert.equal(pendingRecord.accountId, 'customer');
      assert.equal(pendingRecord.grantId, undefined);
      await provider.backchannelResult(pending.body.auth_req_id, consent, { authTime: Math.floor(Date.now() / 1000) });
      const pendingTokens = await start(newKey, targetClient, discovery.token_endpoint,
        { grant_type: grant, auth_req_id: pending.body.auth_req_id });
      assert.equal(pendingTokens.status, 200, JSON.stringify(pendingTokens));
      const [ph, pp, ps] = pendingTokens.body.id_token.split('.');
      assert(verify('sha256', Buffer.from(`${ph}.${pp}`), opKey.publicKey, Buffer.from(ps, 'base64url')));
      assert.equal(JSON.parse(Buffer.from(pp, 'base64url')).sub, newSubject);
      console.log('PASS pending request sector update: canonical account and lack of approval retained; subsequent approval and issuance use current sector subject');
    }
  }
  assert.equal(subjects[0], subjects[1]);
  console.log('PASS pairwise CIBA: private_key_jwt plus jwks_uri; inline-only/basic/hybrid-without-sector rejected; verified ID Tokens share pairwise sub for the same sector; refresh and UserInfo retain subject and canonical account, offline_access is not an attribute');

} finally {
  await new Promise((resolve) => server.close(resolve));
  await new Promise((resolve) => alternate.close(resolve));
}
