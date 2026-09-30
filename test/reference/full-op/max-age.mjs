// CIBA completion time is application-supplied, including on refresh.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync } from 'node:crypto';
import { jwtVerify } from 'jose';
import { Provider } from 'oidc-provider';
const defaultsSelected = true;
const scopeSelected = process.argv[2] === 'scope';
const grantType = 'urn:openid:params:grant-type:ciba';
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
let provider;
const server = createServer((req, res) => provider.callback()(req, res));
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const issuer = `http://127.0.0.1:${server.address().port}`;
try {
  provider = new Provider(issuer, {
    jwks: { keys: [{ ...privateKey.export({ format: 'jwk' }), kid: 'time', alg: 'RS256', use: 'sig' }] },
    scopes: ['openid', 'offline_access'],
    acrValues: ['requested', 'achieved'],
    claims: { amr: null, ...(scopeSelected ? { openid: ['sub', 'auth_time', 'acr', 'amr'] } : {}) },
    clients: [undefined, false, true].map((value, index) => ({
      client_id: `client${index}`, client_secret: 'reference-time-secret',
      grant_types: [grantType, 'refresh_token'], response_types: [], redirect_uris: [],
      token_endpoint_auth_method: 'client_secret_basic', backchannel_token_delivery_mode: 'poll',
      ...(value === undefined ? {} : { require_auth_time: value }),
      ...(defaultsSelected ? { default_acr_values: ['requested', 'achieved'], default_max_age: 60 } : {}),
    })),
    features: { claimsParameter: { enabled: true }, devInteractions: { enabled: false }, ciba: {
      enabled: true, deliveryModes: ['poll'], processLoginHint: async () => 'customer',
      validateBindingMessage: async () => {}, validateRequestContext: async () => {},
      verifyUserCode: async () => {},
      triggerAuthenticationDevice: async () => {},
    } },
    findAccount: async (_ctx, accountId) => ({ accountId, claims: async () => ({ sub: accountId }) }),
  });
  const metadata = await (await fetch(`${issuer}/.well-known/openid-configuration`)).json();
  const client = 'client0';
  for (const value of [undefined, '0', '60', '1.0', '1e2', '0x10', '0b10', '0o10', '1.', '1.e2', '\uFEFF1\u00A0', '-0', '', ' ', '-1', '1.5', 'NaN', '9007199254740992', '1_0', '\u00851']) {
    const response = await fetch(metadata.backchannel_authentication_endpoint, {
      method: 'POST', headers: {
        authorization: `Basic ${Buffer.from(`${client}:reference-time-secret`).toString('base64')}`,
        'content-type': 'application/x-www-form-urlencoded',
      }, body: new URLSearchParams({ scope: 'openid', login_hint: 'customer', ...(value === undefined ? {} : { max_age: value }) }),
    });
    const body = await response.json();
    if (['-1', '1.5', 'NaN', '9007199254740992', '1_0', '\u00851'].includes(value)) {
      assert.equal(response.status, 400, JSON.stringify(body));
      assert.equal(body.error, 'invalid_request');
      console.log(`PASS rejected max_age=${JSON.stringify(value)}`);
      continue;
    }
    assert.equal(response.status, 200, JSON.stringify(body));
    const saved = await provider.BackchannelAuthenticationRequest.find(body.auth_req_id);
    const effective = value === undefined || value === '' ? '60' : value;
    assert.equal(saved.params.max_age, Number(effective) === 0 ? undefined : effective);
    assert.equal(saved.params.prompt, Number(effective) === 0 ? 'login' : undefined);
    assert.equal(saved.claims.id_token.auth_time.essential, true);
    console.log(JSON.stringify({ value: value ?? 'omitted', max_age: saved.params.max_age, prompt: saved.params.prompt, claims: saved.claims }));
    const grant = new provider.Grant({ accountId: 'customer', clientId: client });
    grant.addOIDCScope('openid');
    await grant.save();
    await provider.backchannelResult(body.auth_req_id, grant, { authTime: 123 });
    const tokens = await fetch(metadata.token_endpoint, { method: 'POST', headers: {
      authorization: `Basic ${Buffer.from(`${client}:reference-time-secret`).toString('base64')}`,
      'content-type': 'application/x-www-form-urlencoded',
    }, body: new URLSearchParams({grant_type: grantType, auth_req_id: body.auth_req_id}) });
    assert.equal(tokens.status, 200);
    const { payload } = await jwtVerify((await tokens.json()).id_token, publicKey, {issuer, audience: client});
    assert.equal(payload.auth_time, 123);
  }
} finally {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
}
