// CIBA completion time is application-supplied, including on refresh.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync } from 'node:crypto';
import { jwtVerify, SignJWT } from 'jose';
import { Provider } from 'oidc-provider';
const signedRequests = process.argv.includes('signed');
const defaultsSelected = process.argv[2] === 'defaults';
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
      ...(signedRequests ? { backchannel_authentication_request_signing_alg: 'RS256', jwks: { keys: [{...publicKey.export({format:'jwk'}), kid:'time', alg:'RS256', use:'sig'}] } } : {}),
      ...(defaultsSelected ? { default_acr_values: ['requested', 'achieved'], default_max_age: 60 } : {}),
    })),
    features: { requestObjects: { enabled: true }, claimsParameter: { enabled: true }, devInteractions: { enabled: false }, ciba: {
      enabled: true, deliveryModes: ['poll'], processLoginHint: async () => 'customer',
      validateBindingMessage: async () => {}, validateRequestContext: async () => {},
      verifyUserCode: async () => {},
      triggerAuthenticationDevice: async () => {},
    } },
    findAccount: async (_ctx, accountId) => ({ accountId, claims: async () => ({ sub: accountId }) }),
  });
  const metadata = await (await fetch(`${issuer}/.well-known/openid-configuration`)).json();
  for (const client of ['client0', 'client1', 'client2']) {
    async function post(url, params) {
      if (signedRequests && url === metadata.backchannel_authentication_endpoint) {
        const now = Math.floor(Date.now() / 1000);
        const jwt = await new SignJWT({...params, nbf: now, jti: 'auth-context-request'}).setProtectedHeader({alg:'RS256', kid:'time'})
          .setIssuer(client).setAudience(issuer).setIssuedAt(now).setExpirationTime(now + 300).sign(privateKey);
        params = {request: jwt, acr_values: 'unsigned-override'};
      }
      const response = await fetch(url, { method: 'POST', headers: {
        authorization: `Basic ${Buffer.from(`${client}:reference-time-secret`).toString('base64')}`,
        'content-type': 'application/x-www-form-urlencoded',
      }, body: new URLSearchParams(params) });
      const body = await response.json();
      assert.equal(response.status, 200, JSON.stringify(body));
      return body;
    }
    for (const authTime of [undefined, 123]) for (const selection of ['default', 'explicit', 'acr', 'empty']) {
      const request = await post(metadata.backchannel_authentication_endpoint, { scope: 'openid offline_access', login_hint: 'customer',
        ...(selection === 'explicit' ? { claims: JSON.stringify({ id_token: { auth_time: null, acr: null, amr: null } }) } : {}),
        ...(selection === 'acr' ? { acr_values: 'requested' } : {}),
        ...(selection === 'empty' ? { acr_values: '' } : {}),
      });
      const saved = await provider.BackchannelAuthenticationRequest.find(request.auth_req_id);
      assert.equal(saved.params.acr_values, selection === 'acr' ? 'requested' : defaultsSelected ? 'requested achieved' : undefined);
      const grant = new provider.Grant({ accountId: 'customer', clientId: client });
      grant.addOIDCScope('openid offline_access');
      await grant.save();
      await provider.backchannelResult(request.auth_req_id, grant, { ...(authTime === undefined ? {} : { authTime }), acr: 'achieved', amr: ['pwd'] });
      const issued = await post(metadata.token_endpoint, { grant_type: grantType, auth_req_id: request.auth_req_id });
      const refreshed = await post(metadata.token_endpoint, { grant_type: 'refresh_token', refresh_token: issued.refresh_token });
      for (const token of [issued, refreshed]) {
        const { payload } = await jwtVerify(token.id_token, publicKey, { issuer, audience: client, algorithms: ['RS256'] });
        assert.equal(payload.sub, 'customer');
        assert.equal(payload.acr, defaultsSelected || scopeSelected || ['explicit', 'acr'].includes(selection) ? 'achieved' : undefined);
        assert.deepEqual(payload.amr, scopeSelected || selection === 'explicit' ? ['pwd'] : undefined);
        assert.equal(payload.auth_time, (defaultsSelected || scopeSelected || selection === 'explicit' || client === 'client2') ? authTime : undefined);
        assert.equal(Object.hasOwn(payload, 'auth_time'), (defaultsSelected || scopeSelected || selection === 'explicit' || client === 'client2') && authTime !== undefined);
      }
      console.log(`PASS ${client} selection=${selection} scope=${scopeSelected} signed=${signedRequests} authTime=${authTime ?? 'omitted'}: initial and refresh apply auth_time claim selection`);
    }
  }
} finally {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
}
