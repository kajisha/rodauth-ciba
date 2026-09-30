// Isolated execution of unchanged v9.12.2 sources, not a full OP integration test.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), 'node-oidc-provider');
class InvalidGrant extends Error {}
class AuthorizationPending extends Error {}
class ExpiredToken extends Error {}
let state;
const stubs = {
  'errors.js': { InvalidGrant, AuthorizationPending, ExpiredToken },
  'validate_presence.js': { default: () => {} },
  'check_attest_binding.js': { checkAttestBinding: () => {} },
  'assert_provider_context.js': { default: () => {} },
  'configuration_result.js': { account: (value) => value },
  'weak_cache.js': { default: () => ({ configuration: {} }) },
  'revoke.js': { default: async () => { state.revoked = true; } },
  'grant_common.js': {
    throwIfAsyncGrantError: (request) => { if (request.error) throw new Error(request.error); },
    issueTokens: async () => {
      state.issued = true;
      if (state.failIssuance) throw new Error('injected issuance failure');
    },
  },
};
const cached = new Map();
function dependency(specifier) {
  const name = path.basename(specifier);
  if (!cached.has(name)) {
    const exports = stubs[name];
    assert(exports, `unexpected import: ${specifier}`);
    cached.set(name, new vm.SyntheticModule(Object.keys(exports), function () {
      for (const [key, value] of Object.entries(exports)) this.setExport(key, value);
    }));
  }
  return cached.get(name);
}
async function original(name) {
  const module = new vm.SourceTextModule(fs.readFileSync(path.join(root, name), 'utf8'));
  await module.link(dependency);
  await module.evaluate();
  return module.namespace;
}
const source = await original('grant_source.js');
const { handler } = await original('ciba.js');
const provider = {
  BackchannelAuthenticationRequest: { find: async () => state.request },
  Grant: { find: async () => ({ clientId: 'client', isExpired: false }) },
};
const ctx = { oidc: { params: { auth_req_id: 'id' }, client: { clientId: 'client' }, entity() {} } };
const helpers = {
  validateDpop: async () => undefined, checkMtlsCert() {}, checkDpopRequired() {},
  findGrantSource: (...args) => source.findGrantSource(provider, ...args),
  consumeGrantSource: (...args) => source.consumeGrantSource(provider, ...args),
  validateGrant: (...args) => source.validateGrant(provider, ...args),
};
function reset(request = {}, options = {}) {
  state = { ...options, request: { clientId: 'client', grantId: 'grant', ...request,
    async consume() { this.consumed = true; } } };
}
const run = () => handler(provider, helpers, ctx);

reset({ grantId: undefined });
await assert.rejects(run(), AuthorizationPending);
assert.equal(state.request.consumed, undefined);

reset({ grantId: undefined, error: 'access_denied' });
await assert.rejects(run(), /access_denied/);
assert.equal(state.request.consumed, true);
await assert.rejects(run(), InvalidGrant);

reset({}, { failIssuance: true });
await assert.rejects(run(), /injected issuance failure/);
assert.equal(state.request.consumed, true);
await assert.rejects(run(), InvalidGrant);
assert.equal(state.revoked, true);

reset({ consumed: true, isExpired: true });
await assert.rejects(run(), ExpiredToken);
assert.equal(state.revoked, undefined);

reset({ consumed: true, clientId: 'another-client' });
await assert.rejects(run(), InvalidGrant);
assert.equal(state.revoked, undefined);

reset();
await run();
assert.equal(state.issued, true);
assert.equal(state.request.consumed, true);
await assert.rejects(run(), InvalidGrant);
assert.equal(state.revoked, true);

console.log('PASS: original node v9.12.2 handler/source helper: pending, denied, issuance/replay, expiry precedence, client isolation');
console.log('Stubs: in-memory persistence, issuance, revocation, context/presence/binding checks. Not a full OP/adapter test.');
