# node-oidc-provider lifecycle reference

Run `node --experimental-vm-modules test/reference/lifecycle.mjs` (verified with Node v26.5.0).

The two JavaScript fixtures are unchanged sources from the v9.12.2 release, fetched using the GitHub connector on 2026-09-30:

- [CIBA handler](https://github.com/panva/node-oidc-provider/blob/v9.12.2/lib/actions/grants/ciba.js)
- [Source helper](https://github.com/panva/node-oidc-provider/blob/v9.12.2/lib/helpers/grant_source.js)

Their MIT license is retained alongside them. These files are reference tests, not dependencies of the Ruby gem.

The harness executes both real modules using native VM modules. It substitutes deterministic in-memory persistence, token issuance and revocation, context validation, presence checks and attestation binding. It verifies the actual handler/helper ordering for pending, denial, failed issuance/replay and expired consumption. It cannot establish full OP interoperability, cryptographic behavior, adapter atomicity, or behavior of node's global HTTP error middleware.

In particular, consumed state survives a simulated issuance exception because the test persistence has no outer transaction. A deployment-specific transactional adapter may behave differently. The gem's existing transaction rollback is an observed difference, not evidence that either implementation is insecure.
