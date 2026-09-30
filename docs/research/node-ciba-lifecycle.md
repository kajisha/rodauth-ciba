# CIBA lifecycle comparison against node-oidc-provider v9.12.2

2026-09-30. GitHub connector retrieval succeeded after shell DNS and Web cache failures. The earlier source-access limitation is resolved for the start route, grant handler and request model. The initial analysis below used source inspection and an isolated harness; a subsequent [complete HTTP OP test](../../test/reference/full-op/README.md) now verifies the listed lifecycle scenarios with actual signing and the built-in memory adapter on Node24 LTS.

The unchanged CIBA handler and source helper now also execute in [an isolated reference harness](../../test/reference/README.md). `node --experimental-vm-modules test/reference/lifecycle.mjs` passes on Node v26.5.0; [log](../validation/node-reference-lifecycle.txt). With non-transactional in-memory persistence, issuance failure leaves consumption intact and the next poll revokes the Grant and returns invalid_grant. Cryptography, actual token persistence and global HTTP middleware are stubbed/absent. This confirms local control-flow behavior only.

## Confirmed ordering

- [Start route](https://github.com/panva/node-oidc-provider/blob/v9.12.2/lib/actions/authorization/ciba.js): save the BackchannelAuthenticationRequest, prepare auth_req_id/expires_in, await triggerAuthenticationDevice. There is no compensating deletion in this function if the trigger throws. The gem now uses the same persistence-before-trigger boundary; application-owned outer transactions remain a Sequel-specific concern.
- [CIBA grant handler](https://github.com/panva/node-oidc-provider/blob/v9.12.2/lib/actions/grants/ciba.js): find a client-bound request; check expiry; return authorization_pending when neither grant nor error exists; consume; propagate a saved result error; validate the Grant; issue tokens.
- [Source helper](https://github.com/panva/node-oidc-provider/blob/v9.12.2/lib/helpers/grant_source.js): consuming an already consumed source revokes its Grant and throws invalid_grant. Grant lookup checks existence, expiry and client identity.
- [Request model](https://github.com/panva/node-oidc-provider/blob/v9.12.2/lib/models/backchannel_authentication_request.js): consume invokes adapter.consume and emits consumed. No consumable mixin is needed for this model; the previously guessed mixin path returned 404.
- [Common issuance](https://github.com/panva/node-oidc-provider/blob/v9.12.2/lib/helpers/grant_common.js): validates the account and Grant/account match, saves the access token, optionally saves a refresh token, then generates the ID Token and response.

## Implemented alignment

The gem now checks request expiry before consumed status. Replaying an unexpired consumed approved request revokes its saved CIBA consent and linked OAuth token rows, then returns invalid_grant. A denied result is consumed on first collection (access_denied); a second collection returns invalid_grant. Trusted Ruby completion retries remain idempotent and do not themselves replay token collection.

Tests: test_replayed_result_revokes_its_saved_consent_and_tokens, test_denied_result_is_consumed_on_first_collection, test_expiry_precedes_consumed_result_check.

Revocation is scoped by the saved consent ID: reusing one consent across multiple requests means replay can revoke all tokens linked to that consent. Offline JWT verification cannot observe a database revocation without an application/resource-server mechanism.

## Deliberate differences and remaining gaps

- The node start function omits interval and the CIBA grant handler has no slow_down branch. The gem advertises and enforces an increasing interval. This statement is limited to these functions; it does not prove absence of all application/server rate limiting.
- node consumes before result-error propagation and token generation. The gem deliberately rolls back consumption and token rows if issuance/signing fails, per [ADR 0004](../adr/0004-retain-atomic-issuance-and-stage-alignment.md). Atomicity of an application's node adapter is not established by reading these functions.
- node accepts all three hint mechanisms and invokes application user-code validation. Initial gem scope remains login_hint only; broader capabilities are tracked in the accepted [staged roadmap](../alignment-roadmap.md).
- node persists claims, nonce, resource, params and RAR-related state. The gem now persists nonce and optionally requested/approved/rejected claims. Full claims constraint policy, resource and RAR remain gaps.
- node propagates OIDC result errors; the gem now supports generic error codes with one-use collection and explicit storage migration (see completion-error-boundaries.md).
- Complete node HTTP lifecycle scenarios and the gem's SQLite/PostgreSQL/MySQL matrix now pass. Production node adapters, process crashes and application-specific response-loss recovery remain unverified.
