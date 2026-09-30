# Poll completion errors: protocol boundary versus generic result API

## Current alignment finding

The gem now persists a generic completion error and returns it once before
rejecting replay with `invalid_grant`. Codes are validated as bounded OAuth
error strings; descriptions are not an input to the Ruby API. Existing denials
retain NULL and continue returning `access_denied`. The negative state and
transactional denial hooks are retained, while observation distinguishes a
technical `failed` event from customer `denied`. Migration, idempotent retry,
conflicting completion, hook rollback and ping have direct tests.

The latest reference HTTP test also covers a custom `application_failure` and
an application-provided description. Both `transaction_failed` and the custom
code are returned once with HTTP 400, followed by `invalid_grant`. Neither
retains the supplied description. In 9.12.2, `backchannelResult` assigns
`error_description`, while the model persists `errorDescription`; the grant
handler reconstructs the error from the latter. The measured response bodies
contain only `error` for these two cases. Do not infer a public description
round-trip from the input object's API. [Execution](../validation/node-completion-error-descriptions.txt)
and [fixture](../../test/reference/full-op/lifecycle.mjs).

2026-09-30. Reviewed CIBA Core and executed the complete node-oidc-provider v9.12.2 on Node24.21.0 with its built-in memory adapter.

[CIBA Core §11](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#token_error_response) defines polling errors and distinguishes pending, throttling, expiry and denial. `transaction_failed` appears in the [Push error payload, §12](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#push_error_payload), not the poll-specific additions. Pending and slow_down describe continuing requests; expiry follows the request deadline. This does not define an application-to-OP completion API.

## Observed behavior

The complete reference OP accepted both `TransactionFailed` and `AuthorizationPending` through `backchannelResult`. Polling returned the supplied error once, consumed the request, and returned `invalid_grant` on the next poll. This verifies the generic error propagation in `provider.js` and `grant_common.js`; it does not establish those application-supplied results as suitable terminal poll outcomes.

The earlier access_denied-only restriction has been removed. The public API
still does not duplicate node's error class hierarchy: it accepts a
`CibaSupport::ProtocolError` code. Passing a continuing-state error as a result
is a terminal application decision, not a substitute for normal pending polls.
This matches the reference's one-use completion semantics without treating an
application outage as customer refusal. The default completion HTTP status is
400; invalid_token and insufficient_scope use401/403 as in the reference.

## Device-dispatch exception comparison

The reference harness records a request in the application's dispatch callback and then injects an exception. HTTP initiation returns 500 without auth_req_id, but the pending request remains in the adapter and can still be polled using the internally observed identifier. This matches the gem's existing `test_device_failure_is_not_an_observer_failure_or_success_response`. No test here demonstrates actual notification delivery or durable recovery.

## Evidence

- [Node LTS HTTP log](../validation/node-full-op-lts.txt): generic completion errors, dispatch failure and prior lifecycle scenarios.
- [Gem log](../validation/completion-boundaries.txt): Ruby4.0.6 / SQLite, 105 tests / 783 assertions, no failures/errors/skips.
- [Gem regression test](../../test/ciba_alignment_test.rb): rejects transaction_failed, authorization_pending, slow_down, expired_token, invalid_grant and server_error as completion results without mutation.
- The prior Ruby/DB matrix covered 104 tests. No runtime or schema change was made for this review; the added test has not been rerun on every matrix entry.

## Current gem evidence

[Focused regression](../validation/completion-errors-current.txt) passes7 tests /166 assertions.
The old105-test log and unsupported-error regression above describe the previous
implementation, not the current API.

Ruby3.4 SQLite/PostgreSQL/MySQL each pass18 tests /339 assertions ([matrix](../validation/completion-errors-matrix.txt)). The [installed artifact](../validation/completion-errors-installed.txt) verifies custom failure/replay alongside existing smokes; SHA256 `0b0b395c7ff90ffe4e697afe7f5c17c18bc7d8d339e4134415d65ca384a76626`.
