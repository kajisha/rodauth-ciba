# Bounded stale JWKS reuse: candidate C

Status: superseded candidate. The user delegated the allowance decision to
standards and, where those leave discretion, Jev. The resulting policy is
publisher-authorized stale-if-error capped at60 seconds, not unconditional grace.
See [standards review and decision](jev-alignment-cache-rfc-review.md).
The original proposal below is preserved for comparison; it is not the accepted
implementation contract. The approved successor is now implemented; see the operations guide.

## Policy

Successful validated retrieval records `fresh_until` using the already approved
minimum 60-second lifetime and longer applicable HTTP cache directives.
`stale_until = fresh_until + 60 seconds`. These are monotonic-clock deadlines.
The extra 60 seconds is a proposed operational allowance, not a CIBA requirement
or a measured optimum. Both authentication and encryption use the same policy,
without a dedicated public policy switch.

| Condition | Result |
|---|---|
| Before fresh_until | Use the validated cached keys. |
| At or after fresh_until | Attempt retrieval before choosing a fallback. |
| Retrieval succeeds with valid JWKS | Replace keys; establish new deadlines. |
| Timeout or HTTP 5xx, with validated old keys, and current time strictly before stale_until | Use old keys for this operation; do not move either deadline. |
| At or after stale_until, or no previously validated keys | Reject on retrieval failure. |
| HTTP 3xx/4xx, invalid JSON/JWKS, invalid TLS, blocked address, oversized response | Reject; do not use stale keys. Invalidate stale eligibility so a later transient failure cannot resurrect those keys. |
| Successful empty JWKS or successful removal of a key | Replace old set; never fall back to removed keys for a lookup miss. |
| Explicit eviction or client JWKS source replacement | Discard associated stale eligibility. |

Only explicitly classified timeout exceptions and HTTP 500–599 permit fallback.
Generic exceptions, connection refusal/reset and DNS errors are not silently
classified as timeouts. Existing transport protections and error mapping remain.
Check the grace deadline AFTER network completion, not only before the attempt.
No periodic retry job or separate retry-backoff policy is added: each subsequent
operation after normal expiry attempts retrieval again.

Example with normal TTL=60 seconds: success at t=0; normal expiry at t=60;
failed retrieval at t=70 can use old keys; failures at t=100 do not extend the
deadline; a failed retrieval completing at t=120 cannot use old keys. A first
request at t=180 never starts a new 60-second grace. With normal TTL=3600,
the grace ends at t=3660, not t=120.

## Implementation boundaries

The existing upstream TTL-store interface only returns fresh values. Its private
`@store` must not become a production dependency for retrieving stale entries.
A CIBA-scoped cache entry needs payload, successful freshness deadline, fixed
stale deadline and invalidation generation, with bounded expired-entry cleanup.
Use the existing cache ownership/eviction conventions where feasible; do not add
an unbounded parallel stale-key map or change unrelated OP-wide HTTP behavior.
This integration detail must be resolved in code review before implementation
is considered complete.

Concurrent retrieval and management updates must not restore an older key set:
an in-flight failed retrieval cannot reuse its snapshot after a later successful
replacement or eviction. Recheck generation and current entry under a lock when
committing replacement or selecting fallback; never hold that lock during HTTP.
A successful fetched key set is only reusable after normal JWKS validation.
Cryptographic key selection/verification still applies separately on every use.

## Acceptance tests

- Fresh hit does not fetch; expiry attempts retrieval; successful replacement is used.
- Timeout and parseable/nonparseable HTTP 5xx are classified by transport status,
  independent of error-body JSON, subject to transport size/security restrictions.
- Before/at the fixed grace boundary; first request long after expiry; repeated
  failures; an HTTP attempt crossing the grace deadline; longer original TTL.
- No prior cache, invalid JSON/JWKS, empty successful JWKS, 4xx/3xx, TLS failure,
  blocked address and oversized responses cannot resurrect old credentials.
- Eviction and concurrent successful replacement invalidate stale snapshots.
- Authentication and encryption exercise the same deadlines through actual flows;
  rejection creates no pending request or issued token, preserving rollback.
- Unrelated HTTP lookups retain their existing behavior.

Use a controlled monotonic clock for boundaries, plus HTTP/TLS integration for
failure classification. Do not add minute-long sleeps to the routine suite.

## Remaining product decision

Additional stale-key reuse may authenticate a removed credential or encrypt to
a removed recipient key for up to 60 seconds beyond the normal cache lifetime.
This is distinct from the already accepted normal minimum lifetime. The user
must choose whether that extra allowance is acceptable, or give another duration.
Jev's Confidence 0.88 was confidence in a conditional judgment, not approval of
this allowance. This proposal intentionally differs from the reference's
response-dependent, potentially repeatedly extended failed-refresh freshness.
