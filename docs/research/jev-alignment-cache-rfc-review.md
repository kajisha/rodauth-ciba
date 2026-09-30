# Standards-informed JWKS stale-use decision

## Standards findings

[RFC9111 §4.2.4](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.4)
restricts HTTP stale serving, including explicit revalidation prohibitions.
[§6](https://www.rfc-editor.org/rfc/rfc9111.html#section-6) distinguishes
application data reuse from HTTP caching, so these rules alone do not prove
that all application-level stale key use is forbidden. The relationship must
be clear. A node-like minimum lifetime overriding directives is not evidence
of HTTP-cache conformance. HTTP freshness gives max-age precedence over Expires
and accounts for Age/Date, rather than selecting the largest lifetime.

[RFC5861 §4](https://www.rfc-editor.org/rfc/rfc5861.html#section-4)
defines optional stale-if-error with a bounded allowance, without renewing
freshness. Its listed errors are500/502/503/504, not every5xx. It supplies no
universal60-second JWKS grace or assurance that such a grace meets a deployment's
security requirements. Both request and response directives can authorize the
extension; restricting this gem's policy to publisher authorization is a design
choice, not an RFC requirement.

[OIDC Core §10.2.1](https://openid.net/specs/openid-connect-core-1_0.html#RotateEncKeys)
recommends max-age and coordinating old decryption-key retention with cache
lifetime. No universal failed-fetch grace was found in the reviewed OIDC/CIBA
provisions. These findings constrain the policy but do not choose an operational
allowance, so the user-requested Jev evaluation was performed.

## Jev decision

Model `jev-1.13.0`; [input](jev-alignment-cache-rfc-request.json),
[raw output](jev-alignment-cache-rfc-response.json). Public standards summaries
and conceptual options only; no private source/logs were transmitted.

| Judgment | Result | Selected probability | Confidence |
|---|---|---:|---:|
| Default | Publisher-authorized bounded grace |0.93|0.90|
| Unconditional additional60 seconds | Reject |1.00|1.00|
| Cap explicit publisher allowance at60 seconds | Adopt |0.95|0.91|
| Earlier successful-cache policy | Reconcile HTTP semantics |0.99|0.99|

These are model judgments, not standards text or calibrated correctness claims.
The new result uses evidence missing from previous comparisons; it is not a
repetition intended to obtain a preferred score.

## Decision and implementation contract

Use a single policy for authentication and encryption. Allow fallback only if
the successful JWKS response explicitly permits stale-if-error; cap at the lesser
of its allowance and60 seconds, measured from HTTP freshness expiry with Age/Date.
No directive means no grace. Respect restrictive directives; conservatively
refuse ambiguous/conflicting directives. Do not store no-store responses for
reuse; no-cache requires validation, and must-revalidate blocks stale fallback.
Use eligible500/502/503/504 or corresponding timeout failures, without renewing
the deadline. Invalid TLS, blocked destinations, malformed successful key sets,
explicit eviction and successful key replacement must not resurrect old keys.

This replaces the unilateral grace proposal. Also revisit the earlier approved
minimum60-second floor: do not override explicit HTTP freshness/revalidation
instructions or describe the old behavior as RFC9111-conforming. No arbitrary
extra lifetime is justified solely by reference-provider similarity. A default
for absent freshness metadata must be documented separately from explicit TTLs.

The earlier normal-cache decision was based on reference behavior and a Jev
comparison without these standards constraints. That missing evidence explains
the change in recommendation. Implementation follow-up: the user approved this decision. Runtime now uses
explicit freshness and publisher-authorized bounded fallback. The no-metadata
default is no reuse. See the operations guide for exact restrictions and local
cache ownership. Current validation is recorded in alignment closeout; earlier
floor tests are historical evidence only.
