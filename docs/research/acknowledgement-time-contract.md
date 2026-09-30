# Acknowledgement lifetime and application processing time

Reference: released node-oidc-provider 9.12.2 on the pinned Node 24 image.
Both fixtures advance an injected application clock at callback boundaries;
the reference exercises real HTTP routes without wall-clock sleeps.

| Case | Source creation | Stored expiry | Response expires_in | First poll |
|---|---|---|---|---|
| Hint resolution +7 s; dispatch +3 s; requested expiry 20 s | start +7 s | start +27 s | 20 | authorization_pending |
| Hint resolution +7 s; dispatch +25 s; requested expiry 20 s | start +7 s | start +27 s | 20 | expired_token |

These results match in the reference and gem. Lifetime starts after validation
and account resolution. Synchronous device dispatch runs after storage and
before the response; its elapsed time is not subtracted from expires_in.
The gem explicitly returns interval while the reference omits that optional field.

The second case shows a shared limitation: a success acknowledgement can describe
an already expired request if the application callback runs too long. Do not
interpret acknowledgement as approval or guaranteed remaining lifetime. Device
dispatch should schedule the application work promptly, not wait for customer
interaction. That integration constraint does not establish a strict maximum
request duration or receipt-based expiry guarantee for arbitrary deployments.

No runtime change was made: moving the epoch or changing expires_in would change
the measured reference behavior. CIBA-080 remains partial for the literal
receipt-time requirement in the original normative catalog; it is no longer an
unmeasured reference difference. Network latency, clock changes between hosts,
custom node adapters and production queue delivery were not tested here.

- [Reference fixture](../../test/reference/full-op/acknowledgement-time.mjs)
- [Node execution](../validation/node-acknowledgement-time.txt)
- [Gem execution: 1 test / 12 assertions](../validation/acknowledgement-time.txt)
