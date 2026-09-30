# Remaining partial audit findings

Current reconciliation: CIBA-072 has a mandatory-input inventory and direct
presence/selection evidence ([inventory](required-parameter-inventory.md));
CIBA-067 is also reconciled against the [supported parser inventory](request-parameter-inventory.md).
Both are protocol_boundary_verified. The current overlay has103 verified rows
and5 partial rows. The table below retains the earlier investigation history.

The159-row catalog has been classified, not declared conformant. Its22 partial
rows overlap; they do not represent22 independent missing features. This review
retains all IDs and separates reference differences from limitations shared by
both implementations. Other workstreams in alignment-roadmap.md remain in scope.

| IDs | Classification | Next evidence/action |
|---|---|---|
| 007, 008, 014, 025, 064 | Authentication coverage | The twelve configured RS/PS/ES/HS assertion algorithms now pass at both endpoints in reference/gem, with three-DB issuance evidence; CIBA-008 is resolved for that configuration. Legacy method-URN registration was found unusable and is now rejected for CIBA, with three-DB evidence; the shared metadata now removes that unusable URN without changing upstream authentication dispatch. Edwards client assertions now have initial inline verification, explicit independent algorithm configuration and registration/Discovery support. Reference accepts both names; gem rejects wrong keys/claims/replay and passes the three-DB regression subset. Remote HTTP keys, forced-expiry rotation/failure, ordinary code-grant coexistence, installed inline-key authentication and full Ruby3.3/3.4 suites now pass. Installed HTTPS Edwards authentication and unrelated RSA client scope now pass. CIBA-014/025/064 are verified for configured methods; CIBA-007 is also resolved by matching OAuth/OIDC method lists with the legacy URN removed. Do not invent an unbounded Cartesian product of all extensions. |
| 013 | Configuration adaptation | Node always advertises user-code support and requires its application verifier; gem makes it opt-in and rejects clients requiring a disabled feature. Compare enabled configurations; do not remove the verifier gate just to align defaults. |
| 017 | Verified reference-supported proof | Private-key JWT and self-signed TLS proof both have evidence. Signed-request-only proof is rejected by both. No missing reference feature is established by this row. |
| 050 | Confirmed feature gap | Initial Ed25519/EdDSA request verification, OKP import, exact algorithm/curve checks, wrong-key rejection and registration are implemented. Cross-library fixed vectors, actual HTTP remote keys and installed-artifact issuance now pass; CIBA-050 is protocol_boundary_verified for the configured algorithms. HTTPS Edwards rotation remains a broader integration case. Both names pass the pinned reference HTTP test. |
| 054 | Resolved NumericDate alignment | Reference HTTP accepts fractional dates and future iat. Gem now accepts them while checking finite numeric values, valid exp/nbf and required claims; three-DB signature regressions pass. |
| 056 | Resolved request-jti alignment | Reference and gem accept empty strings, reject null/non-string values and create fresh pending requests on reuse without inheriting approval. Client uniqueness remains a client duty; authentication-assertion replay checks remain separate. |
| 066 | Verified configured signature boundary | Eleven algorithms including Edwards, key/claim negative cases and independent vectors are now verified; current three-DB signature/pairwise audit passes. Custom profiles and production key custody remain application responsibilities. |
| 067, 072 | Aggregate validation rows | Combined signed-request/ping/user-code dispatch now has a missing/empty inner-field regression: valid unsigned outer values cannot supply scope, hint, notification token or required user code; rejection precedes persistence/device dispatch ([2 tests / 44 assertions](../validation/signed-ping-required-fields.txt)). Claims/resources/RAR and request_context signed-value isolation have separate tests. This does not prove every extension combination; retain partial classification until the supported parameter inventory and individual row limits are reconciled. These aggregate IDs must not generate duplicate features. |
| 080 | Shared timing limitation | Both start lifetime after resolution and can acknowledge after expiry if dispatch takes too long. Measured; no reference behavior change required. |
| 089 | Delivery concurrency coverage | Resolved for measured management overlap: reference forwards saved credentials to the current registered endpoint on retry. Gem now follows that design; mode changes to poll reject retries and in-flight sends retain their selected destination. Three-DB ping tests and reference HTTP/TLS evidence cover this boundary. |
| 093 | Explicit application contract | Neither arbitrary app hooks nor database waits have a proven hard30-second bound. State deployment timeout responsibility; do not imply current fast tests establish a service-level guarantee. |
| 109 | Bounded transport adaptation | Resolved: ping now closes after status headers without reading/draining the body. Real TCP, reference TLS and installed TLS tests pass; CIBA-109 is protocol_boundary_verified. Key/sector reads remain bounded. |
| 124 | Deliberate throttling adaptation | Gem enforces advertised interval/slow_down; node delegates polling policy to the app. Existing plan explicitly retains this difference pending contrary interoperability evidence. |
| 138 | Conditional output absent | The gem does not emit error_uri in tested errors. Do not add a URI output feature merely to validate it; document custom overrides as application responsibility. |
| 147 | Resolved error mapping | Gem now matches measured reference: missing identity400 invalid_request without challenge, wrong Basic401 invalid_client with challenge. Scoped to backchannel/CIBA grant; JWT/mTLS and ordinary-flow regressions pass on three DBs. |
| 151 | Shared policy/deployment limit | Expired hints with retained trusted keys are accepted by default in both. Deployment hint-retention policy remains outside OP transport proof. |
| 153 | Verified hint signature boundary | Edwards issuance/JWKS/hints and RSA-recipient encrypted output now have independent and installed evidence. CIBA HMAC issuance/hints now use the client secret, with request-local Basic/POST retrieval and a callback for other methods. Three-DB tests and independent jose verification pass. DCR secret lengths, installed issuance/refresh/hints and backend secret replacement now pass, with full Ruby3.3/3.4 regression evidence. CIBA-153 is protocol_boundary_verified; arbitrary deployment rotation policies are not inferred. Encrypted input hints are rejected by both. |

## Edwards signature evidence

The existing reference algorithm fixture now runs eleven algorithms: nine RS/PS/ES
variants plus Ed25519 and EdDSA. Each passes with its registered key and rejects a
different key over real HTTP in the pinned Node24/provider9.12.2 environment.
[Execution](../validation/node-signed-edwards.txt).

At the initial comparison the gem excluded these algorithms. A subsequent
CIBA-local OpenSSL adapter now supports both for Ed25519 keys. The installed Ruby OpenSSL supports generating ED25519 keys, but that
alone does not establish portable JWK import or JWT verification support.
[ruby-jwt documentation](https://github.com/jwt/ruby-jwt) identifies EdDSA as an
extension; [jwt-eddsa](https://github.com/jwt/ruby-jwt-eddsa) documents its separate
algorithm/JWK integration. The implementation choice must be verified against
the supported Rubies, the gem's CIBA-scoped behavior and the two distinct JOSE
algorithm names; globally enabling an algorithm is not sufficient evidence.
Current implementation and limits are tracked in docs/signed-requests.md; no
global JWT algorithm support is inferred from the CIBA-local adapter.
