# Signed CIBA authentication requests

2026-09-30. Measured against released node-oidc-provider 9.12.2 on Node24.21.0.
The gem now has an opt-in implementation. This contract records the original
implementation boundary; [support and remaining verification](../signed-requests.md)
distinguish tested behavior from unfinished coverage.

## Specification boundary

[CIBA Core sections 4, 7.1.1 and 7.2](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)
define asymmetric signed requests, algorithm registration/discovery, and required
iss/aud/exp/iat/nbf/jti. The request JWT carries authentication parameters;
client-authentication parameters remain outside it. requested_expiry may be a
string or number. Encrypted request JWTs are unsupported. Client authentication
and request-signature verification are separate checks. The former is not
replaced by a successfully verified request object.

## Actual reference evidence

The [complete HTTP harness](../../test/reference/full-op/lifecycle.mjs) now enables
`features.requestObjects` and adds a separate `signed` client, with its own RSA
key and registered RS256 backchannel request algorithm. The OP signing key is
different. Existing unsigned clients and all earlier scenarios continue passing.
[Execution log](../validation/node-full-op-lts.txt).

| Case | Measured result |
|---|---|
| RequestObjects disabled | No backchannel signing algorithms in Discovery |
| RequestObjects enabled | Discovery includes RS256; source excludes HS algorithms |
| Correct signed request, authenticated client | Pending request for customer, requested lifetime 123 seconds |
| Customer approval then poll | Actual signed ID Token has audience `signed` |
| Correct signature without client authentication | 401 invalid_client |
| Registered signed client sends ordinary unsigned parameters | 400 invalid_request |
| Same signed JWT submitted twice | Two distinct accepted authentication requests |
| Conflicting outer scope/login_hint | Ignored; values inside JWT determine request |
| Missing inner scope/hint, values supplied outside | 400 invalid_request; outer values cannot fill missing JWT fields |
| Missing any of iss/aud/exp/iat/nbf/jti | 400 invalid_request |
| Wrong issuer/audience/client_id, expired exp or future nbf | 400 invalid_request |
| Wrong signing key or unknown kid | 400 invalid_request |
| Nested request/request_uri | 400 invalid_request |
| requested_expiry number or numeric string | Both accepted with requested lifetime |
| Future iat with valid exp | Accepted by the default reference checks |
| Empty-string jti | Accepted by the default reference checks |

The reference middleware authenticates first, strips outer authorization
parameters, processes the signed request and then validates CIBA parameters.
Request-object errors are remapped to invalid_request. Its default policy
requires jti but has no one-use request ledger. These measurements are not a
recommendation to accept empty identifiers or inconsistent timestamps.

## Upstream reuse and necessary adaptation

rodauth-oauth 1.7.0's `oauth_jwt_secured_authorization_request` handles the browser
authorization route. Its `validate_authorize_params` may fetch request_uri,
accepts optional iss/aud checks and overlays JWT fields on the existing request.
Calling it unchanged would preserve unsigned outer fields and would not impose
the CIBA claim contract. It also reports authorization-route errors rather than
the CIBA invalid_request response. Do not enable or change this globally merely
to add CIBA support.

Reuse `oauth_application_jwks` for the authenticated client's registered keys,
with explicit CIBA signature/algorithm/claim checks. Do not trust a key or URL
supplied in the JWT header. Before this increment, the CIBA client eligibility check
rejects any `backchannel_authentication_request_signing_alg`; it must be changed
along with activation and metadata, not independently.

## Implementation contract

1. Add an opt-in asymmetric algorithm list, empty by default; publish it only
   when active. Add explicit client-metadata migration/configurable column and
   require the registered algorithm to match the verified JWT. Preserve other
   OAuth routes and client-authentication mechanisms.
2. Normalize parameters only after client authentication and signature/claim
   validation. With a request object, use inner authentication parameters only,
   as measured in node. Reject nested requests, encryption, unsupported/none/HS
   algorithms and malformed or oversized compact JWTs.
3. Require the six standard claims, client issuer and OP audience membership.
   Reject invalid time types, future nbf, expired exp, empty jti and future iat.
   Empty-jti/future-iat rejection will be explicit stricter differences from the
   measured default, rather than undocumented assumptions about node.
4. Convert only defined representations: requested_expiry number/string;
   claims object and authorization_details array to their existing parsers;
   resource string/array to the existing resource validator. Other standard
   authentication fields remain strings. Preserve exactly-one-hint validation.
5. Do not use the client-assertion replay ledger for request objects. Under the
   node-compatible default, a repeated valid signed request creates a fresh
   request requiring new approval; it neither retrieves nor reuses an earlier
   grant. Document this delivery/retry behavior and retain normal rate controls.
6. Keep raw request JWTs, client authentication parameters and JOSE metadata out
   of persisted device snapshots and observation events. Only validated CIBA
   inputs enter the existing request/consent lifecycle.

Required verification: local negative tests and actual issuance; all existing
DB/Ruby matrix entries; independent reference scenarios above; installed-gem
signed-request smoke; Discovery/client metadata and migration tests; signing
key selection/rotation, request versus client-assertion separation, malformed
JSON and outer-parameter confusion checks. Remote JWKS transport/cache failures
and multiple feature-enable orders require explicit coverage, not inference
from a static in-memory key fixture.


## Algorithm acceptance audit

The dedicated `test/reference/full-op/signed-algorithms.mjs` runs the released
provider with explicit RS256/384/512, PS256/384/512 and ES256/384/512 request
algorithms. All nine accept the registered key and reject a distinct signing
key. [Node log](../validation/node-signed-algorithms.txt). The gem exercises the
same algorithm set, a five-part encrypted shape rejection, and numeric-date type
rejections. Its six signed-request tests pass128 assertions on Ruby4.0.6/SQLite.
[Gem log](../validation/signed-request-audit-current.txt). No runtime code changed.
These algorithm cases prove initiation validation, not full issuance with each
algorithm. Reference Ed25519/EdDSA remains outside the gem's enabled algorithm
set and is an unresolved alignment difference.
