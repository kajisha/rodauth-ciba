# Configured client assertion algorithm matrix

This comparison explicitly configures twelve advertised authentication algorithms:
RS256/384/512, PS256/384/512, ES256/384/512 and HS256/384/512. The first nine use
private_key_jwt; the HMAC algorithms use client_secret_jwt and a64-byte client
secret. Shared-secret authentication requires upstream's plaintext-secret mode;
this fixture is not a recommendation to weaken an existing hashed-secret store.

Both actual node9.12.2 HTTP endpoints authenticate each configured algorithm and
reject the wrong key. Token collection while pending returns authorization_pending
only after successful client authentication. The Ruby integration additionally
approves each request and obtains a signature/issuer/audience-verified ID Token.
Wrong audience or issuer and wrong keys do not create/consume the request. The
HMAC wrong key is the OP key, ensuring the client secret is the verification key.

The matrix checks that Discovery's algorithm list equals the configured list;
it does not infer algorithm support solely from a generic JWT library constant.
The shared metadata test separately checks OAuth/OIDC equality. Basic/post and
actual TLS authentication remain in their dedicated fixtures, not this JWT test.

- [Pinned reference](../validation/node-client-auth-algorithms.txt)
- [Gem local:1 test /137 assertions](../validation/client-auth-algorithms-current.txt)
- [Three-DB execution](../validation/client-auth-algorithms-matrix.txt)

This resolves the missing matrix for these configured algorithms. It does not
establish all combinations of load order, management updates or sender-bound
access tokens. CIBA signed-request Ed25519/EdDSA support does not imply Edwards
client assertion support; the latter still follows upstream JWT capabilities.
The upstream metadata also includes a legacy JWT assertion-type URN as an
advertised method when plaintext secrets are enabled. This test does not claim
that URN can independently serve as a registered CIBA authentication method;
the registration defect is now fixed as described below. The later metadata correction below removes only the unusable URN; actual
upstream authentication dispatch remains unchanged.

## Legacy assertion-type URN is not a registered authentication method

The gem previously accepted the JWT assertion-type URN as the sole registered
CIBA authentication method. Upstream dispatch subsequently required the actual
private_key_jwt or client_secret_jwt method, leaving this registration unusable.
The red test records HTTP201 for that invalid configuration. The pinned reference
instead rejects it at HTTP registration.

CIBA eligibility now explicitly excludes this URN. Opt-in DCR and management
candidate validation reuse that boundary; the normal JWT assertion_type request
parameter remains accepted with the real registered authentication method.
At that stage shared Discovery advertisement was left unchanged. The later
correction below removes the URN from the advertised list without rewriting
non-CIBA authentication dispatch.

[Red regression](../validation/client-auth-urn-red.txt),
[reference rejection](../validation/node-client-auth-urn.txt),
[three-DB regression](../validation/client-auth-urn-matrix.txt).

## Confirmed Edwards client-authentication gap

The reference matrix now configures fourteen algorithms, adding Ed25519 and
EdDSA. Both authenticate the backchannel and token endpoints; wrong keys return
401 at each. This is separate from signed authentication request verification.
[Reference execution](../validation/node-client-auth-edwards.txt).

The initial explicit gem probe (now promoted into
[regression tests](../../test/ciba_edwards_auth_test.rb)) signs with
OpenSSL, registers an OKP Ed25519 client key and pins each authentication
algorithm. Both algorithms initially returned401 invalid_client at both endpoints
([red execution](../validation/client-auth-edwards-red.txt)). Each token test has
its own pre-approved request, avoiding replay from masking authentication.
That initial failing probe was not counted among the331 passing regression
tests. The implementation increment below replaces it with passing regressions.

Upstream dispatch correctly selects private_key_jwt for non-HMAC algorithms.
The missing boundary is JWT/JWK verification: the CIBA private-key method passes
client keys to the upstream JWT backend, while the existing Ed25519 public-key
importer is used only for signed CIBA requests. Authentication algorithm metadata
also derives from upstream OP signing keys; adding an Edwards verifier alone
would leave registration/Discovery incomplete.

The next implementation must provide explicit authentication-algorithm
configuration and matching metadata, use client OKP keys (never OP fallback),
retain audience/issuer/subject/expiry/nbf checks and assertion replay protection,
and exercise wrong keys, registered algorithm mismatch, inline/remote keys and
non-CIBA behavior. Edwards ID Token signing is a separate boundary and must not
be advertised as a side effect of client authentication support.

## Initial Edwards authentication implementation

`ciba_client_assertion_signing_algorithms` is optional (default nil retains
upstream-derived registration defaults). An explicit array configures the CIBA
client assertion algorithms independently of OP token-signing keys. For example,
`%w[RS256 Ed25519 EdDSA]` permits those algorithms for CIBA clients. OAuth and
OIDC Discovery add these capabilities to the upstream authentication list; they
do not remove upstream capabilities or alter ID Token algorithm advertisement.

Edwards verification uses the existing local RFC8410 Ed25519 importer with the
client's registered OKP key. It checks exact alg/curve, kid, use, key_ops, signature
length and signature over the original compact bytes. No global ruby-jwt
algorithm or OP signing key is installed. Unknown critical headers and duplicate
JSON fields are rejected. Shared issuer/subject/expiry/iat/audience checks and
atomic assertion replay storage remain in the existing authentication wrapper;
the Edwards decoder additionally validates nbf.

DCR accepts the algorithms only when explicitly enabled for private_key_jwt and
rejects them for client_secret_jwt. The two new tests check Discovery, registration,
both endpoints, wrong signing keys, key metadata, malformed/future nbf, expiry,
issuer/audience and replay. The existing twelve-algorithm test remains in the
regression subset. [Three-DB execution](../validation/client-auth-edwards-matrix.txt).

The follow-up below adds remote keys, ordinary-flow coexistence and installed
artifact evidence. Full authentication-workstream completion is not inferred.

## Remote keys and installed authentication follow-up

A real HTTP JWKS fixture now exercises both Edwards algorithm names. A live cache
retains its old key, explicit cache invalidation switches to the replacement key,
and the old signature then fails. This is deterministic cache expiry, not a
wall-clock TTL measurement.503 and invalid JSON reject authentication without
creating requests or consuming the saved approval; recovery permits token
collection with a signature-verified ID Token. Each CIBA-capable client also
authenticates a normal authorization_code token exchange using its Edwards key.

[Three-DB execution](../validation/client-auth-edwards-remote-matrix.txt): five
related tests /247 assertions per DB, no failures/errors/skips. The reference
fixture independently fetches real HTTP remote JWKS for both Edwards names and
rejects wrong keys at both CIBA endpoints
([execution](../validation/node-client-auth-edwards-remote.txt)). Its new remote
cases do not claim identical rotation/failure-cache policy.

The installed artifact smoke adds Edwards authentication at both endpoints,
assertion replay rejection, customer approval, opaque/JWT access tokens and
verification of the OP's RS256 ID Token. The sample explicitly creates the
client assertion replay table before enabling authentication.
[Installed execution](../validation/client-auth-edwards-installed.txt).
This authentication smoke uses inline keys; HTTPS Edwards client-key retrieval
in the installed package is not established by it.

The full suite on Ruby3.3 and3.4 now passes334 tests /4,316 assertions per
version, with the existing two SQLite row-lock skips
([execution](../validation/client-auth-edwards-rubies.txt)). The installed artifact
includes this contract document and passes the package-presence check; SHA256
`d43fd74be78fc8f615a8f6125488af244dda284820ae723293696d20c6d61edf`.
That artifact predates this results paragraph; implementation is unchanged.

## Installed HTTPS retrieval and configuration scope

The installed TLS fixture now serves Edwards client JWKS over HTTPS for both
algorithm names and both opaque/JWT configurations. Default loopback filtering
rejects retrieval before the handler; the fixture then allows exactly its owned
loopback address while preserving certificate verification. Trusted TLS permits
authentication at both endpoints and issuance of a verified ID Token. A separate
process without trust in the fixture CA rejects authentication without any key
handler access or persisted CIBA request. JWKS requests are GETs without forwarded
authentication credentials.
[Execution](../validation/client-auth-edwards-https-installed.txt), SHA256
`d99ffb61d2645e040b3a7ab1bbc0240e38c743d778a978d37aa9717020ac1a4c`.
This artifact predates this report paragraph.

The configuration-scope regression sets the CIBA list to Edwards only, then
authenticates an unrelated RSA authorization_code client. It succeeds without
CIBA request or replay-ledger writes; shared Discovery retains RS256 alongside
the explicitly added Edwards capabilities.
[Three DBs](../validation/client-auth-edwards-scope-matrix.txt): five tests /114
assertions each, no failures/errors/skips. This closes the configured-method
coverage gap. The remaining legacy-URN metadata mismatch is corrected below.

## Shared authentication-method metadata correction

OAuth/OIDC Discovery now removes the assertion-type URN from
`token_endpoint_auth_methods_supported`, matching the reference. Both discovery
documents retain the same remaining list. The underlying upstream method list
and dispatch are untouched: no authentication mode is globally disabled, and
ordinary RSA clients still authenticate. The normal client_assertion_type
parameter remains required for JWT assertions.

[Initial mismatch](../validation/client-auth-metadata-urn-red.txt),
[reference Discovery and registration](../validation/node-client-auth-metadata-urn.txt),
[three DBs](../validation/client-auth-metadata-urn-matrix.txt): four tests /162
assertions each, including existing twelve-algorithm authentication and normal
OAuth coexistence. This resolves CIBA-007 for the configured metadata boundary.
