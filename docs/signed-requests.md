# Optional signed CIBA requests

Run the explicit client-metadata migration once:

```ruby
Rodauth::CibaSupport::Schema.add_signed_requests(db)
```

It adds nullable `backchannel_authentication_request_signing_alg` to
`oauth_applications` without modifying pending requests or existing grants.
Custom schemas may supply `table:` and `column:`; configure the matching
`oauth_applications_backchannel_authentication_request_signing_alg_column` in
Rodauth. Client verification keys use upstream `jwks` or `jwks_uri` metadata;
the migration does not add those upstream columns.

Enable explicitly, then register each signing client's algorithm and public keys:

```ruby
ciba_request_signing_algorithms ["RS256"]
```

The default is an empty list. Discovery publishes
`backchannel_authentication_request_signing_alg_values_supported` only when
enabled. Asymmetric RS/PS/ES algorithms and Ed25519/EdDSA (Ed25519 curve) may be configured. RS256 has actual
request-issuance and installed-gem tests. All nine configured RS/PS/ES variants
have direct acceptance/wrong-key tests in both gem and reference OP; installed
issuance coverage for the other variants remains absent. Opt-in DCR composition
is tested separately. Ed25519/EdDSA now use CIBA-local OpenSSL verification with strict OKP/Ed25519 key import; registration, Discovery, wrong-key rejection and approved issuance are tested. Other OAuth routes and
their JAR/client-authentication policy are unchanged.

A client with a registered signing algorithm must send `request`. The gem also
rejects signed requests from clients without a registered algorithm. Algorithm
selection is pinned to that registration and the enabled list; header values
cannot choose another algorithm. Missing/invalid signed requests return
`invalid_request`; a client registered for a disabled algorithm is ineligible
(`unauthorized_client`), including for collection of pending results. Keep the
algorithm enabled until those results have been collected or expired.

The client authenticates independently using its registered method. The request
JWT cannot substitute for a client assertion, and does not enter the client
assertion replay ledger. Verification keys come only from the authenticated
client's registered JWKS. The verifier filters key type, kid, optional alg/use
and key_ops; unknown keys, encrypted objects, none/HS algorithms and unsupported
critical headers are rejected. JWT header key URLs are never used. Registered
remote JWKS lookup/cache behavior is delegated to upstream. Loopback HTTP tests
use a narrowly allowed test receiver; actual fetches now pass through the
[CIBA outbound HTTP boundary](outbound-http.md). Default private/loopback access
is rejected without sending a receiver request. Existing cache semantics remain.
The tests
exercise actual Net::HTTP fetching, no-cache and max-age caching, key rotation,
malformed/empty responses, HTTP 503 and connection refusal. Unknown kid does not
force a cached JWKS refresh. Publish new keys before using them, retaining old
keys during the cache overlap; removing a key does not revoke cached copies.
After explicit upstream cache invalidation, tests verify the new key is accepted
and the removed key rejected. This does not simulate natural TTL passage, TLS,
production DNS, redirects or multi-process cache invalidation.

During this signature-key lookup only, upstream HTTP authentication halts and
network failures become `invalid_request`, without saving a pending request.
An actual wrong client credential still returns 401. Before this adaptation,
upstream HTTP 503 misleadingly returned 401 and connection refusal returned 500.
The normalized error is a gem policy; node source can propagate
`invalid_client_metadata` from its remote-key refresh. It is not a claim that
all remote-key error responses are identical across the two libraries.

Signature verification precedes account resolution and persistence. Require
client issuer, OP audience membership, finite numeric exp/iat/nbf and string jti. Fractional NumericDate values are accepted. Time checks use
`oauth_jwt_iat_leeway`; exp must remain valid and nbf must not be in the future
beyond that tolerance. Like the reference, a future iat alone does not reject
a signed request with valid exp/nbf. JSON duplicate members,
malformed encodings, nested request/request_uri and payloads beyond the existing
HTTP body limit are rejected. Like the reference, jti must be present and a
string, but the OP does not require it to be nonempty or implement request-JWT
replay consumption. Clients remain responsible for unique identifiers.

After verification, only inner CIBA parameters are passed to the normal
validator. Outer authentication parameters do not fill gaps or override signed
values, matching the reference's treatment of nonconforming outer input.
requested_expiry accepts an integer or string; claims objects, authorization
details arrays and resource arrays enter their existing optional-feature
validators. Exactly one enabled hint is still required. Raw request JWTs and
authentication parameters do not enter saved requests, device snapshots or
observation events. Applications must redact original HTTP logs separately.

Like the reference default, submitting the same still-valid signed JWT again
creates a **new pending authentication request**, not an idempotent lookup or
reuse of an approval. Normal client/request rate controls remain necessary.
Each accepted request needs its own new customer approval and retains the
existing one-time token collection and replay-revocation behavior.

See [reference evidence](research/signed-request-reference-contract.md),
[local tests](validation/signed-request-tests.txt) and the installed-gem
`examples/extensions_smoke.rb`. Production remote-JWKS scenarios, all feature-enable
orders, Edwards HTTPS key rotation, installed issuance with all algorithms and broader dynamic-registration combinations remain incomplete;
passing these cases is not full node parity or CIBA certification.

### Edwards request signatures

Configure `ciba_request_signing_algorithms %w[Ed25519 EdDSA]` and register the exact
algorithm used in the JWT header. Both names use an OKP JWK with crv=Ed25519 and
an unpadded base64url 32-byte public x value. X25519 and Ed448 are not accepted.
The key's alg, use, key_ops and kid restrictions still apply. Private material
is rejected by dynamic registration. ID Token signing, client assertions and
non-CIBA JWT processing are not enabled for these algorithms by this setting.

Verification uses Ruby OpenSSL PKey verification without prehashing and imports
the public key as [RFC8410 SubjectPublicKeyInfo](https://www.rfc-editor.org/rfc/rfc8410.html#section-4),
using [OpenSSL PKey verification](https://docs.ruby-lang.org/en/master/OpenSSL/PKey/PKey.html#method-i-verify). It adds no JWT global algorithm
registration or native dependency. The existing bounded parser, required claims,
issuer/audience/time validation and per-request approval boundary remain shared
with RSA/EC requests.

[Three-DB regression](validation/edwards-request-matrix.txt): each11 tests /
234 assertions pass. [Reference11 algorithms](validation/node-signed-edwards.txt)
includes acceptance and wrong-key rejection. Node/jose-generated fixed vectors now pass with inline and actual HTTP remote
JWKS on all three DBs; modified payloads fail without creating requests.
[Vector/remote regression](validation/edwards-vectors-matrix.txt): each4 tests /
108 assertions. The built and isolated installed gem also accepts both fixed
vectors with opaque/JWT access-token settings and verifies the returned ID Token
([installed artifact](validation/edwards-installed.txt)). The installed Edwards
fixture uses inline keys; remote Edwards HTTPS rotation is not covered by it.

The public fixtures are `examples/fixtures/edwards-requests.json`, generated by
`test/reference/full-op/edwards-vectors.mjs` with the pinned Node/jose dependency.
They contain no private keys. Their fixed clock is injected only by tests and
the smoke example; production time validation is unchanged. Regeneration is a
separate explicit command, so normal test runs verify the saved foreign-generated
signature bytes rather than signing fresh inputs with the Ruby implementation.

## NumericDate alignment

[CIBA Core7.1.1](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1)
requires exp, iat and nbf on signed requests.
[RFC7519 section2](https://www.rfc-editor.org/rfc/rfc7519.html#section-2)
defines NumericDate to allow non-integer values. The previous integer-only
validation and additional future-iat rejection were extra gem restrictions.

Provider9.12.2 over HTTP accepts fractional dates and future iat, while rejecting
malformed iat, future nbf and expired exp. The gem now matches that boundary;
mandatory claims, asymmetric signature checks and explicit customer approval
remain required. This change is scoped to signed CIBA request objects, not
upstream client assertions or ID Token hints.

[Reference execution](validation/node-signed-numericdate.txt),
[gem before correction](validation/signed-numericdate-red.txt),
[three-DB regression](validation/signed-numericdate-matrix.txt).

## Request jti versus client assertion replay

The reference accepts an empty-string jti on signed authentication requests and
rejects null/non-string values. The gem now matches that type/presence check.
This acceptance rule does not advise clients to generate empty identifiers or
remove their obligation to generate unique request identifiers. Repeating the
same signed request produces a fresh auth_req_id and approval-pending state,
including when its first request has already issued tokens. No approval or
permission is inherited from the repeated JWT.

Client authentication assertions are a separate JWT use: their existing nonempty
jti requirement and atomic replay rejection remain unchanged.
[Reference](validation/node-signed-jti.txt),
[before correction](validation/signed-jti-red.txt),
[three-DB regression](validation/signed-jti-matrix.txt).
