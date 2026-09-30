# Optional ID Token hints

Enable `ciba_id_token_hint_enabled true` and implement
`resolve_ciba_id_token_subject(subject, oauth_application:)`. The callback receives
a cryptographically verified subject (public or enabled pairwise) and the authenticated client record;
return the corresponding local account ID or nil. Do not assume custom public
subjects are database primary keys. Normal account eligibility and subsequent
approval/account/client binding checks still apply. No migration is needed.

Exactly one of `login_hint`, enabled `login_hint_token`, or enabled `id_token_hint`
is accepted. ID Token hints are limited to 8192 bytes. Raw hints are removed before
request persistence, transaction hooks, device snapshots and observation events.
Applications must separately redact incoming HTTP parameters in their own logs.

The dedicated hint verifier uses the authenticated client's configured ID Token
signing algorithm, falling back to the OP's first signing algorithm as the issuer
does. It checks signature, issuer, audience membership and a string subject.
Like the reference hint verifier, it ignores expiration and does not require iat
or exp. If present, iat/nbf must be numeric; fractional values are accepted. Future
nbf is rejected with the configured leeway. Future iat is rejected only when exp
is absent. A present jti must be a string. Supported algorithm families
are RS, PS, ES and HS; all twelve256/384/512 variants have actual issuance,
current/expired reuse and wrong-key rejection tests.
Unsigned and encrypted hints are not supported. A valid nested encrypted hint
is rejected before subject resolution, matching the measured node-oidc-provider
9.12.2 CIBA behavior even with its encryption feature and OP key configured.

Asymmetric keys come from `oauth_jwt_public_keys[algorithm]`, falling back to
`oauth_jwt_keys[algorithm]` only when no public-key entry exists. Arrays retain
old verification keys. A supplied kid must match the trusted key's JWT::JWK kid;
without kid all configured keys for the pinned algorithm may be tried. No token
URL or embedded key is fetched or trusted. Removing a key stops acceptance of
hints signed by it. CIBA HMAC issuance and hint verification use the authenticated
client's secret, matching the reference. See the secret retrieval contract below.

Expiration is ignored **only in this dedicated hint verifier**. By default
`ciba_id_token_hint_max_age nil` leaves age unrestricted while keys remain
trusted, matching the measured node behavior. Set a positive integer number of
seconds to limit age from iat. This is separate from expiration and does not
alter normal access-token or client-assertion validation.

The hint path now matches the measured reference's azp and typ handling: neither
is used to reject a hint. Registered algorithm, trusted key, issuer and client
audience remain mandatory. The recognized JOSE critical declaration b64=true
is accepted; unknown critical extensions and unencoded JWT payloads are rejected.
This change is isolated to hints; access-token, signed-request and client-assertion
validation is unchanged. With an explicit ciba_id_token_hint_max_age, iat is
required to evaluate that application age policy. Optional [pairwise subjects](pairwise.md)
use the same resolver boundary to map the verified subject to a canonical account.

The reference even ignores the type of exp in this identity-hint path. This is
not a contract for issuing malformed ID Tokens or accepting them as authentication
results. The regression re-signs controlled variants and proves they still only
create pending requests. [Reference](validation/node-id-hint-validation-profile.txt),
[three-DB regression](validation/id-hint-validation-matrix.txt).

Successful hint validation creates a pending request, not an approval or token.
New customer authentication/approval remains mandatory. See the
[reference measurements](research/id-token-hint-reference-contract.md) and
[local tests](validation/id-token-hint-tests.txt). The later
[encrypted-hint boundary test](validation/encrypted-hint-boundary.txt) and
pairwise integration tests extend that evidence. Edwards ID Token support is explicitly configured as described below; arbitrary
application resolver correctness remains outside the verified scope.

## Complete configured RS/PS/ES/HS matrix

The updated test verifies each actually issued ID Token using its configured
key, issuer and audience, then tests current and expired reuse as hints. Neither
form inherits approval; a token signed by a different key is rejected before
request persistence. The HMAC client-secret negative case explicitly selects
HS256 first, so it tests wrong key ownership rather than only algorithm mismatch.
[Three databases](validation/id-hint-algorithms-matrix.txt): seven tests /229
assertions per DB, no failures/errors/skips.

The independent reference matrix now covers those twelve plus Ed25519/EdDSA
([execution](validation/node-id-hint-algorithms.txt)). Edwards issuance/hint verification was a concrete remaining gap; the initial
implementation below addresses it separately from request-object/client-assertion verification.

## Explicit Edwards ID Token keys

Configure `ciba_id_token_signing_keys` with `"Ed25519"` and/or `"EdDSA"` entries
containing an OpenSSL Ed25519 private key. Default is an empty hash. The client
must explicitly select the matching `id_token_signed_response_alg`; the ordinary
OP default signing algorithm is unchanged. Each entry may instead be an array:
the first key signs new ID Tokens, and later public/private keys are retained
for hint verification. The first key must be private and all keys must be Ed25519.

The shared JWKS publishes only public OKP material with RFC7638-derived kid, alg
and sig use; existing upstream keys remain present. Discovery adds the configured
ID Token algorithms. CIBA issuance signs with the selected key, and hints verify
with the same configured/retained public keys. Removing a retained key prevents
acceptance of its hints. Hint issuer/audience/subject/time checks and new-approval
requirements remain in force. This does not change JWT access-token signing.

The gem continues to include at_hash, using the left half of SHA-512 for Edwards.
The reference's CIBA token-endpoint default omits this optional claim; its
ID Token model maps both Edwards algorithm names to SHA-512 when hashing is
requested. This is not a claim that their default claim sets are identical.

Edwards ID Tokens can use the optional [recipient encryption](id-token-encryption.md)
path. Without that enabled capability, an encryption selection raises
ConfigurationError instead of emitting plaintext and keeps approval available.
Independent Node verification, installed artifact and supported-Ruby evidence for
signed output is recorded in the [contract](research/id-token-hint-reference-contract.md).
Encryption has its own narrower evidence and remaining integration work.
[Initial14-test three-DB regression](validation/edwards-id-token-matrix.txt),
[final Edwards/rollback cases](validation/edwards-id-token-final-matrix.txt).

## HMAC client-secret ownership

CIBA ID Tokens signed with HS256/HS384/HS512 now use the UTF-8 client secret for
both issuance and hint verification, as required by
[OIDC Core ID Token validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation).
The algorithm is still selected by registered `id_token_signed_response_alg`
or the upstream default, and must be configured among the supported signing
algorithms. OP-wide HS keys are not a fallback for a missing client secret.
Non-CIBA JWT encoding and JWT access-token signing retain upstream key handling.

After successful client_secret_basic/client_secret_post authentication, the
verified secret is retained only on that request's Rodauth instance, bound to
the authenticated application's ID. This works with hashed DB storage; no new
plaintext persistence is introduced. With explicitly configured plaintext
client-secret storage, other authentication methods can use the stored secret.
For hashed storage plus private_key_jwt/mTLS, supply an application secret lookup:

```ruby
ciba_id_token_hmac_secret do |oauth_application:|
  secrets.fetch(oauth_application.fetch(:client_id)) # application's secret store
end
```

The callback must return that client's original secret, not its password hash
or an OP signing key. Missing/non-string secrets and insufficient key length
fail issuance with rollback; they do not produce an ID Token with another key.
Minimum byte lengths are 32/48/64 respectively, following
[JWA section 3.2](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2);
secret entropy and secure storage remain application responsibilities.
Current-secret rotation changes both new issuance and accepted HMAC hints.

This replaces the unreleased implementation's OP-key HMAC behavior. Previously
issued OP-key HMAC hints are no longer accepted unless that key is actually the
client secret. Do not configure a shared OP key as every client's secret to
preserve those tokens.

[Three-DB tests](validation/hmac-id-token-matrix.txt) cover Basic/POST,
plaintext/hashed storage, all three HS algorithms, initial issuance/refresh,
current/expired hints, wrong OP key rejection and missing/short callback rollback.
[Full local regression](validation/hmac-id-token-full.txt) passed353 tests before
the additional registration-length case below.

The installed [HMAC smoke](../examples/hmac_id_token_smoke.rb) exercises all
three algorithms with plaintext/hashed secret storage and opaque/JWT access
tokens. It verifies initial issuance, refresh, hints and rejection of the OP key.
Replacing the stored client secret rejects old authentication and old HMAC hints;
existing refresh credentials issue with the new secret after new authentication.
This is a backend replacement fixture, not a standard secret-rotation endpoint
or a measurement of reference cache propagation.
[Installed artifact evidence](validation/hmac-id-token-installed.txt),
[Ruby 3.3/3.4 evidence](validation/hmac-id-token-rubies.txt).

### Dynamically generated secret length

Upstream's default generated secret is43 encoded bytes, insufficient for HS384
and HS512 signing. A [regression](validation/hmac-registration-secret-red.txt)
reproduced the HS384 failure. For CIBA registration only, the gem now replaces
an insufficient generated secret with fresh cryptographic randomness sized for
the selected algorithm, using the upstream secret setter to preserve configured
hash storage. HS256 and unrelated clients keep their existing generation path.
This applies whether or not management-token issuance is enabled.
[Three-DB regression](validation/hmac-registration-secret-matrix.txt) verifies
registration, hashed storage, authenticated CIBA issuance and client-secret
signature validation for all three algorithms. The
[reference registration fixture](validation/node-hmac-registration-secret.txt)
also produces secrets meeting the algorithm's minimum length.
