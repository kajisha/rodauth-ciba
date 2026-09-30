# ID Token hint validation boundary

2026-09-30. Complete node-oidc-provider 9.12.2 HTTP comparison on Node24.21.0, with an actual issued RS256 ID Token and controlled, re-signed test variants. The original comparison established the implementation contract below. An optional gem implementation now exists; see [its validation policy and remaining differences](../id-token-hint.md).

## Measured reference behavior

| Input | Result |
|---|---|
| Previously issued ID Token | Authentication request accepted with the original account; polling remains authorization_pending until new approval |
| Correctly signed ID Token expired one hour ago | Accepted as a hint; still needs new approval |
| Audience array containing the authenticated client and another value | Accepted |
| Correct audience but azp naming another client | Accepted: this version's helper does not validate azp |
| Different issuer or audience excluding the current client | invalid_request |
| Missing subject or future nbf | invalid_request |
| Modified signature | invalid_request |

[Harness](../../test/reference/full-op/lifecycle.mjs), [execution log](../validation/node-full-op-lts.txt). Existing hint-token, resource, claims, RAR and lifecycle scenarios still pass. These tests use one public-subject/RSA configuration; they do not establish HMAC, key rotation, encrypted-hint or pairwise-subject support.

`lib/models/id_token.js#validate` chooses the client's configured ID Token signing algorithm, uses the client's symmetric keystore for HS algorithms or the OP keystore otherwise, and verifies the signature, OP issuer, current client audience and string subject while ignoring expiration. `lib/actions/authorization/ciba.js` then resolves the subject as an account and performs the normal new CIBA flow. `lib/helpers/jwt.js#verifyAudience` checks audience membership but does not use the extra ignoreAzp argument passed by its caller. Record that fact rather than assuming azp is checked from the argument name.

[CIBA Core §14](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#SecurityConsiderations) distinguishes a returned ID Token hint from ordinary token use: it discusses accepting expired ID Tokens for a reasonable period while checking issuer, client audience and signature, subject to key retention. This does not make an old ID Token a fresh authentication/authorization result. An implementation needs an explicit hint-validation policy, not globally relaxed access-token verification.

## Upstream integration finding

In the installed rodauth-oauth 1.7.0 ruby-jwt path, `jwt_decode(..., verify_claims: false)` is insufficient to accept expired hints. A local probe signed two otherwise identical tokens with the fixture OP key, one expiring in 60 seconds and one expired one hour ago. The former returned claims and the latter nil. `verify_claims: false` supplies an empty options hash to JWT.decode; ruby-jwt's expiration default still applies. RP-initiated logout uses this method too, but that usage is not evidence of the required CIBA hint semantics.

Do not change the OP-wide decoder to accept expired tokens. Use a dedicated validation path with explicit signature, algorithm and claim rules and an explicit expiration policy for this parameter only. Do not reuse the backchannel client-authentication assertion ledger: an ID Token hint is not a client assertion and is not a one-use authorization grant.

## Required gem work

1. Add an opt-in capability while preserving default login_hint and optional login_hint_token. Require exactly one hint; do not store raw ID Tokens in request snapshots/events.
2. Pin validation to the authenticated client's configured ID Token signing algorithm and trusted OP verification keys (or the correct client symmetric secret for HMAC). Define retained-key/kid behavior. Never select verification keys from untrusted token URLs or silently verify without a key.
3. Validate the OP issuer, current client audience membership, subject shape and applicable time claims explicitly. Specify how old an expired hint may be and how retained keys limit acceptance. Decide and test azp semantics rather than mechanically copying the reference's omission.
4. Map the validated public subject to an eligible local account through a documented boundary; custom subject encodings cannot be assumed to be account primary keys. Pairwise remains outside the current profile unless its mapping is separately implemented.
5. Preserve new customer approval, saved-grant account/client binding, request expiry and one-time result consumption. Poll parameters must not replace the selected subject. A successful hint check alone issues no tokens.
6. Test current/expired hints, wrong issuer/client/key/algorithm, malformed/empty subject, future nbf/iat, multiple hints, unknown/closed accounts, stale signing keys and ordinary access-token expiration regression. Include reference and installed-gem evidence before advertisement.

The dedicated verifier, HMAC key-source adaptation, retained-key selection and optional maximum age are now implemented and covered by gem integration tests. Pairwise subjects have a separate opt-in implementation and application resolver tests in `test/ciba_pairwise_test.rb`. The requirements above remain review criteria; local passing tests do not establish all node configurations or algorithms.

## Encrypted hint boundary: correction after direct measurement

The earlier status treated encrypted hints as a presumed missing parity feature.
The pinned reference implementation does not decrypt them: `IdToken.validate`
calls the JWS verifier directly, including in the CIBA route. The presence of
generic JWT decryption helpers or encrypted ID Token issuance does not establish
encrypted-hint acceptance.

The full HTTP harness now enables node's encryption feature and configures a
private OP encryption key. It wraps an actual issued RS256 ID Token in a valid
RSA-OAEP-256/A256GCM JWE with `cty: JWT`, and independently decrypts the envelope
to verify the fixture. Supplying it as `id_token_hint` returns HTTP400
`invalid_request` before device dispatch. Its inner signed token is accepted as
a hint requiring new approval. The complete lifecycle harness still passes.
[Reference log](../validation/node-encrypted-hint-reference.txt).

The gem test similarly constructs and authenticates a real nested JWE using
OpenSSL, configures an OP encryption key, and checks rejection before subject
resolution or request creation. The unwrapped signed hint is accepted and stays
pending. All seven local hint tests pass (100 assertions).
[Gem log](../validation/encrypted-hint-boundary.txt).

Encrypted hints remain unsupported in both measured implementations; this is a
verified shared boundary, not an outstanding feature needed to match v9.12.2.
No production decryption code or new gem dependency was added. These tests do
not cover encrypted ID Token issuance, every encryption algorithm, or upstream
Ruby's optional JWE backend; they establish the dedicated CIBA hint boundary.

## Actual-issuance algorithm comparison

A dedicated reference HTTP fixture now issues and cryptographically verifies
ID Tokens for RS256/384/512, PS256/384/512, ES256/384/512, HS256/384/512,
Ed25519 and EdDSA. Current and expired hints create only pending requests;
wrong-key signatures reject. It is part of the reference npm test command.
[Fixture](../../test/reference/full-op/id-hint-algorithms.mjs),
[execution](../validation/node-id-hint-algorithms.txt).

The gem's actual-issuance matrix now covers all twelve RS/PS/ES/HS choices,
including independent signature/issuer/audience verification, forged-signature
rejection before persistence and pending state for current/expired hints.
[Three-DB execution](../validation/id-hint-algorithms-matrix.txt): seven tests /229
assertions per database. At that stage the gem used OP HMAC keys while the
reference used client secrets. The later correction below changes CIBA issuance
and hint verification together, rather than conflating those key stores.

At this comparison stage, the dedicated hint verifier accepted only those
twelve algorithms. The initial adapter below subsequently adds Edwards. Edwards request and authentication support does not close
that gap. Token issuance, published verification keys and hint verification
must be evaluated together before expanding the accepted hint list.

## Initial Edwards issuance and hint adapter

The CIBA extension now has a separate optional Ed25519/EdDSA ID Token key map,
without registering a global ruby-jwt algorithm or adding signing keys to the
upstream default map. It publishes public OKP keys, advertises configured ID
Token algorithms, signs CIBA ID Tokens and reuses the local Edwards signature
verifier for hints. Client assertions reuse that cryptographic helper while
retaining their distinct claims/time/replay policy.

Registration without configured keys rejects. Issued signatures, public-key
bytes, at_hash, current/expired hints, wrong key, issuer/audience/subject/nbf and
retained/removed keys have direct regression evidence. The reference default
CIBA token response omits at_hash; a proposed test requiring it failed and was
corrected to assert absence. Its `lib/models/id_token.js` maps Ed25519/EdDSA to
SHA-512 when calculating optional token hashes. The gem retains its existing
at_hash inclusion policy and uses that mapping.

[Three-DB regression](../validation/edwards-id-token-matrix.txt),
[final rollback cases](../validation/edwards-id-token-final-matrix.txt).
This is an initial runtime implementation, not complete interoperability or
encrypted-token support. An encryption request fails closed rather than silently
returning a signed plaintext token. Broader integration evidence is recorded
below; encrypted ID Token issuance remains unsupported.

## Independent Edwards verification of the installed gem

`examples/edwards_id_token_smoke.rb` now runs from `bin/verify-package`, issuing
both algorithm names with opaque and JWT access tokens. Its optional
`CIBA_EDWARDS_ID_TOKEN_EXPORT` absolute path exports synthetic tokens and public
JWKS only. The keys are ephemeral and private key material is never exported.
`test/reference/full-op/verify-gem-edwards-id-tokens.mjs` independently verifies
all four cases using Node jose: signature, fixed expected issuer/audience/subject,
JWK thumbprint, SHA-512 at_hash, tampered payload rejection and wrong audience
rejection. A saved public fixture supports repeatable offline execution; its
recorded issuance-check time is used, not a claim of current token validity.

Reproduce fresh evidence by setting the export path to
`test/reference/full-op/fixtures/gem-edwards-id-tokens.json` (absolute) when
running `mise exec ruby -- ruby bin/verify-package`, then run
`node verify-gem-edwards-id-tokens.mjs` from `test/reference/full-op` with its
installed jose dependency. The default fixture is explicit historical evidence;
regenerate it to verify a changed Ruby implementation.

[Installed package execution](../validation/edwards-id-token-installed.txt)
and [independent jose execution](../validation/edwards-id-token-jose.txt) passed.
This does not establish encrypted ID Token interoperability.

## Edwards refresh and pairwise integration

`test_edwards_id_token_refresh_public_subject` and
`test_edwards_id_token_refresh_pairwise_subject` exercise both Ed25519/EdDSA
with opaque/JWT access tokens. They verify the actual initial and refreshed
signatures, stable expected subject, audience, authentication time/method,
at_hash, UserInfo subject, active signing key replacement with old public key
retention, refresh rotation/replay rejection and signing-failure rollback.
Pairwise authentication uses the existing private_key_jwt path; these tests do
not replace the separate key transport coverage or assert every authentication
combination. They add integration evidence for the gem, not a new measured
comparison of these combinations in node-oidc-provider.

[Three-DB execution](../validation/edwards-id-token-refresh-matrix.txt) passes
five Edwards ID Token tests /311 assertions on each of SQLite, PostgreSQL and
MySQL, including these two new integration cases. The independent jose test
above covers initial issuance, not these refreshed tokens.

[Supported Ruby execution](../validation/edwards-id-token-rubies.txt) passes
the complete current suite on Ruby 3.3 and 3.4: 341 tests /4,774 assertions each,
zero failures/errors and two SQLite row-lock skips. This does not cover every
Ruby/database cross-product; the three-DB Edwards matrix uses Ruby 4.0.6.

## Encrypted output: measured gap and plaintext fallback correction

The reference `encrypted-id-tokens.mjs` now performs actual CIBA issuance and
refresh for RS256, Ed25519 and EdDSA clients using RSA-OAEP-256/A256GCM recipient
encryption. jose decrypts the compact JWE, checks cty/kid and verifies the inner
signature, issuer, audience and subject. [Execution](../validation/node-encrypted-id-tokens.txt)
passes all three algorithms. Encrypted output is supported by the reference;
the separately measured rejection of encrypted *input hints* does not remove
this output requirement.

Inspection of rodauth-oauth 1.7.0 `oauth_jwt_base.rb` found that the installed
ruby-jwt backend ignores encryption options when optional JWE support is absent.
Its optional JWE path can also return the signed token when no recipient key
matches. The gem previously guarded only the new Edwards branch, so configured
RSA CIBA clients could receive plaintext despite requesting encryption.
[Regression before correction](../validation/id-token-encryption-fallback-red.txt)
reproduces the unexpected 200 response with a signed three-segment ID Token.

The CIBA wrapper now requires a five-segment result with the requested alg/enc
when encrypted ID Token output is configured. Otherwise it raises a configuration
error inside the existing issuance transaction; no token is returned and the
request remains approved. The guard is limited to CIBA ID Token encoding and
does not change unrelated OAuth encoding. Complete and incomplete encryption
metadata are tested, followed by successful signed issuance after removing that
configuration. This guard is not an encryption implementation or cryptographic
verification of a JWE backend. Actual encrypted output, recipient-key selection,
metadata defaults and independent decryption remain implementation work.

[Final regression matrix](../validation/id-token-encryption-fallback-matrix.txt)
passes seven tests /350 assertions on each of SQLite, PostgreSQL and MySQL,
including Edwards issuance/refresh/pairwise and existing refresh rollback.

The subsequent optional [recipient encryption implementation](../id-token-encryption.md)
now supplies an initial successful encrypted-output path using jwe 1.1.1.
The earlier fallback correction remains for disabled/unsupported configurations.
It covers RSA-OAEP/RSA-OAEP-256 recipient encryption, six AES content methods,
Edwards/RSA signatures, initial issuance and refresh. DCR and Discovery apply
only these CIBA ID Token capabilities without widening unrelated algorithms.
[Three-DB evidence](../validation/id-token-recipient-encryption-matrix.txt):
nine tests /1,043 assertions each. [Full local regression](../validation/id-token-recipient-encryption-full.txt):
345 tests /5,506 assertions, two SQLite row-lock skips.
[Independent jose decryption](../validation/id-token-recipient-encryption-jose.txt)
checks 72 issued/refreshed tokens and ciphertext tampering. This does not close
the broader encryption capability and deployment combinations listed in the
feature document.

The encryption key-selection review subsequently found a concrete difference:
the gem selected the first eligible key, while the reference ranks matching
alg/use metadata higher. The correction preserves input order on ties and is
checked by actual issuance with two different recipient keys.
[Three-DB regression](../validation/id-token-recipient-priority-matrix.txt)
passes ten tests /1,047 assertions per database. The final source passes
[Ruby 3.3/3.4](../validation/id-token-encryption-rubies.txt), 346 tests /5,510
assertions each (two SQLite row-lock skips), and
[installed package encryption](../validation/id-token-encryption-installed.txt)
for initial issuance/refresh with RS256/Ed25519/EdDSA and opaque/JWT access tokens.
The package probe uses inline keys; it does not establish remote recipient-key
retrieval or rotation.

## Initial client-secret HMAC alignment

CIBA HMAC ID Token issuance and hints now use the client secret, matching
OIDC Core 3.1.3.7 and the measured reference. Verified Basic/POST secrets can be
reused within the authenticated request even when stored as hashes. An explicit
`ciba_id_token_hmac_secret(oauth_application:)` callback supports other methods
with application-managed original secrets. No OP-key fallback is performed;
non-CIBA JWT and access-token encoding retain their upstream key sources.
[Contract and migration boundary](../id-token-hint.md#hmac-client-secret-ownership).

[Three-DB regression](../validation/hmac-id-token-matrix.txt) passes nine tests
/421 assertions each; [full local regression](../validation/hmac-id-token-full.txt)
passes353 tests /5,829 assertions with two SQLite skips. Independent
[Node jose verification](../validation/hmac-id-token-jose.txt) verifies24 actual
gem ID Tokens across three algorithms, Basic/POST, hashed/plaintext storage,
initial issuance/refresh, rejects the OP key and checks at_hash. Its public
synthetic fixture records verification time for reproducibility and uses only
fixed test secrets. Subsequent [installed-artifact validation](../validation/hmac-id-token-installed.txt) covers12 HMAC configurations and backend secret replacement. [Ruby3.3/3.4](../validation/hmac-id-token-rubies.txt) each pass354 tests/5,847 assertions with two SQLite skips. DCR now generates sufficiently long secrets for each HMAC algorithm; the updated [three-DB subset](../validation/hmac-registration-secret-matrix.txt) passes10 tests/439 assertions each. This closes the catalog signature-verification boundary, without claiming every deployment rotation policy or a standard secret-rotation API.

## Hint validation profile alignment

The previous azp/typ/required-integer-time restrictions are removed from the
hint path. The new [reference execution](../validation/node-id-hint-validation-profile.txt)
accepts fractional times, optional iat/exp, future iat when exp is present,
non-numeric ignored exp, another azp, an at+jwt typ and the known b64=true
critical declaration. Missing issuer/audience/subject, wrong signatures,
future nbf, nonnumeric iat/nbf and non-string jti remain rejected. The gem follows
these measured boundaries; finite numeric checks remain for evaluated dates.
An empty string subject is passed to the application resolver rather than being
inherently interpreted as a database ID. Application age limits require iat.

Every accepted test hint remains pending without inherited approval. RSA and
Edwards paths are covered; client-assertion and signed-request critical-header
policy is unchanged. [Ruby3.4 three-DB regression](../validation/id-hint-validation-matrix.txt)
passes31 tests /983 assertions on each database. The initial local broad filter
hit four sandbox listener errors; that log is not a passing run.
