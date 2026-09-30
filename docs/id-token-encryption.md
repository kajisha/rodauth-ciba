# CIBA ID Token encryption

> Latest policy supersedes the historical minimum-floor notes below: use explicit
> HTTP freshness, and permit failed-fetch reuse only with publisher stale-if-error,
> capped at60 seconds without renewing deadlines. See [operations](operations.md#remote-jwks-cache-lifetime).


> Cache policy update: the user approved a minimum60-second successful JWKS
> lifetime shared by CIBA authentication and encryption, without a new policy
> switch. Earlier shorter-TTL comparisons below describe the previous runtime.
> Failed-refresh reuse remains excluded; expiry followed by failed retrieval
> does not renew freshness. See the current alignment closeout and Jev review.


Enable recipient encryption explicitly:

```ruby
ciba_id_token_encryption_enabled true
```

For RSA encryption, register the client's public `jwks` or HTTPS `jwks_uri`. Select
`id_token_encrypted_response_alg` plus `id_token_encrypted_response_enc`.
Create storage columns for those two strings and the selected key metadata.
Dynamic registration defaults omitted `enc` to `A128CBC-HS256` when `alg` is
present; `enc` without `alg` is rejected. Discovery publishes enabled ID Token
encryption algorithms without widening UserInfo/request-object encryption lists.
The default flag is false. Configured encryption must never fall back to a signed
plaintext ID Token; a failure rolls back issuance and leaves approval available.

With the capability disabled, dynamic registration treats the two encryption
fields as unsupported metadata: they are ignored, omitted from its response,
and not stored. This follows the measured reference behavior. Clients must
inspect returned registration metadata. This does not erase a statically
configured encryption requirement or silently bypass one during issuance.

The implementation supports RSA-OAEP and RSA-OAEP-256 recipient keys, plus
client-secret-derived `dir`, A128KW/A192KW/A256KW and
A128GCMKW/A192GCMKW/A256GCMKW, and ECDH-ES with optional AES-KW. These use A128GCM/A192GCM/A256GCM and A128CBC-HS256/A192CBC-HS384/A256CBC-HS512 content
encryption. It first signs the ID Token, then encrypts it using `jwe`1.1.1
and the CIBA-local GCMKW/ECDH adapters.
RSA and Edwards ID Token signing both use this path, including refresh.
The outer protected header carries cty=JWT, selected kid (if present), issuer
and audience; no compression is enabled.

For RSA algorithms, only registered client RSA keys of at least 2048 bits qualify. Optional alg must
match; optional use must be enc. If key_ops is declared, selection requires
encrypt and wrapping requires wrapKey. Both operations must be present to issue.
A missing metadata-compatible recipient returns400 invalid_client_metadata;
selected unusable key material or operation declarations fail processing. None
of these failures falls back to an OP key. Existing JWKS retrieval controls
apply. Do not supply a client's private key to the OP.

When several keys qualify, keys explicitly matching alg and use have higher
priority than keys omitting those fields. Equal scores preserve their input
order, matching node-oidc-provider. Actual reference issuance and the gem's
regression put a generic key first and verify that the explicitly tagged second
key receives the encrypted token. [Before correction](validation/id-token-recipient-priority-red.txt),
[three-DB regression](validation/id-token-recipient-priority-matrix.txt),
[reference](validation/node-encrypted-id-tokens.txt).

Encrypted ID Token *hints* remain unsupported, matching the measured reference
behavior; clients can decrypt an issued ID Token before using its signed inner
token as a hint. This is distinct from encrypted output support.

Evidence: [Ruby regression](validation/id-token-recipient-encryption-current.txt),
[three databases](validation/id-token-recipient-encryption-matrix.txt),
[Node jose independent decryption](validation/id-token-recipient-encryption-jose.txt),
and [reference OP](validation/node-encrypted-id-tokens.txt).
The cross-library probe covers 36 algorithm combinations, initial issuance and
refresh, inner signature verification and ciphertext tampering. Its temporary
export includes an ephemeral synthetic recipient private key and must be removed
after checking; it is not a committed fixture. Run the Ruby test
`test_ciba_id_token_recipient_encryption` with `CIBA_ENCRYPTED_ID_TOKEN_EXPORT`
set to a temporary path, then run `verify-gem-encrypted-id-tokens.mjs` with that
path in the reference Node environment.

This is an initial subset of node-oidc-provider encryption capabilities. ECDH,
symmetric recipient encryption and all metadata-management/remote-key
combinations remain outstanding.

`examples/encrypted_id_token_smoke.rb` now runs from `bin/verify-package` after
installing the built gem into a temporary directory. It exercises RS256,
Ed25519 and EdDSA signatures with RSA-OAEP-256/A256GCM, opaque/JWT access tokens,
initial issuance and refresh, recipient decryption and inner signature checks.
It uses Rack requests and inline recipient keys; this does not establish remote
HTTPS recipient retrieval. [Package evidence](validation/id-token-encryption-installed.txt).
[Ruby 3.3/3.4 regression](validation/id-token-encryption-rubies.txt) covers the
full suite on SQLite; two row-lock tests remain skipped on that database.

## HTTPS recipient retrieval and failure atomicity

The initial encryption path unintentionally used upstream's unguarded HTTP
lookup during issuance. The [installed regression before correction](validation/id-token-encryption-https-red.txt)
shows a forbidden loopback recipient being contacted and a token issued.
The HTTP wrapper now covers CIBA issuance/refresh recipient retrieval as well
as assertion/request keys. Upstream HTTP authorization failures during issuance
raise an exception rather than halting with a response inside the transaction;
this preserves source rollback.

The [installed HTTPS probe](validation/id-token-encryption-https-installed.txt)
runs with an explicitly trusted local certificate and a separate untrusted
process. It verifies default loopback denial, explicit fixture-only allowance,
TLS certificate rejection before the handler, GET without forwarded credentials,
old-key cache retention, new-key use after explicit cache eviction, 503/malformed
JSON failure rollback and subsequent recovery/refresh rotation in opaque and
JWT access-token modes. Recipient decryption and the inner RSA signature are
checked throughout. Real TTL passage is not measured; eviction is explicit.
The private key never leaves the test recipient.

[Database regressions](validation/id-token-encryption-remote-matrix.txt) also
exercise redirects and oversized bodies during initial issuance and refresh.
These use HTTP fixtures with an explicit loopback allowance; TLS evidence comes
from the installed probe. The earlier supported-Ruby matrix predates this HTTP
correction. Broader signing/encryption combinations and deployment conditions
remain outstanding; remote-cache and management evidence follows below.

After the HTTP correction, [full Ruby 4.0.6 regression](validation/id-token-encryption-https-full.txt)
passes 348 tests /5,576 assertions on SQLite with two row-lock skips; the
targeted three-DB matrix passes seven tests /802 assertions per database.

## Reference remote cache and management comparison

`test/reference/full-op/encryption-remote.mjs` exercises actual reference HTTP
endpoints and key retrieval with a narrowly allowed local fixture URL. Live
cache retains the old recipient; explicit expiry retrieves the replacement.
Recipient decryption and inner signature/issuer/audience/subject are verified.
No Authorization header reaches the key server.
[Reference execution](validation/node-encryption-remote.txt).

One concrete difference remains after failed recipient-key refresh. With 503
and valid JSON, the reference first returns 400 invalid_client_metadata, then
uses retained keys for the next token refresh without refetching while the key
endpoint still fails. The gem rolls back and returns 500 server_error; fetch
failures are not inserted as successful cache entries. Invalid JSON causes
repeated refetch/failure in both implementations, with those different error
codes; repairing the response restores issuance.

The reference `ClientKeyStore.refresh` updates freshness before checking HTTP
status, but parses JSON before updating freshness. This explains the observed
difference. It also imposes at least 60 seconds of freshness; the gem's upstream
HTTP cache honors no-cache without this floor. These probes force expiry rather
than waiting for real TTL. Lifetime and post-failure key retention are unresolved
alignment differences, not claimed equivalence or an approved new adaptation.
No cache behavior was changed by this comparison.

The reference also dynamically registers an encrypted client and updates its
inline recipient via the management endpoint. Invalid encryption metadata leaves
the old key intact; successful replacement changes the recipient for existing
refresh credentials while the original token still decrypts with the old key.
Gem tests `test_ciba_encryption_management_replaces_recipient_opaque` and
`test_ciba_encryption_management_replaces_recipient_jwt` verify those boundaries
in both access-token modes. [Database execution](validation/id-token-encryption-management-matrix.txt).
This does not prove every management transition, remote URI change or concurrent
registration update.

### Defaults, removal and disabled registration

The management probes now also omit enc while retaining alg: both implementations
replace the previous A256GCM selection with A128CBC-HS256 and encrypt subsequent
refresh responses accordingly. Removing both encryption fields clears the
stored requirement and returns signed ID Tokens on existing refresh credentials.
The tests follow rotated registration access tokens after each successful PUT;
reusing the previous management token correctly fails authentication.

Disabled-capability registration originally stored and returned the encryption
fields, although issuance could not honor them. An initial proposal to reject
registration was revised after the reference returned 201 while omitting both
fields. The implementation now ignores them, matching the reference's response
and stored client. [Reference registration](validation/node-encryption-disabled-registration.txt),
[reference updates](validation/node-encryption-remote.txt),
[final DB matrix](validation/id-token-encryption-config-matrix.txt).
This correction is confined to CIBA registration; ordinary OAuth clients follow
their existing upstream handling.

## Client-secret-derived encryption

`dir`, AES-KW and AES-GCMKW do not require recipient JWKS. The OP derives
bytes from the UTF-8 client secret using SHA-256 for lengths up to32 bytes,
SHA-384 up to48, and SHA-512 up to64, truncating to the required length. AES-KW
uses the wrapping-key size; `dir` uses the content-encryption key size (the
full combined MAC/encryption size for CBC-HS). This follows the pinned
node-oidc-provider9.12.2 client model and its actual issuance/refresh output.
It is distinct from HMAC signing, which uses the original secret directly.

`ciba_id_token_encryption_secret(oauth_application:)` retrieves the original
secret and by default delegates to `ciba_id_token_hmac_secret`. Verified
Basic/POST credentials can be reused within that authenticated request even
with hash storage. Explicit plaintext storage is the fallback. Applications
using private-key authentication with hashed secrets must supply an original
secret through the callback. A missing, empty or invalid-encoding secret fails
issuance and rolls back consumption; the hash is never used as the secret.

The [reference probe](validation/node-encryption-symmetric.txt) verifies42
combinations, including AES-GCMKW, without recipient JWKS. The initial symmetric increment
implemented24 combinations (`dir`/AES-KW × six content methods); the
[local tests](validation/symmetric-encryption-current.txt) verify hashed-secret
DCR, initial/refresh issuance, wrong keys and missing-secret rollback.
[Independent jose verification](validation/symmetric-encryption-jose.txt)
decrypts48 actual gem tokens and verifies their inner RS256 signatures.
The standalone verifier takes a disposable vector file exported with
`CIBA_SYMMETRIC_EXPORT`; synthetic secrets must not be committed.

ECDH is now implemented by the CIBA-local adapter described below. The `jwe`1.1.1 `VALID_ALG` list
names ECDH and AES-GCMKW, but its algorithm dispatcher has no implementations.
AES-GCMKW is now provided by the CIBA-local adapter described below; ECDH is
handled separately. Broader authentication/signature combinations remain pending. Existing RSA evidence does not establish those cases.

The [three-DB encryption subset](validation/symmetric-encryption-matrix.txt)
passes10 tests/1,211 assertions on each SQLite/PostgreSQL/MySQL. A subsequent source-review
found that upstream `oidc.rb#generate_id_token` eagerly calls
`oauth_application_jwks` before encoding. The [regression reproduction](validation/symmetric-jwks-red.txt)
confirmed that an unrelated503 JWKS URI incorrectly prevented symmetric issuance.
A CIBA-only generation scope now skips that recipient lookup for symmetric
algorithms and restores the previous scope on success or exception. Authentication
outside generation still resolves and validates the registered public key.
The [targeted HTTP tests](validation/symmetric-jwks-current.txt) verify zero
recipient requests during Basic issuance/refresh and actual private_key_jwt
retrieval with wrong-key rejection and recovery. The [reference probe](validation/node-symmetric-jwks.txt)
verifies84 combinations (42 without JWKS and42 with a503 URI), all without
recipient retrieval. This does not suppress asymmetric encryption or ordinary OP
key retrieval.

The [full local regression](validation/symmetric-encryption-full.txt) passes356 tests/6,261 assertions, with two SQLite row-lock skips.

The updated [three-DB subset](validation/symmetric-jwks-matrix.txt) passes21
tests/1,505 assertions per DB, including encryption and client assertions.
The [installed artifact](validation/symmetric-encryption-installed.txt) passes16
symmetric cases across four key algorithms, Basic with hashed storage / POST
with plaintext storage, and opaque/JWT access tokens. It decrypts and verifies
initial and refresh ID Tokens while an unrelated JWKS URI is configured and
any outbound recipient HTTP call would fail the smoke. Existing RSA and TLS
package checks also pass. The build reuses installed dependencies; network
resolution of dependencies is not established.

[Supported Ruby regression](validation/symmetric-encryption-rubies.txt) passes358 tests/6,274 assertions on each Ruby3.3 and3.4, with two SQLite row-lock skips.

## AES-GCM key wrapping

The CIBA-local adapter supports A128GCMKW/A192GCMKW/A256GCMKW. It uses OpenSSL
AES-GCM to wrap a newly generated content key, with a fresh12-byte random IV,
empty wrapping AAD and a16-byte authentication tag. Both wrapping parameters
are included in the protected header, which the JWE backend authenticates as
content AAD. Content encryption and compact serialization remain in `jwe`;
there is no global algorithm registration or new token-decryption endpoint.
The client-secret derivation above also applies to GCMKW.
[RFC7518 §4.7](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7).

The [registration red test](validation/gcmkw-red.txt) failed before the adapter.
The expanded [local symmetric tests](validation/gcmkw-current.txt) pass42
algorithm/content combinations, checking DCR with hashed storage, initial and
refresh output, wrapping IV/tag lengths and distinct sampled IVs. This sampling
is not a guarantee of collision-free operation; randomness comes from
`SecureRandom` for each wrap and from the JWE backend for content keys/IVs.
The [independent jose verifier](validation/gcmkw-jose.txt) decrypts84 actual gem
tokens, verifies the inner RS256 signature, rejects wrong keys, and rejects
changes to wrapping IV/tag, encrypted key, ciphertext and content tag.

The [reference execution](validation/node-symmetric-jwks.txt) already covers
all42 combinations with and without an unrelated503 JWKS URI. The updated [installed-artifact smoke](validation/gcmkw-installed.txt) covers
all seven symmetric key algorithms in28 configurations: hashed Basic/plaintext
POST and opaque/JWT access tokens. Initial and refresh tokens are unwrapped,
decrypted and signature-checked, with unexpected recipient HTTP calls rejected.
Supported-Ruby validation is recorded separately below.

The [GCMKW encryption regression subset](validation/gcmkw-matrix.txt) passes17 tests/1,794 assertions on each SQLite/PostgreSQL/MySQL. The [full local regression](validation/gcmkw-full.txt) passes358 tests/6,724 assertions with two SQLite row-lock skips.

The [GCMKW supported-Ruby regression](validation/gcmkw-rubies.txt) passes358 tests/6,724 assertions on each Ruby3.3 and3.4, with two SQLite row-lock skips. The [ECDH contract](research/ecdh-encryption-reference-contract.md) records96 reference configurations and the new adapter with its remaining validation gates.

## ECDH recipient keys

ECDH-ES and ECDH-ES+A128KW/A192KW/A256KW accept registered public P-256,
P-384, P-521 or X25519 recipient keys. All six content methods above are
supported. Public JWKS/jwks_uri is required; client-secret retrieval is not used.
For ECDH public recipients, `key_ops` must be omitted or empty, matching the
reference's public-key import behavior. Nonempty declarations fail issuance; see
the [metadata comparison](research/ecdh-encryption-reference-contract.md#recipient-key-metadata).
The protected header includes a fresh public epk, recipient kid when present,
cty/issuer/audience. Direct ECDH has an empty encrypted-key segment; wrapping
variants use the existing AES-KW backend. Unsupported curves and invalid key
agreement fail instead of returning plaintext. See the [reference and current
validation contract](research/ecdh-encryption-reference-contract.md).

This is an initial implementation. [Installed-artifact validation](validation/ecdh-installed.txt)
now covers32 ECDH configurations. [Ruby3.3/3.4](validation/ecdh-rubies.txt) each pass361 tests/9,074 assertions.
ECDH-specific HTTP/HTTPS key retrieval, failure/rotation and sequential management
now pass ([contract](research/ecdh-encryption-reference-contract.md#gem-remote-retrieval-and-management)); real TTL is now [measured](research/ecdh-encryption-reference-contract.md#actual-cache-expiry-without-mutation), with a shorter-max-age policy difference; [management/issuance overlap](research/ecdh-encryption-reference-contract.md#management-update-overlapping-issuance) now has reference and three-DB snapshot evidence.

Recipient selection follows explicit alg/use priority and stable input order. Cryptographic validation occurs after selecting the recipient: an unusable preferred key fails issuance without trying another key. [Comparison and regression evidence](research/ecdh-encryption-reference-contract.md#multiple-recipients-and-invalid-preferred-keys).
