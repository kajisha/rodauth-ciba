# ECDH recipient encryption: measured reference contract

> Latest policy supersedes the historical minimum-floor notes below: use explicit
> HTTP freshness, and permit failed-fetch reuse only with publisher stale-if-error,
> capped at60 seconds without renewing deadlines. See [operations](../operations.md#remote-jwks-cache-lifetime).


> Cache policy update: the user approved a minimum60-second successful JWKS
> lifetime shared by CIBA authentication and encryption, without a new policy
> switch. Earlier shorter-TTL comparisons below describe the previous runtime.
> Failed-refresh reuse remains excluded; expiry followed by failed retrieval
> does not renew freshness. See the current alignment closeout and Jev review.


Reference: node-oidc-provider9.12.2 on the pinned Node24 image. This is a
comparison of CIBA initial/refresh output, not a complete JOSE conformance audit.

`test/reference/full-op/encryption-ecdh.mjs` and its [execution](../validation/node-encryption-ecdh.txt)
cover96 configurations: four key algorithms × four recipient curves × six
content methods, yielding192 encrypted ID Tokens.

| Boundary | Measured behavior |
|---|---|
| Key algorithms | ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW |
| Curves | P-256, P-384, P-521, X25519 |
| Content methods | A128GCM, A192GCM, A256GCM, A128CBC-HS256, A192CBC-HS384, A256CBC-HS512 |
| Recipient | Public registered client JWK with matching alg, use=enc and kid |
| Protected header | cty=JWT, selected recipient kid, public epk with matching curve and no private d |
| Ephemeral keys | Distinct sampled epk for each initial/refresh token; no claim of mathematical uniqueness |
| Compact encrypted-key field | Empty for direct ECDH-ES, nonempty for the AES-KW variants |
| Decryption/signature | Recipient private key decrypts; inner RS256 verifies issuer/audience/sub |

The fixture uses Basic authentication. Its client identifiers contain `+`, so
credentials are form-encoded before Base64 encoding. The first run failed at
client authentication because the fixture omitted this encoding; fixing the
fixture made the encryption cases pass. This was not an OP encryption defect.

## Initial gem implementation and remaining boundaries

The initial gem adapter now implements these four algorithms and curves. Its
JWE dependency names ECDH in a constants list but does not implement it, so
key agreement and Concat KDF are local to CIBA; content encryption and AES-KW
remain in the existing backend. Dynamic registration accepts public EC and
X25519 JWKs and requires recipient key metadata for these algorithms.

The adapter validates EC points through OpenSSL, accepts only the three named
EC curves or canonical32-byte X25519 JWK material, and uses a new ephemeral key
per token. Failed agreement/all-zero shared secrets abort issuance. Only public
epk fields are emitted. The KDF uses SHA-256 with length-prefixed AlgorithmID,
empty PartyUInfo/PartyVInfo and the output size in bits. Direct ECDH derives
the content key; wrapping variants derive the AES-KW key.
[RFC7518 §4.6.2](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.2).

The [red test](../validation/ecdh-red.txt) established the missing path.
[Initial local evidence](../validation/ecdh-current.txt) covers96 initial/refresh
configurations plus invalid-point, mismatched-curve, wrong metadata, Ed25519,
short-X25519 and zero-X25519 rejection with rollback/recovery. Local decryption
reuses the adapter's key-import/KDF helpers, so the [independent jose check](../validation/ecdh-jose.txt)
is the stronger wire-format evidence:192 actual tokens decrypt and verify,
while a foreign same-curve recipient and altered epk are rejected. Exported
private recipient keys are disposable test material and are removed after use.

Remaining gates include additional low-order inputs and metadata selection,
real cache-expiry timing and concurrent management/issuance. Remote retrieval/rotation
and sequential management integration now have the follow-up evidence below. Installed artifacts and supported Rubies now have the follow-up evidence below. A positive
static-key matrix does not establish those integration boundaries.

The [full local regression](../validation/ecdh-full.txt) passes361 tests/9,074 assertions with two SQLite row-lock skips. The registration/Discovery test also exercises16 curve/algorithm combinations with actual issuance and rejects registration without recipient key metadata.

The [three-DB encryption subset](../validation/ecdh-matrix.txt) passes20 tests/4,144 assertions on SQLite, PostgreSQL and MySQL. These results include existing RSA/symmetric paths; ECDH-specific remote-key/management evidence remains pending; installed/supported-Ruby results follow below.

## Installed artifact and remote reference follow-up

The [installed-gem execution](../validation/ecdh-installed.txt) passes32 ECDH
configurations: four curves × four key algorithms × opaque/JWT access tokens,
with A256CBC-HS512 content encryption. Each initial/refresh token is decrypted
using the recipient's private key and its inner RS256 signature/claims are
verified. This is separate from the earlier independent jose96-combination
matrix; it establishes packaging, not all content methods in every deployment.

The remote fixture now takes algorithm/curve arguments. [P-256 direct ECDH](../validation/node-ecdh-remote-ec.txt)
and [X25519 with A256KW](../validation/node-ecdh-remote-okp.txt) both verify live
cache retention, forced-expiry key replacement, failures/recovery and management
recipient replacement/defaults/removal. The [existing RSA mode](../validation/node-ecdh-remote-rsa-regression.txt)
still passes. ECDH+KW is not enabled by the reference's default algorithm list;
the fixture explicitly enables it. The first attempt without that setting was
rejected as invalid client metadata, not as a key-agreement failure.

As with RSA, a503 response initially fails but refreshes the reference cache's
freshness, so the next request reuses the old key despite the continuing503.
Malformed JSON instead fails repeatedly with refetches. These observations do
not resolve the pending choice about matching that cache policy. Gem-specific
remote ECDH retrieval, management overlap and TLS validation remain outstanding.

The [supported-Ruby full suites](../validation/ecdh-rubies.txt) each pass361 tests/9,074 assertions on Ruby3.3 and3.4, with two SQLite row-lock skips. These are SQLite suites; they do not establish every Ruby × database combination.

## Gem remote retrieval and management

[Actual HTTP retrieval](../validation/ecdh-remote-current.txt) now covers P-256
ECDH-ES and X25519 ECDH-ES+A256KW in opaque/JWT access-token configurations.
A live cache retains the old recipient; explicit eviction retrieves the new
key. Initial503 failure preserves approval. Repeated503 and malformed-JSON
refresh failures each refetch, preserve the complete refresh-row snapshot and
grant count, and recover with rotation after the endpoint is repaired. This
confirms the existing fail-closed cache difference rather than resolving it.

[Management tests](../validation/ecdh-management-current.txt) cover both ECDH
recipients and the original RSA cases: invalid changes preserve the old key,
valid replacement changes the refresh recipient, old tokens remain decryptable,
omitted enc defaults to CBC and removing encryption settings restores signed
output for existing refresh credentials. This is sequential replacement, not
proof of every overlapping update/issuance interleaving.

[Installed HTTPS execution](../validation/ecdh-remote-installed.txt) applies the
same key-cache/rotation and failure/recovery flow to P-256 and X25519 with
opaque/JWT access tokens. Default loopback denial and untrusted TLS are rejected
before the JWKS handler receives credentials; explicitly trusted local TLS
succeeds and recipient GETs carry no Authorization header. RSA regression
checks continue to pass. The ECDH TLS helper uses local import/KDF for decryption;
wire-format independence remains established by the earlier jose192-token probe.

The DB-matrix build hit an unrelated Docker snapshot-cache failure
([build log](../validation/ecdh-remote-management-build-error.txt)). Validation
uses the previously built Ruby3.4 test image with current lib/test/examples
mounted read-only. Its image-local Gemfile.lock is retained because mounting
the macOS checkout lockfile caused Bundler to require a platform/checksum update
([lockfile failure](../validation/ecdh-readonly-lockfile-error.txt)). No global
Docker caches were deleted. These execution changes do not modify gem runtime.

The [Ruby3.4 three-DB subset](../validation/ecdh-remote-management-matrix.txt) passes10 tests/296 assertions on each SQLite/PostgreSQL/MySQL. It covers the eight new ECDH remote/management cases and the two existing RSA management cases. No runtime change was needed for these scenarios.

## Recipient key metadata

The [reference metadata probe](../validation/node-ecdh-metadata.txt) exercises
P-256 and X25519 using ECDH-ES/A256GCM. Omitted key_ops or an empty array allow
initial/refresh issuance and decryption. Nonempty arrays containing deriveBits,
sign or encrypt fail with500 server_error: jose passes these usages to
WebCrypto's public-key import, which rejects them. Selection alone had not
revealed this downstream constraint. This is a measured implementation behavior,
not a claim that CIBA specifies this HTTP status.

The gem previously ignored ECDH key_ops and issued a token, reproduced in the
[red test](../validation/ecdh-key-ops-red.txt). It now rejects a selected public
recipient whose declared key_ops is not empty; omission remains valid. Rejection
raises a configuration error inside the issuance transaction, preserving approval
and preventing grant insertion. The [local ECDH regression](../validation/ecdh-key-ops-current.txt)
passes4 tests/2,386 assertions, including the96-configuration and DCR tests.
Other malformed key_ops types are also rejected by the gem; parity for every
malformed type has not been established.

A separate difference remains: when no recipient matches use/alg, the reference
returns400 invalid_client_metadata, while the gem currently returns500
server_error. Both reject issuance, but rejection is not equivalent wire behavior.
Recipient error mapping and multi-key priority/fallback still need reconciliation.

The [Ruby3.4 three-DB ECDH subset](../validation/ecdh-key-ops-matrix.txt) passes12 tests/2,626 assertions each using the source-mount execution described above. The [full local regression](../validation/ecdh-key-ops-full.txt) passes370 tests/9,350 assertions, with two SQLite row-lock skips.

## Recipient errors and RSA operation declarations

The [expanded reference probe](../validation/node-recipient-metadata-errors.txt)
includes RSA as well as P-256/X25519. A missing metadata-compatible recipient
returns400 invalid_client_metadata. The gem previously mapped that case to500;
[reproduction](../validation/recipient-error-red.txt). It now raises a protocol
error from inside the transaction so initial approval and refresh state remain
available. Metadata eligibility and cryptographic key validity are separate:
invalid key material/agreement and nonempty ECDH public-key usages still fail
as processing errors, not as successful issuance or plaintext fallback.

RSA has two operation checks in the reference: selection requires encrypt if
key_ops is present, while jose wrapping requires wrapKey. Thus omission or both
operations succeeds; empty/wrapKey-only gives400, and encrypt-only gives500.
The gem previously ignored the latter restriction ([red](../validation/rsa-key-ops-red.txt))
and now checks the selected RSA recipient before encryption. This follows the
measured reference implementation, not a claim that CIBA mandates both names.
The [focused final tests](../validation/recipient-error-final-current.txt)
verify initial/refresh failure recovery and RSA key-operation declarations.

These changes do not resolve remote-cache policy or the order of cryptographic
validation versus multi-key selection. Those remain distinct comparison tasks.

The metadata-error change passes the [30-test encryption subset](../validation/recipient-error-matrix.txt) on three DBs (4,459 assertions each) and [371-test local suite](../validation/recipient-error-full.txt) (9,389 assertions, two SQLite skips). These runs started before the final RSA wrapKey guard; its focused final results are recorded separately to avoid claiming the older full suite covers that last edit.

The [final Ruby3.4 three-DB tests](../validation/recipient-error-final-matrix.txt) pass4 tests/112 assertions per DB, including RSA usage declarations, metadata mismatch, invalid key material and initial/refresh rollback/recovery.

## Multiple recipients and invalid preferred keys

The [reference selection probe](../validation/node-recipient-selection.txt)
checks RSA, P-256 and X25519. Matching explicit alg/use outranks an earlier
unspecified key; equal scores retain input order. If the preferred key has an
invalid EC point, zero X25519 input or unusable RSA modulus, issuance fails500
instead of trying a lower-priority valid key. Successful cases decrypt with
the selected recipient and verify initial/refresh signatures.

The gem had removed invalid keys before scoring, allowing fallback for RSA and
EC. The [red test](../validation/recipient-selection-red.txt) reproduces that
behavior. Validation now happens after selection: no metadata candidates still
returns400, but a selected unusable key fails500 without fallback. RSA minimum
modulus size remains enforced after selection; ECDH point/agreement checks and
operation declarations remain enforced. No weaker key is accepted to obtain
alignment.

The [final Ruby3.4 three-DB subset](../validation/recipient-selection-matrix.txt)
passes7 tests/3,010 assertions per DB, including RSA/Edwards recipient encryption,
all96 ECDH configurations, rejection/rollback and the new selection cases.
The [installed-artifact suite](../validation/recipient-selection-installed.txt)
also passes, including initial/refresh and HTTP/TLS recipient-key checks.
This resolves the measured priority/fallback gap; cache policy and concurrent
management timing remain distinct open boundaries.

## Actual cache expiry, without mutation

The [real-time reference probe](../validation/node-recipient-real-ttl.txt) uses
X25519 ECDH-ES+A256KW and a JWKS response with Cache-Control: max-age=2. After
replacing the endpoint's key, the reference still encrypts to the old key after
three seconds without another GET. After63,123ms it retrieves and uses the new
key. No cache field or clock was changed. This corroborates the source's
minimum60-second freshness window; the probe does not measure the exact boundary
to millisecond precision. Run separately with `npm run test:cache-ttl` because
it waits for real time rather than adding a minute to each normal reference run.

The [gem real-time probe](../validation/recipient-real-ttl-current.txt) uses
P-256 direct ECDH and X25519+A256KW. With the same max-age=2, it retains the old
key immediately, then after three seconds fetches the new key without eviction
or a mocked clock. It also rechecks failure/rollback/recovery through the shared
HTTP fixture. The [Ruby3.4 three-DB matrix](../validation/recipient-real-ttl-matrix.txt)
passes2 tests/64 assertions per DB.

Actual expiry handling is now measured, not an unverified behavior. A policy
difference remains: upstream rodauth-oauth honors the shorter positive max-age,
while the reference applies a60-second minimum. This turn changes only probes,
not runtime caching. Failed-refresh retention remains a separate unresolved
policy choice; successful expiry evidence does not approve using stale keys
following errors. Concurrent management/issuance remains a separate test boundary.

## Management update overlapping issuance

The [X25519 reference probe](../validation/node-encryption-overlap.txt) and
[RSA reference probe](../validation/node-encryption-overlap-rsa.txt) pause
account resolution during both initial issuance and refresh, commit a separate
management PUT replacing the recipient, then resume. The in-flight operation
uses the old client/key snapshot; the next refresh uses the new recipient.
Both tokens decrypt and their signatures/issuer/audience/subject verify.
Barriers have explicit deadlines and are always released during cleanup.

The gem fixture uses X25519+A256KW with opaque/JWT access tokens. Initial
issuance pauses after the client snapshot, before consuming the request;
refresh pauses after its final client revalidation, before token generation.
PostgreSQL/MySQL permit the management PUT to commit before resumption; the
expected in-flight recipient is old, then new on the next refresh. SQLite
serializes writes, so its contention test permits either consistent initial
recipient and requires the subsequent refresh to use the new key.

The first fixture paused initial issuance after request consumption and could
not complete its management PUT before releasing issuance on PostgreSQL
([barrier failure](../validation/encryption-overlap-barrier-error.txt)). Moving
the barrier earlier tests an achievable interleaving instead of requiring a
blocked update to commit. This was a test synchronization problem, not evidence
of mixed-key issuance or a production deadlock. No runtime change was needed.
These tests cover this metadata snapshot boundary, not arbitrary hooks or
process crashes, and do not change the accepted DB-atomicity adaptation.

The final [Ruby3.4 three-DB overlap matrix](../validation/encryption-overlap-matrix.txt) passes4 tests/46 assertions on each SQLite/PostgreSQL/MySQL. Initial and refresh issuance match the measured reference snapshot behavior at the specified barriers.
