# 0.1.0 release validation

Edwards client authentication follow-up: Ruby3.3/3.4 full SQLite suites each pass
334 tests /4,316 assertions with2 row-lock skips
([log](validation/client-auth-edwards-rubies.txt)). Remote-key/ordinary-code-grant
subset passes on all three DBs:5 tests /247 assertions each
([log](validation/client-auth-edwards-remote-matrix.txt)).
[Installed artifact](validation/client-auth-edwards-installed.txt) adds inline
Edwards authentication and replay rejection at both CIBA endpoints for opaque/JWT
access tokens; all prior smoke flows also pass. SHA256
`d43fd74be78fc8f615a8f6125488af244dda284820ae723293696d20c6d61edf`.
The artifact predates this results update; runtime code is unchanged.


Latest consolidated runtime verification after ping-destination, NumericDate and
missing-client error alignment:

- [Three databases](validation/alignment-consolidated-databases.txt):331 tests each;
  SQLite4,217 assertions with2 row-lock skips, PostgreSQL/MySQL4,214 assertions
  without skips. All pass on Ruby4.0.6.
- [Ruby3.3/3.4 SQLite](validation/alignment-consolidated-rubies.txt):331 tests /
  4,217 assertions each,0 failures/errors and2 row-lock skips.
- The first full run found an old401 expectation in the JWT-grant bypass test
  ([initial run](validation/alignment-consolidated-databases-red.txt)). Updated it
  to400 invalid_request with no challenge; persistence remains forbidden and
  authenticated CIBA still succeeds. No production change was needed for that test.
- [Installed artifact](validation/alignment-consolidated-package.txt) passes all
  packaged smoke flows including TLS. SHA256
  `981e5e9a8c9a1a2789d4e6322003db2923d88030372aa8ab2390088c380d8a18`.
  This artifact predates this report and the later test-only expectation update;
  runtime code is unchanged. Dependency resolution reused installed local gems.


Node/jose fixed Edwards vectors: three-DB inline/HTTP remote-key regression each
4 tests /108 assertions passes. Installed package accepts both algorithms with
opaque/JWT access tokens and verifies the ID Token; full package smoke passes.
[Artifact log](validation/edwards-installed.txt), SHA256
`26c775be0f13c01987de8c26d827acd54a0e7de2909650121f0b756ecf4f2acb`.
This artifact predates the documentation update recording these results.

Edwards signed-request increment: Ruby3.3/3.4 full suites each324 tests /
3977 assertions,0 failures/errors and2 SQLite row-lock skips
([log](validation/edwards-rubies.txt)). Three-DB signature subset each11 tests /
234 assertions passes ([log](validation/edwards-request-matrix.txt)). This is not
installed-gem Edwards interoperability or a complete release gate.

## Pairwise self-signed mTLS (2026-09-30)

Reference and installed-gem fixtures pass pairwise self-signed TLS clients with
remote JWKS, CIBA issuance and UserInfo. The installed artifact also covers DCR,
HTTPS certificate rotation and refresh. Discovered failures were corrected:
private_key_jwt-only eligibility, pairwise JWT account lookup in introspection,
and Rodauth's1024-byte token parameter truncation. The new bounded CIBA-specific
introspection path retains signature and live-issuance checks. Final focused
cases pass on all three DBs; the full installed smoke suite passes.
[DB](validation/pairwise-mtls-final.txt), [package](validation/pairwise-mtls-package-final.txt),
[reference](validation/node-pairwise-mtls.txt). The prior related run had30 tests
per DB, before the final introspection changes. Signed-request-only ownership
proof remains unsupported; full multi-process/production policy parity is not
established.

## Ruby minimum-version regression after mTLS alignment (2026-09-30)

The complete suite passes **306 tests /3,561 assertions** on each of Ruby3.3.12
and Ruby3.4.11 with SQLite in pinned aarch64 Linux Docker images. Each skips the
two row-lock-specific cases that are not applicable to SQLite; neither has
failures or errors. [Run](validation/mtls-alignment-rubies.txt), reproduced by
`./bin/test-rubies`. The image runtime versions were separately read with
`docker run --rm rodauth-ciba-ruby33-test ruby --version` and its ruby34 equivalent.
This includes current mTLS, remote JWKS and JWT introspection changes. It does
not run the installed-package smoke on those Ruby versions or establish every
Ruby × DB combination. Current DB subsets and Ruby4 installed-artifact results
remain separately recorded below.

The protocol-to-test mapping and README now include implemented DPoP/mTLS and
registration boundaries. Named methods in the mapping were checked against test
sources. The159-item initial-scope audit is explicitly historical; optional
extension implementation does not automatically upgrade its excluded rows to
verified. A refreshed normative audit remains required before broad conformance
claims.

## Installed HTTPS mTLS rotation and JWT introspection (2026-09-30)

The package's self-signed mTLS clients now use HTTPS remote JWKS in an isolated
child process with a fixture CA, preserving certificate verification. Opaque/JWT
variants pass forced-expiry rotation to a different certificate with the same
key, confidential refresh and new binding, retained old-token binding,
repeated503 rejection without requests persisted, and receiver recovery.
The test found missing cnf in JWT introspection; that serializer now validates
live issuance/client/subject/digest before reporting binding. Related cases pass
**14 tests /307 assertions** on each DB with no failures/errors/skips.
[DB](validation/mtls-jwt-introspection-matrix.txt),
[complete installed smoke](validation/mtls-remote-installed-final.txt).
One process, Ruby4.0.6/SQLite for the installed artifact; forced cache expiry is
not real TTL timing or distributed rotation evidence.

## Remote mTLS certificate rotation boundary (2026-09-30)

The mTLS/remote-JWKS subset passes17 tests /304 assertions on each DB; the final
rotation/failure/recovery case separately passes on all three DBs.
[Related](validation/mtls-remote-matrix.txt), [final](validation/mtls-remote-final.txt).
Actual node TLS authentication with an owned HTTP JWKS receiver verifies cache
retention, forced-expiry replacement and failure error mapping.
[Reference](validation/node-mtls-remote.txt). The installed smoke suite also
passes after the runtime error-handling change, including real TLS aliases in
four mTLS combinations. [Package](validation/mtls-remote-package.txt). That package
fixture does not yet cover remote certificate rotation itself. Expiry is forced
in the focused rotation tests; real TTL timing and multiple processes are not
proved. Failed-refresh cache semantics intentionally remain stricter than node.

## Application mTLS aliases (2026-09-30)

The installed artifact passes the existing smoke suite with the mTLS fixture now
publishing application-owned endpoint aliases on a separate TLS port. All four
PKI/self-signed × opaque/JWT combinations use discovered aliases for CIBA, token,
introspection and UserInfo. Signed ID Token issuer/audience remain canonical,
negative certificate checks still fail, and management/binding semantics remain
intact. [Package](validation/mtls-aliases-package.txt). Node's actual TLS fixture
passes the equivalent alias flow and proves default metadata omits aliases.
[Reference](validation/node-mtls-aliases.txt). No production gem code changed;
proxy/path-rewrite/DPoP-alias and remote rotation cases are not established.

## mTLS capability and client policy (2026-09-30)

Related mTLS/Discovery cases pass **21 tests / 311 assertions** on each of
SQLite/PostgreSQL/MySQL, with no failures/errors/skips.
[Matrix](validation/mtls-capability-matrix.txt). Installed package checks pass,
including real TLS PKI/self-signed × opaque/JWT with upstream global binding true
and client binding disabled through management: new refreshed access tokens are
unbound; old tokens stay bound. [Package](validation/mtls-capability-package.txt).
Both discovery documents expose capability independently of client policy.
Remote rotation, aliases and arbitrary TLS deployment policies remain unverified.

## Installed mTLS DCR and management over TLS (2026-09-30)

The installed package passes real TLS dynamic registration followed by CIBA,
UserInfo, introspection and refresh for PKI/self-signed × opaque/JWT. Generated
client IDs are used and verified in ID Token audiences. Failed management PUT
preserves policy/credential; successful omission resets future binding to false
and rotates credentials. Old bound tokens still require certificates; later
refresh tokens authenticate with mTLS and issue unbound access tokens under the
new policy. All other installed smoke fixtures pass.
[Log](validation/mtls-dcr-installed-tls.txt). No production code changed in this
increment. Ruby4.0.6/SQLite, temporary local installation and synthetic TLS trust;
certificate rotation, aliases/global capability policy and production proxies
remain outside this evidence.

## mTLS dynamic registration (2026-09-30)

Ruby4.0.6 registration/management/mTLS/DPoP subsets pass **65 tests** on
SQLite/PostgreSQL/MySQL, with 953/948/948 assertions and no failures/errors/skips.
[Related cases](validation/mtls-registration-matrix.txt).
A separate final run includes the new dynamically registered self-signed client
issuance and management policy-change case on all three DBs.
[Final cases](validation/mtls-registration-final.txt).
Validation covers strict binding booleans, missing storage, one PKI subject,
required self-signed keys, disabled-property omission, default false, dual-binding
rejection and unchanged row/credential after invalid PUT. Old tokens retain their
binding after future issuance policy changes. Node's actual TLS fixture now uses
DCR clients and also checks management replacement.
[Reference](validation/node-mtls-registration.txt). The preceding installed TLS
fixture uses static registration; installed mTLS DCR has not yet been established.

## Installed mTLS over real Ruby TLS (2026-09-30)

The temporary installed artifact passes all four PKI/self-signed × opaque/JWT
flows over WEBrick and Net::HTTP TLS: CIBA acceptance/collection, verified token
identity and certificate digest, UserInfo and refresh. Missing certificates,
header-only certificate claims and foreign client certificates fail; the same
key in a different certificate cannot use bound UserInfo. The client verifies
server trust/hostname, and the application verifies PKI peers separately from
self-signed registration. Module provenance is checked against the installed
gem. Existing DPoP, registration, extensions, ping/JWKS/sector TLS smoke also pass.
[Package log](validation/mtls-installed-tls.txt). Ruby4.0.6/SQLite, local synthetic
keys only; no publication/network dependency resolution. DCR mTLS, remote rotation,
production proxies and multi-process integration remain unverified.

## Initial CIBA mTLS implementation (2026-09-30)

Initial Ruby4.0.6 full suites pass **297 tests** on SQLite/PostgreSQL/MySQL
(3355/3352/3352 assertions), no failures/errors; SQLite skips two row-lock cases.
[Full log](validation/ciba-mtls-matrix.txt). A later dual-DPoP-binding test found
approval consumed during rejection inside nested persistence; validation moved
before that transaction. Final mTLS/DPoP cases pass **30 tests / 541 assertions**
on every DB, no failures/errors/skips. [Final log](validation/ciba-mtls-final.txt).
The seven local mTLS cases pass134 assertions, covering explicit trust/storage,
both authentication methods with opaque/JWT, no-header fallback, correct DER
binding, UserInfo/introspection/refresh, expiry/revocation and rollback.
The earlier local broad subset hit a sandbox socket-bind error in a remote-JWKS
test; the Docker full run covered that test successfully. These Rack fixtures
do not yet prove Ruby TLS-server integration or installed-package mTLS behavior.

## mTLS characterization — unresolved implementation (2026-09-30)

The complete node9.12.2 OP passes both TLS client authentication methods through
CIBA issuance and refresh over real TLS, with certificate-DER thumbprint and
UserInfo certificate binding. The runner generates/removes local fixture keys.
[Reference](validation/node-mtls-reference.txt). The actual Ruby gem Rack probe
observes incompatible binding, certificate-free UserInfo200, and self-signed
x5c auth500. Its two passing setup assertions are **not mTLS conformance tests**.
[Probe](validation/upstream-mtls-probe.txt). Production corrections and matching
installed-artifact TLS verification remain required.

## JWT client authentication on CIBA refresh (2026-09-30)

Ruby4.0.6 authentication/assertion/refresh cases pass **59 tests** on SQLite,
PostgreSQL and MySQL, with 624/627/627 assertions and no failures/errors.
SQLite skips one row-lock-specific test. [DB log](validation/assertion-refresh-matrix.txt).
The new regressions cover private_key_jwt and client_secret_jwt using issuer aud
for initiation, collection and refresh; wrong aud preserves refresh state, replay
cannot issue again, and unrelated authorization-code audience policy is retained.
The complete node OP confirms acceptance/rejection for both methods.
[Reference](validation/node-assertion-refresh.txt). This targeted matrix does not
replace the earlier full-suite or installed-artifact evidence; mTLS remains open.

## Discovery extension correction (2026-09-30)

Ruby4.0.6/SQLite passes **43 tests / 686 assertions** for discovery, metadata,
DPoP and introspection, without failures/errors/skips.
[Integration](validation/discovery-extensions-integration.txt).
OIDC metadata now preserves configured introspection URLs/auth metadata and
DPoP algorithms from OAuth server metadata, with no advertisement when disabled.
The installed-gem suite compares both metadata documents and uses the OIDC URL
for opaque DPoP introspection. [Package](validation/discovery-extensions-package.txt).
The node fixture confirms endpoint/algorithm presence and disabled omission; it
does not advertise an introspection auth-method list, whereas the gem retains
the upstream list. [Reference](validation/node-discovery-extensions.txt).
This is metadata-only production code; the earlier 287-test DB matrix predates
this correction, and no new full DB/Ruby matrix is claimed here.

## DPoP opaque introspection correction (2026-09-30)

Ruby4.0.6 full suites pass **287 tests** on SQLite/PostgreSQL/MySQL, with
3216/3214/3213 assertions and no failures/errors. SQLite skips two row-lock tests.
[DB log](validation/dpop-introspection-matrix.txt). Both ordinary and resource
opaque DPoP tokens now introspect as active with their stored cnf/type; wrong
client credentials, unknown/expired/revoked tokens and unrelated OAuth behavior
are covered. The complete node OP confirms cnf for initial/refreshed keys and
inactive responses after revocation. [Reference](validation/node-dpop-introspection.txt).
The installed package also passes the added introspection assertion and all
existing smoke fixtures. [Package](validation/dpop-introspection-package.txt).
Ruby3.3/3.4 were last run before this correction. OIDC Discovery exposure of the
introspection URL and external resource enforcement remain open.

## DPoP POST and storage configurations (2026-09-30)

All **19 DPoP tests / 370 assertions** pass on SQLite/PostgreSQL/MySQL, without
failures/errors/skips. [DB log](validation/dpop-post-storage-matrix.txt).
Added opaque/JWT POST UserInfo, explicit plaintext storage and a distinct hash
column, with method/key/ath/replay and token-liveness checks. Existing default
opaque storage was already hashed; explicit assertions now verify it. The real
node OP confirms POST method binding and replay rejection.
[Reference](validation/node-dpop-post.txt). No production code changed in this
increment. This targeted run does not replace the earlier full-suite/package
evidence or cover external resource/proxy integration.

## Installed DPoP artifact (2026-09-30)

The temporary installed gem now passes opaque/JWT DPoP dynamic registration,
required-proof/nonce challenge, old-iat issuance with valid nonce, signature and
key-binding checks, cleanup then replay rejection, UserInfo positive and negative
cases, and confidential refresh with a new key followed by UserInfo.
Both feature/module load paths are checked against the installed directory.
The existing lifecycle, optional extensions, DCR, TLS ping, sector and remote
JWKS package checks also pass. [Package log](validation/dpop-installed-package.txt).
Environment: Ruby4.0.6, SQLite, in-process Rack for DPoP; dependencies reused
locally. No publication or network dependency resolution. Proxy integration,
external resource servers and multi-process behavior remain unverified.

## DPoP server nonce (2026-09-30)

Ruby4.0.6 full suites pass **281 tests** on SQLite/PostgreSQL/MySQL
(3082/3080/3079 assertions), no failures/errors; SQLite skips two row-lock tests.
[Full log](validation/dpop-nonce-matrix.txt). Review then found and corrected
acceptance of zero iat with a valid nonce, which the reference rejects. All final
DPoP tests pass on each DB: **15 tests / 267 assertions**, no failures/errors/skips.
[Final log](validation/dpop-nonce-final.txt). The real node OP checks required and
optional nonce challenges, old iat with valid nonce, cross-endpoint use, zero-iat
rejection and proof replay. [Reference](validation/node-dpop-nonce.txt).
Gem opaque/JWT cases also test cleanup/replay retention, expiry and secret
rotation. After the zero-iat correction, Ruby3.3 and Ruby3.4 each pass the full
**281 tests / 3086 assertions** on SQLite, with no failures/errors and the same
two row-lock-specific skips. [Ruby log](validation/dpop-nonce-rubies.txt).
Installed DPoP artifacts and multi-process clock/secret behavior remain
unverified; this does not establish complete DPoP parity.

## DPoP dynamic registration (2026-09-30)

The registration/management/DPoP subset passes **44 tests** on Ruby4.0.6 with SQLite/PostgreSQL/MySQL (553/548/548 assertions), no failures/errors/skips. [Log](validation/dpop-registration-matrix.txt). It covers strict boolean input, missing storage, false/default serialization, ignored metadata when disabled, issued-client enforcement, failed-update preservation and omission resetting future issuance policy without unbinding existing tokens. Node's real OP passes DCR followed by issuance/UserInfo/refresh and management checks. [Reference](validation/node-dpop-registration.txt). This targeted run does not replace the preceding 275-test full-suite evidence, and Ruby3.3/3.4 and installed-package DPoP validation remain outstanding.

## CIBA DPoP UserInfo boundary (2026-09-30)

Ruby4.0.6 full suites pass **275 tests** on SQLite/PostgreSQL/MySQL, with 2954/2952/2951 assertions and no failures/errors. SQLite skips two row-lock-specific tests. [DB log](validation/ciba-dpop-userinfo-matrix.txt). Opaque/JWT UserInfo verifies proof, ath, issuance-key binding and replay; unknown, forged, expired and revoked tokens are rejected. Concurrent proof reuse yields one success. Existing unbound CIBA Bearer Tokens still work. Node's actual UserInfo proof-reuse test also passes. [Reference](validation/node-dpop-reference.txt). Ruby3.3/3.4, installed artifacts, nonce handling and additional combinations remain unverified for this increment; this is not full DPoP readiness.

## Initial CIBA DPoP token endpoint (2026-09-30)

Ruby4.0.6 full suites pass **273 tests** on SQLite/PostgreSQL/MySQL, with 2895/2893/2892 assertions, no failures/errors; SQLite skips two row-lock-specific tests. [Log](validation/ciba-dpop-matrix.txt). The new tests cover proof validation, pending reuse before issuance, concurrent replay exclusion, rollback, required-proof client policy, ordinary-grant preservation and opaque/JWT confidential refresh with a new key. Additional malformed JOSE/signature rejection assertions were added after this full run; the final targeted **7 tests / 90 assertions** pass on every DB without failures/errors/skips. [Final cases](validation/ciba-dpop-final.txt). This is token-endpoint integration, not complete DPoP support. Ruby3.3/3.4 and installed artifacts have not been revalidated for this addition.

## default_max_age registration boundary (2026-09-30)

Ruby4.0.6 full suites pass **265 tests** on SQLite/PostgreSQL/MySQL, with 2798/2796/2795 assertions respectively, no failures/errors; SQLite skips two row-lock-specific tests. [Log](validation/registration-max-age-matrix.txt). The subsequent integral-JSON-number normalization also passes the targeted **1 test / 59 assertions** on each DB. [Final changes](validation/registration-max-age-final.txt). The actual node registration harness confirms the nonnegative safe-integer boundary. [Reference](validation/node-registration-max-age.txt). Ruby3.3/3.4 and installed-artifact runs predate this metadata fix; this section does not claim those were rerun.

## Pairwise concurrent management/issuance (2026-09-30)

Two new opaque/JWT integration tests pass on SQLite (**21 assertions**), PostgreSQL and MySQL (**19 assertions** each), with no failures/errors/skips. [Log](validation/pairwise-concurrent-matrix.txt). On row-locking DBs, a barrier forces sector management to commit after issuance loads client metadata but before token generation: ID Token, JWT Access Token and persisted subject agree on the captured sector, while later UserInfo uses the current sector. SQLite exercises concurrent writers and either serial order. Runtime code is unchanged. These two added tests have not been run on Ruby3.3/3.4; the 262-test full suites below predate them. This narrows the concurrent-sector gap below, without establishing concurrent refresh/key-change behavior or node's concurrent ordering.

## Pairwise and registration: refreshed Ruby matrix (2026-09-30)

`bin/test-rubies` completed successfully using the pinned Ruby3.3 and3.4 Docker images. Each SQLite suite passes **262 tests / 2730 assertions**, with no failures/errors and two row-lock-specific tests skipped. [Log](validation/pairwise-current-rubies.txt). This includes the latest pending-request sector-update tests as well as DCR, pairwise opaque/JWT issuance, hints, refresh and issuance-subject storage. It supersedes the 211-test Ruby results below.

The three-DB full suite previously passed 262 tests before the pending-request assertions were added; those additions subsequently passed on all three DBs in the targeted **2 tests / 88 assertions** run. [Full DB log](validation/pairwise-sector-update-matrix.txt), [additional assertions](validation/pairwise-pending-matrix.txt). The latest installed artifact also exercises pairwise issuance with real TLS JWKS and verified ID Token/UserInfo. [Package log](validation/pairwise-issuance-package.txt). Concurrent pairwise management/issuance and installed pairwise JWT/refresh remain unverified; these results do not establish broader node parity or release readiness.

## Optional request context (2026-09-30)

Ruby4.0.6 SQLite/PostgreSQL/MySQL suites pass **216 tests**, 2084–2086 assertions, no failures/errors. SQLite skips the inapplicable row-lock test. [DB log](validation/request-context-matrix.txt). The installed opaque/JWT extension smoke now supplies a signed context, validates it through the application callback, checks request storage and excludes it from ID Token claims. [Package log](validation/request-context-package.txt). Ruby3.3/3.4 were last checked at 211 tests; the additional context tests have not been run there yet.

## Current Ruby matrix (2026-09-30)

Ruby3.3.12 and3.4.11 SQLite each pass **211 tests / 2050 assertions**, no failures/errors, one inapplicable row-lock test skipped. [Log](validation/revocation-ruby-matrix.txt). Together with the current three-DB matrix this verifies the latest revocation/provenance runtime on the five declared combinations. The [roadmap audit](alignment-roadmap.md) keeps still-unsupported capabilities separate from this passing subset.

## Access-token revocation and provenance (2026-09-30)

Ruby4.0.6 SQLite/PostgreSQL/MySQL full suites pass **211 tests**, 2050–2051 assertions, no failures/errors. SQLite skips the row-lock-specific barrier test; the other DBs run it. [DB log](validation/access-token-revocation-complete-matrix.txt). Coverage includes saved-consent retention, related-artifact invalidation, new opaque namespaces after cleanup, legacy formats, signed JWT rejection and forged-marker rejection. The installed gem smoke additionally exercises opaque-AT revocation retaining consent and JWT revocation rejection, alongside refresh and HTTPS ping. [Package log](validation/access-token-revocation-package.txt). Ruby3.3/3.4 were last checked at 200 tests, before these changes; this section does not claim the newer tests ran there.

## Installed refresh artifact (2026-09-30)

`bin/verify-package` now runs opaque/JWT refresh with signed requests, claims/resources/RAR, rotation, retained authentication context, successor invalidation after CIBA replay, advertised revocation endpoint and cleanup from a temporary gem installation. This found a missing revocation URL in OIDC Discovery; the extension now publishes it when revocation is enabled. The targeted revocation tests pass **2 tests / 55 assertions** after that fix. [Package log](validation/refresh-package.txt). Existing HTTPS ping timeout/untrusted-CA checks also pass. The full 200-test matrix below preceded this metadata-only change; it was not rerun for this change. Access-token-initiated grant-wide revocation remains incomplete.

## Refresh implementation and hooks (2026-09-30)

Ruby4.0.6 SQLite/PostgreSQL17/MySQL8.4 and Ruby3.3.12/3.4.11 SQLite pass **200 tests**, 1894–1897 assertions, no failures/errors/skips. [DB](validation/refresh-hooks-matrix.txt), [Ruby](validation/refresh-ruby-matrix.txt). Includes optional refresh issuance, independent sources, age-based rotation/replay, resource and claims/RAR updates, refresh-token revocation, cleanup, hook rollback/revalidation/reentrancy and after-commit observation. Fixed node 9.12.2 HTTP reference tests also pass; application RAR policies differ as documented. Installed-gem refresh smoke and access-token-initiated grant-wide revocation remain incomplete. This is not a refresh release-readiness declaration.

## Ping concurrency and transport failures (2026-09-30)

Ruby4.0.6 SQLite/PostgreSQL17/MySQL8.4 and Ruby3.3.12/3.4.11 SQLite each pass **179 tests**, 1613–1616 assertions, no failures/errors/skips. [DB log](validation/db-matrix-latest.txt), [Ruby log](validation/ruby-matrix-latest.txt), [host log](validation/ping-concurrency-tests.txt). Barrier tests cover collection during blocked automatic notification and two simultaneous retries on distinct connections, one issuance and replay revocation. Signed-request/user-code/ping composition uses only the signed notification token.

Installed-gem HTTPS smoke additionally stalls a response until timeout, retries explicitly, and runs without trusting the receiver CA to prove certificate rejection before credentials reach HTTP. Approval persists and token collection remains available. No runtime code change was required. Process-crash and multi-process delivery remain outside this evidence.

## Optional ping (2026-09-30)

Ruby4.0.6 SQLite/PostgreSQL17/MySQL8.4 and Ruby3.3.12/3.4.11 SQLite each pass **176 tests**, 1590–1593 assertions, no failures/errors/skips. [DB log](validation/db-matrix-latest.txt), [Ruby log](validation/ruby-matrix-latest.txt), [host log](validation/ping-tests.txt). Includes private delivery migration/storage, outer-commit timing, rollback, failure persistence, retry, endpoint changes and cleanup cascade. Installed-gem smoke uses actual HTTPS with certificate verification and tests 200/204, 503/302, explicit retry and token retrieval. Concurrent delivery and adverse TLS/timeout coverage remain incomplete.

## Outbound address boundary (2026-09-30)

Ruby4.0.6 SQLite/PostgreSQL17/MySQL8.4 and Ruby3.3.12/3.4.11 SQLite each pass **171 tests**, 1531–1534 assertions, no failures/errors/skips. [DB log](validation/db-matrix-latest.txt), [Ruby log](validation/ruby-matrix-latest.txt), [host log](validation/outbound-http-tests.txt). Includes public/special-use/mapped addresses, mixed DNS, IP pinning/hostname retention, default loopback rejection before HTTP, and response-size bounds. Real remote-JWKS fixtures opt into only their loopback address. Installed-gem smoke passes. Direct gem TLS/timeout and live rebinding cases remain unverified; node ping TLS evidence is separate.

## Optional user codes (2026-09-30)

Ruby4.0.6 SQLite/PostgreSQL17/MySQL8.4 and Ruby3.3.12/3.4.11 SQLite each pass **166 tests**, 1480–1483 assertions, no failures/errors/skips. [DB log](validation/db-matrix-latest.txt), [Ruby log](validation/ruby-matrix-latest.txt), [host log](validation/user-code-tests.txt). Tests cover required callback, missing/invalid/optional policy, eligible account, no raw persistence, no dispatch on rejection, callback exceptions and signed-inner parameter isolation. An existing one-second grant-expiry test exposed a wall-clock boundary race; its creation/completion now use the same injected clock as issuance. No production expiry behavior changed.

The complete node OP tests missing/wrong code before dispatch and separate customer approval before issuance. Installed-gem extension smoke combines user code with signed requests, ID Token hints, claims/resources/RAR. These fixtures do not implement production user-code storage or anti-brute-force policy.

## Remote JWKS transport and cache (2026-09-30)

Ruby4.0.6 SQLite/PostgreSQL17/MySQL8.4 and Ruby3.3.12/3.4.11 SQLite each pass **162 tests**, 1438–1441 assertions, no failures/errors/skips. [DB log](validation/db-matrix-latest.txt), [Ruby log](validation/ruby-matrix-latest.txt), [host log](validation/remote-jwks-tests.txt). Real loopback HTTP exercises cache reuse, key rotation after explicit invalidation, untrusted header URLs, malformed/empty JWKS, HTTP failure and connection refusal. The scoped error mapping preserves actual client-authentication failures. Installed-gem smoke passes after the runtime fix. Host execution requires loopback bind permission; production TLS and distributed cache behavior are not covered.

## Optional signed requests (2026-09-30)

Ruby4.0.6 SQLite/PostgreSQL17/MySQL8.4 and Ruby3.3.12/3.4.11 SQLite each pass **160 tests**, with 1414–1417 assertions and no failures/errors/skips. [DB log](validation/db-matrix-latest.txt), [Ruby log](validation/ruby-matrix-latest.txt), [local log](validation/signed-request-tests.txt). Includes metadata/migration, independent authentication, required claims, signature/key filtering, duplicate JSON rejection, repeated request semantics and inner-only claims/resource/RAR processing. Installed-gem opaque/JWT extension examples now sign their requests with a separate client key. Remote JWKS and broader algorithm/configuration combinations remain incomplete.

## Optional id_token_hint (2026-09-30)

Ruby4.0.6 SQLite/PostgreSQL17/MySQL8.4 and Ruby3.3.12/3.4.11 SQLite each pass **155 tests**, with 1336–1339 assertions and no failures/errors/skips. [DB log](validation/db-matrix-latest.txt), [Ruby log](validation/ruby-matrix-latest.txt), [local log](validation/id-token-hint-tests.txt). Covers expired hints requiring new approval, unchanged ordinary decoder expiration, retained keys, signature/claim rejection and actual RSA/EC/HMAC issuance/reuse. Installed-gem smoke also confirms a real issued ID Token creates a pending request. Encrypted hints and the full algorithm/feature cross-product remain unverified.

## optional login_hint_token（2026-09-30）

Ruby4.0.6のSQLite/PostgreSQL17/MySQL8.4、Ruby3.3.12/3.4.11のSQLiteで各 **149 tests、failure/error/skipなし**（1245〜1248 assertions、競合順序による分岐差）。[DBログ](validation/db-matrix-latest.txt)、[Rubyログ](validation/ruby-matrix-latest.txt)。hint排他、型/長さ、resolver必須、client context、有効account、承認identity、raw token非保存、pollによる上書き不可、受付後の機能無効化を検証した。

node参照OPのhint callbackと署名済みID Token subjectも成功。配布gemのopaque/JWT claims/resource/RARフローにlogin_hint_tokenを組み合わせて成功した。fixtureは固定値を解決するもので、本番向けJWT/opaque検証器の安全性を保証するものではない。

## RAR競合と承認側の機能無効化境界（2026-09-30）

Ruby4.0.6のSQLite/PostgreSQL17/MySQL8.4、Ruby3.3.12/3.4.11のSQLiteで各 **145 tests、failure/error/skipなし**（1199〜1202 assertions）。[DBログ](validation/db-matrix-latest.txt)、[Rubyログ](validation/ruby-matrix-latest.txt)。競合の順序で期待分岐が変わるためassertion数には差がある。異なるnarrowingを合成しないこと、取消し完了後の有効token不在、新形式consentを結び付けた旧要求が機能無効化をすり抜けないことを検証した。

node全OPのRAR再引換え後のopaque introspectionも成功。配布gemの基本・opaque/JWT claims/resource/RAR smokeを修正後に再実行して成功した。新しい実装欠陥の修正であり、全体の整合化完了や独立監査の完了を意味しない。

## optional RARの受付・発行接続（2026-09-30）

Ruby4.0.6のSQLite/PostgreSQL17/MySQL8.4、Ruby3.3.12/3.4.11のSQLiteで各 **141 tests / 1126 assertions、failure/error/skipなし**。[DBログ](validation/db-matrix-latest.txt)、[Rubyログ](validation/ruby-matrix-latest.txt)。クライアント型制限、保存済み承認、必須policy、型検証、hook後再確認、rollback、JWT/opaque出力とID Token除外を検証した。

配布gemでもclaims/resource/RAR併用の追加migration、承認、nonce/at_hash、署名、introspection、UserInfo拒否、再引換えが成功。[ログ](validation/node-alignment-package.txt)。型固有の正しさは導入アプリのpolicyに依存する。[導入責務と未検証範囲](authorization-details.md)。

## RARの保存・形式検証基盤（2026-09-30）

Ruby4.0.6のSQLite/PostgreSQL17/MySQL8.4、Ruby3.3.12/3.4.11のSQLiteで各 **135 tests / 1082 assertions、failure/error/skipなし**。[DBログ](validation/db-matrix-latest.txt)、[Rubyログ](validation/ruby-matrix-latest.txt)。JSON 2.18.0で重複キー・不正UTF-8を拒否し、nullable列追加で既存要求・承認・token・clientを保持することを検証した。配布gemの基本・claims/resource smokeも成功。RAR全体は未実装で、これらは対応完了の証拠ではない。

## 配布gemの追加機能検証（2026-09-30）

`bin/verify-package` が一時ディレクトリへインストールしたgemで `examples/extensions_smoke.rb` を実行するように拡張。claims/resourceのmigration、保存済み承認、opaque/JWT発行、公開JWKSによるID TokenとJWTの署名検証、nonce/auth_time/at_hash、承認scope・audience・属性の限定、UserInfo拒否、再引換えを検証した。opaqueではintrospectionによる失効、JWTではunsupported_token_typeも確認した。コードのロード先がインストール済みgem内であることを実パスで検査する。

基本フローと追加2フローすべて成功。[ログ](validation/node-alignment-package.txt)。この検証はRuby4.0.6/SQLiteと既存ローカル依存gemを利用し、依存のネットワーク取得や公開は行っていない。ライブラリ本体に変更はないため、DB/Ruby matrixは再実行していない。

## resource JWT introspection境界（2026-09-30）

Ruby4.0.6/SQLiteで **130 tests / 1020 assertions、failure/error/skipなし**。[ログ](validation/resource-introspection-tests.txt)。node全OPでは発行直後・再引換え後とも構造化JWTをunsupported_token_typeで拒否することを確認し、gemのCIBA resource JWTにも適用した。配布gemの生成・一時インストール・基本HTTP smoke成功。他DB/Rubyの最新matrixは以下の129テスト時点で、この追加テストの実行結果ではない。

## resource併用・選択callbackの追加検証（2026-09-30）

Ruby4.0.6のSQLite/PostgreSQL17/MySQL8.4、Ruby3.3.12/3.4.11のSQLiteで各 **129 tests / 997 assertions、failure/error/skipなし**。[DBログ](validation/db-matrix-latest.txt)、[Rubyログ](validation/ruby-matrix-latest.txt)。resource専用の同時poll、claims併用、上流resource機能とのJWT/introspection接続、改ざん署名・別issuer拒否を含む。node全OPの省略時callback比較と配布gemの基本HTTP smokeも成功。

## optional resource対応（2026-09-30）

Ruby4.0.6でSQLite/PostgreSQL17/MySQL8.4、Ruby3.3.12/3.4.11でSQLiteの各 **125 tests、failure/error/skipなし**（960〜961 assertions）。[DBログ](validation/db-matrix-latest.txt)、[Rubyログ](validation/ruby-matrix-latest.txt)。scope/audience分離、JWT/opaque UserInfo拒否、opaque introspection、policy変更、発行失敗rollback、列追加を含む。配布gemの生成・一時インストール・HTTP smokeも成功したが、package smoke自体は従来の基本フローである。

node-oidc-provider 9.12.2全OPのNode24.21.0試験も成功。空のresource permissionはOIDC permissionへのfallbackを起こさないことを追加実測した。[参照ログ](validation/node-full-op-lts.txt)。追加policyと組合せの残件は[resource対応範囲](resources.md)に記録。

## 旧JWTのclaims分離修正（2026-09-30）

Ruby4.0.6でSQLite/PostgreSQL17/MySQL8.4各 **117 tests / 896 assertions、failure/error/skipなし**。[DBログ](validation/db-matrix-latest.txt)。旧JWTの保存行がなくなった後も、他の発行分の明示claim許可を利用しないことを追加検証した。Ruby3.3/3.4は直前の116テスト時点の検証で、今回の追加ケースは未実行。

## optional claims対応後の最新matrix（2026-09-30）

Ruby3.3.12/3.4.11のSQLiteとRuby4.0.6のSQLite/PostgreSQL17/MySQL8.4で各 **116 tests / 889 assertions、failure/error/skipなし**。[claims仕様](claims.md)の要求・承認・拒否、両応答先、poll改変、request valueの反射防止、UserInfoのトークン別分離、JWT取消し、既存行を保持するmigrationを含む。デフォルト無効の既存フローも回帰検証した。以下は段階別の履歴。

## nonce対応後の最新matrix（2026-09-30）

Ruby3.3.12/3.4.11のSQLiteとRuby4.0.6のSQLite/PostgreSQL17/MySQL8.4で各 **111 tests / 812 assertions、failure/error/skipなし**。既存要求を保持するnonce列の追加、カスタム列名、ID Tokenへの保存値の反映、poll時の上書き拒否を含む。node24.21.0の完全な参照OPでも署名検証後のnonce一致を確認した。以下は過去の段階別記録。

## Grant既定期限の整合化（2026-09-30）

新規Grantの既定期限を14日に変更。`ciba_grant_lifetime`設定、明示期限・明示nil、既存レコード保持と期限切れ時の発行拒否を検証した。Ruby4.0.6でSQLite/PostgreSQL/MySQL各 **108 tests / 795 assertions、failure/error/skipなし**。[ログ](validation/db-matrix-latest.txt)。nodeの完全なOPでも、再読込した保存済みGrantのexp-iatが14日であることを追加確認した。

## 最新Ruby検証（2026-09-30）

`./bin/test-rubies` が成功。固定DockerイメージのRuby3.3.12・3.4.11でそれぞれSQLiteの **104 tests / 757 assertions、failure/error/skipなし**。[ログ](validation/ruby-matrix-latest.txt)。Ruby4.0.6の3種類のDB検証と合わせた対応証拠であり、全Ruby×全DBの直積やJRubyの検証ではない。公開APIの拡張レビューは[こちら](research/consent-api-evolution.md)。

## 最新DB検証（2026-09-30）

`./bin/test-databases --seed 3363` をDockerで実行し、Ruby4.0.6 / SQLite・PostgreSQL17・MySQL8.4でそれぞれ **104 tests / 757 assertions、failure/error/skipなし**。最新の保存済みGrant、JWT認証、同時poll、取消し競合、rollback、migration up/downを含む。[成功ログ](validation/db-matrix-latest.txt)。初回のMySQL実行ではJWKSのVARCHAR容量と外部キー付き列の削除で16 errorsが出たため、テストschemaをTEXTにし、migration例とテストの削除を`drop_foreign_key`へ修正した。[修正前ログ](validation/db-matrix-before-fixes.txt)。ビルド時の依存gem取得も成功し、終了後に専用コンテナとネットワークを削除した。

node-oidc-provider v9.12.2の完全なOPを用いたHTTP検証も追加した。[手順・比較範囲](../test/reference/full-op/README.md)。以下のDocker接続不可・DB別未検証という記録は当時の履歴であり、この追記で更新する。

最新追記: 結果再取得時のGrant取消し・拒否結果の消費・期限判定順を変更し、104 tests / 757 assertions成功。変更後のpkg artifactを `mise exec ruby -- ruby bin/verify-package` で再生成・一時インストールして検証した。再引換えによる取消しも確認。ログは `validation/node-alignment-package.txt`。以下は途中段階の検証履歴である。

2026-09-29。初版公開に向けたローカル検証を実施した。RubyGemsへの公開・GitHubへのpush・タグ作成は行っていない。

## node-oidc-provider整合化の途中状態（2026-09-30）

要求TTLの既定600秒、binding_messageの既定値・差替えpolicy、保存済みCIBA Grant・結果API・関連トークン取消し・必須のAD起動callbackを変更。承認フック後のGrant再検証・デモの結果API移行、共通OIDC属性providerへの接続・承認scope限定・browser session非依存も検証。Ruby4.0.6 / SQLiteで100 tests / 731 assertions成功。[整合化作業](node-alignment.md)は継続中で、リリースの完了判定ではない。変更後のgemを再生成し、一時ディレクトリにインストールしてsmoke testを実行した。Discovery・保存済みGrant/result API・poll・署名付きID Token・再引換え拒否・関連token取消しを確認。依存gemは既存ローカル環境を利用しており、ネットワーク越しの依存解決は未検証。Docker socketは現在もpermission deniedで、DB別検証は未完了。検証ログ: `validation/node-alignment-package.txt`。

## 要件・セキュリティレビュー後の状態（2026-09-29）

`docs/security-review.md` と `docs/requirements-audit.md` が最新レビュー記録。JWT認証の必須claim・再利用防止・認証経路の分離、エラー処理、interval保存型を修正した。以下の50/46テストの記録と `pkg/` のgemはこの修正より前のもの。今回の依頼は要件監査と不足テスト・修正までで、配布gemの再ビルド・公開はしていない。

修正後のローカル検証は76 tests /563 assertions、failure/error/skipなし（Ruby4.0.6 / SQLite）。

現在のsandboxではDocker socketへの接続がpermission deniedとなるため、変更後のPostgreSQL/MySQL検証は未実施。新しいJWT replay ledgerを含む変更について、以前のDB matrix成功を引き継いで保証しない。公開前にDB別検証と配布物の再生成が必要。

## 認証方式制限の修正（以前の同日追記）

OP全体へのbasic/post限定を削除し、CIBAでも上流の有効なconfidential認証方式を利用する形に変更。Discoveryの方式一覧は上流のまま保持。JWT assertionのBackchannel audience受理をCIBA Core §7.1に合わせた。

修正後はmacOS arm64 / Ruby4.0.6 / SQLiteで **50 tests / 376 assertions、失敗・エラー・skipなし**。private_key_jwtとclient_secret_jwtのCIBA start/poll、非CIBA authorization_codeとの共存、不正署名/audience、認証方式二重指定、公開クライアント拒否を追加検証した。DB制御は変更していないため、この修正ではDocker matrixを再実行していない。下記matrix・クリーンインストール・実HTTPの実績は修正前の46テスト版である。配布gemは修正後のコード/docsから再ビルドした。

## 検証済み構成（認証方式修正前）

| Ruby | DB | 結果 |
|---|---|---|
| 3.3.12 (Linux arm64) | SQLite 3.53.2 | 46 tests / 355 assertions、失敗・エラー・skipなし |
| 3.4.11 (Linux arm64) | SQLite 3.53.2 | 同上 |
| 4.0.6 (Linux arm64) | SQLite 3.53.2 / WAL | 同上 |
| 4.0.6 (Linux arm64) | PostgreSQL 17.11 / READ COMMITTED | 同上 |
| 4.0.6 (Linux arm64) | MySQL 8.4.11 / InnoDB / REPEATABLE READ | 同上 |

macOS arm64 / Ruby4.0.6 / SQLiteでも46テストが成功。上流とドライバはrodauth-oauth1.7.0、Rodauth2.28.0、Sequel5.108.0、JWT3.3.0、sqlite3 2.9.6、pg1.6.3、mysql2 0.5.7。正確な依存解決はGemfile.lockに記録。

実行コマンドは `./bin/test-databases --seed 3363` / `./bin/test-rubies`。生の結果はリポジトリの `docs/validation/databases.txt` / `rubies.txt` に保存。DBコンテナ・ネットワークは削除済み。イメージとビルドキャッシュは再利用のため残した。

## 配布・導入確認

- `gem build rodauth-ciba.gemspec` 成功。成果物は `pkg/rodauth-ciba-0.1.0.gem`。
- ソースリポジトリをマウントしないクリーンなRubyコンテナで生成gemとSQLite adapterをインストールし、gem内の `examples/smoke.rb` を実行。
- Discovery、要求受付、Ruby承認、poll、JWKSによるID Token署名・issuer・audience・subjectの検証、refresh token無しを確認。
- 実HTTPでWEBrickサーバーとCLIクライアントを起動し、ブラウザ用フォームのGET/cookie/CSRF付きPOSTを経由した承認後にクライアントが署名検証に成功。
- 明示migrationのup/down、カスタムtable/column mapping、既存authorization_code、非CIBA DCR検証への委譲をテスト。
- gemの配布対象はlib、選択した公開docs、examples、README/LICENSE/CHANGELOGに限定。APIキー、開発DB、研究用Jev入出力、無関係なファイルは含めない。

homepageは未設定（リポジトリ公開URLが未提供）。gem buildのこの警告は配布を妨げない。名前/ライセンス/著作者の初期値はrodauth-ciba / MIT / rodauth-ciba contributors。2026-09-29のRubyGems API照会で同名gemは404だったが、名前の予約や将来の取得を保証するものではない。

## 実験から修正した事項

- 内側失敗を外側transactionが捕捉するケースにsavepointを導入。
- pending pollの読み取りをDBのロックに揃え、反復読み取りsnapshotの古さに依存しないようにした。
- Basic credentialのform decodingと認証方法の二重指定をCIBA経路で処理。
- 新しいRubyプロセスでJWT backendを明示ロードし、事前にJWTがrequireされているテスト環境への依存を除去。
- Rack3のrewind不能な入力を扱い、実HTTPとMockRequestの差を回帰テストで固定。

## 限界と公開判定

宣言した初版範囲について、公開を妨げる既知の失敗は残っていないと判断する。完全な仕様全機能や全DB/全隔離レベルへの保証ではない。

- OIDC Conformance Suiteそのもの、認定試験、第三者security auditは未実施。参照したSuiteケースと各要求の対応は `protocol-coverage.md` に記載。
- GitHub Actionsを用意し、同等のローカルmatrixを実行した。まだremoteがないためhosted CIの実績はない。
- Ruby3.3/3.4とPostgreSQL/MySQLの全組合せ、他DB、他隔離レベル、分散ノード、DB failover、長時間負荷は未検証。
- 観測・通知callbackはbest-effort。厳密な監査・配送はアプリの同DB outbox等を使う。失われたtoken成功応答は再取得不可。
- アプリの本人確認、業務認可、TLS/proxy設定、rate limit、上流schema、永続鍵管理は導入先が担う。デモの固定ユーザー・HTTP・平文fixture secretは本番向けではない。

`docs/research` と `implementation-contract.md` は設計履歴。現行の公開契約はREADME / api.md / operations.mdを参照する。
