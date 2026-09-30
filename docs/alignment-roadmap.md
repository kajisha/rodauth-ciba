# Staged alignment with node-oidc-provider

> Latest policy supersedes the historical minimum-floor notes below: use explicit
> HTTP freshness, and permit failed-fetch reuse only with publisher stale-if-error,
> capped at60 seconds without renewing deadlines. See [operations](operations.md#remote-jwks-cache-lifetime).


> Current cache decision: successful CIBA remote JWKS fetches now have a minimum
> 60-second lifetime for authentication and encryption, with no dedicated policy
> switch. This supersedes older shorter-TTL difference notes below. Reuse after
> failed refresh remains unresolved and is not implemented. See
> [alignment closeout](alignment-closeout.md#current-decision-gate).


The current [closeout queue](alignment-closeout.md) separates unresolved behavior
differences from evidence reconciliation and final validation. The historical
results below do not all describe the latest source state.

The original22 partial findings are [triaged](research/alignment-partial-triage.md)
into feature gaps, bounded coverage, shared limitations and adaptations. Sixteen have
since gained verified protocol evidence, including: Edwards signed requests, configured assertion algorithms,
ping response bodies and management updates, signed-request NumericDate, and
missing-client error mapping. One timing item is explicitly an unverified application contract; the current overlay has5 partial findings.
Edwards requests have fixed cross-library vectors, remote-key and installed
execution evidence. Classification is not completion of this roadmap.

Accepted on 2026-09-30: keep poll/login_hint for the initial release, retain atomic DB issuance, and pursue broader alignment in stages. Reference: node-oidc-provider v9.12.2. [ADR 0004](adr/0004-retain-atomic-issuance-and-stage-alignment.md) records the tradeoff; [current status](node-alignment.md) separates implementation from evidence. This is not a claim of feature parity or a commitment to ship every feature in the next release.

## Current requirement audit (2026-09-30)

This table is the current cross-workstream audit; the numbered sections below
remain the accepted plan. A passing subset does not close the broader objective.

Latest local regression (Ruby4.0.6 / SQLite): [380-test run](validation/alignment-latest-local.txt)
had zero assertion failures,18 socket-bind permission errors and two row-lock skips.
All18 affected tests then passed with local listener permission ([392 assertions](validation/alignment-local-socket-retry.txt)).
This is a two-stage local result, not a clean single-run result or a refreshed
supported-Ruby/three-DB matrix. It includes the signed/ping required-field regression
and the recent recipient-selection, real-TTL and management-overlap tests.

Subsequent registration correction: `require_auth_time` now rejects non-booleans,
persists explicit values and preserves false on management GET, matching the
[reference contract](research/registration-reference-contract.md#require_auth_time-boolean-metadata).
Ruby3.4 three-DB validation passes2 tests /95 assertions each. Token auth_time
emission/defaulting remains a separate behavior to compare; metadata validation
alone does not close that boundary.

The subsequent [authentication claim selection](authentication-claims.md) correction
saves request/client selection at acceptance and applies it on initial issuance and
refresh, with an explicit application scope mapping. The reference comparison covers
36 configurations with verified initial/refresh signatures; the Ruby3.4 three-DB
subset passes13 tests /951 assertions each. NULL legacy sources preserve their
previous disclosure contract; existing installations require an explicit migration.
This resolves the measured new-request auth_time/acr/amr output difference, not all
application claim policy combinations.

| Planned boundary | Current authoritative evidence | Remaining work / classification |
|---|---|---|
| Baseline lifecycle, persistence and package | [Full DB matrix](validation/alignment-current-databases.txt), [Ruby matrix](validation/alignment-current-rubies.txt), [installed artifact](validation/alignment-current-package.txt), [full reference OP suite](validation/alignment-current-reference.txt) | The pre-HMAC351-test baseline suite passes Ruby4.0.6 on SQLite/PostgreSQL/MySQL and Ruby3.3/3.4 on SQLite. SQLite has5,637 assertions and two row-lock skips; PostgreSQL/MySQL have5,634 assertions with no skips. The full configured reference suite and installed artifact smoke pass, including encrypted output and actual HTTPS recipient retrieval. Not all Sequel adapters, every Ruby × DB combination, or an independent audit. The159-item catalog now has103 verified boundaries,5 partial findings,17 reference-unsupported conditions,20 client duties and14 application contracts; all referenced test methods exist. These checks do not establish completion of broader alignment. |
| Request versus saved consent, scopes, nonce, claims, resources/RAR | `test/ciba_grant_test.rb`, `test/ciba_claims_test.rb`, `test/ciba_resources_test.rb`, `test/ciba_rar_test.rb`, `test/ciba_refresh_permissions_test.rb` | Implemented opt-in capabilities. Claim value/essential constraints and RAR semantics remain application policy; this is not arbitrary policy equivalence. |
| Other hints | [login hint token](login-hint-token.md), [ID hint](id-token-hint.md), `test/ciba_pairwise_test.rb`, installed smoke | Signed ID hints and application token resolver implemented. Pairwise hints resolve through an application callback to a canonical account and create a new pending request without inherited consent. Encrypted ID hints are rejected by both the gem and node v9.12.2 with encryption enabled ([measured boundary](research/id-token-hint-reference-contract.md#encrypted-hint-boundary-correction-after-direct-measurement)); this is not a missing parity feature. Arbitrary application resolver correctness is not established by the fixture. |
| ID Token signing and encrypted output | [ID hint/signing contract](research/id-token-hint-reference-contract.md), [encryption](id-token-encryption.md), independent jose probes, installed HTTPS recipient tests | Edwards signing/JWKS/hints now have independent verification, supported-Ruby, installed and refresh/pairwise evidence. RSA-recipient encryption supports two key algorithms and six content methods; independent jose checks issuance/refresh/tampering across36 combinations. DCR/defaults/removal and management recipient replacement are measured against the reference. HTTPS restrictions, cache eviction/rotation and retrieval-failure rollback are tested. CIBA HMAC signing/hints now use client secrets with three-DB and independent jose evidence. DCR secret lengths, installed-gem issuance/refresh/hints and backend secret replacement are verified; Ruby3.3/3.4 each pass354 tests/5,847 assertions ([evidence](validation/hmac-id-token-rubies.txt)). Backend replacement does not establish a standard rotation API. Client-secret-derived dir/AES-KW now has initial24-combination issuance/refresh and independent jose evidence ([contract](id-token-encryption.md#client-secret-derived-encryption)); installed-artifact coverage now passes16 configurations, and unrelated JWKS fetching is fixed with private-key authentication preserved; Ruby3.3/3.4 each pass358 tests/6,274 assertions ([evidence](validation/symmetric-encryption-rubies.txt)). AES-GCMKW now has a CIBA-local OpenSSL wrapping adapter with initial42-combination symmetric tests and84-token independent jose verification; the installed artifact passes28 symmetric configurations and Ruby3.3/3.4 each pass358 tests/6,724 assertions ([evidence](validation/gcmkw-rubies.txt)). ECDH has an initial CIBA-local adapter for four algorithms/four curves, with96 initial/refresh configurations and192-token independent jose validation; registration/Discovery, installed32-case validation and Ruby3.3/3.4 full361-test suites now pass; ECDH-specific HTTP/installed-HTTPS retrieval and sequential management pass, including Ruby3.4 three-DB regression; nonempty ECDH key_ops rejection is now aligned with reference import failures. Missing metadata-compatible recipients now return reference-style400 invalid_client_metadata with rollback, and RSA operation declarations are checked at selection/wrapping. Multi-key selection now validates after scoring and does not fall back from an unusable preferred key, with reference and three-DB evidence. Actual TTL expiry is measured: gem honors max-age=2 while reference retains keys for at least60 seconds; the cache policy difference remains open. A management PUT overlapping initial/refresh issuance now matches reference snapshot behavior in the measured three-DB cases in the [contract](research/ecdh-encryption-reference-contract.md). Remote-cache lifetime and failed-refresh retention differ; policy clarification is pending and no change is assumed. Encrypted input hints are a separate reference-unsupported boundary. |
| Signed requests / user code | [signed requests](signed-requests.md), [user code](user-code.md), remote JWKS tests | Implemented opt-in with documented stricter validation, key lookup and app-policy boundaries. |
| Ping | [ping contract](ping.md), actual HTTPS installed smoke, full node ping harness | Implemented opt-in. Process-crash recovery and durable delivery are not guaranteed by either measured handler; multi-process delivery remains unverified. Push is not a target of this reference version. |
| Refresh and revocation | [refresh](refresh-tokens.md), [AT revocation comparison](research/access-token-revocation-reference.md), package smoke | Implemented default confidential-client lifecycle plus hooks/cleanup. Legacy unmarked tokens retain upstream handling; arbitrary issue/rotation policies and sender-constrained refresh combinations are not established by current evidence. |
| Completion error types | [error boundary](research/completion-error-boundaries.md), `test/ciba_alignment_test.rb` | Generic completion error codes are now persisted and returned once, with migration, idempotency/conflict checks, transactional hooks and ping. Three DBs each pass18 tests /339 assertions. Normal pending/expiry remain state-derived; submitting pending as a completion is terminal as in the reference. Application descriptions are not exposed by this API. Final full regression is pending for this change. |
| Client registration and subject types | `CibaSupport::Registration`, `test/ciba_registration_test.rb`; [real node registration contract](research/registration-reference-contract.md), [installed package](validation/registration-package.txt) | Opt-in DCR lifecycle, rotation, ping/signature/user-code and RAR/resource/refresh composition implemented; defaults remain static-only. Deletion, input/storage repairs, update/opposite-client/delete-refresh concurrency, consent-before-client locking and rollback tested. Installed artifact covers basic registration/issuance/management rotation/deletion. The default_max_age registration boundary now validates safe integer values and persists them in explicit storage ([contract](research/registration-reference-contract.md#default_max_age-validation-and-persistence)); this does not implement freshness policy. Additional client-auth combinations and remaining metadata validation remain incomplete; race tests do not cover arbitrary app hooks or new-consent interleavings. An initial opt-in [pairwise integration](pairwise.md) now covers sector derivation, application subjects and opaque/JWT UserInfo/hints; opaque/JWT refresh, rotation and callback-failure rollback now have integration coverage; installed-gem TLS sector-document validation and bounded redirect following pass; sector-document cache reuse and fresh registration validation are tested; sector changes affecting issued-token UserInfo and refresh are tested using stored issuance subjects; sequential pending-request updates and installed pairwise issuance also pass; concurrent sector management/issuance now passes two opaque/JWT cases on all three DBs, with forced update-before-generation on PostgreSQL/MySQL ([log](validation/pairwise-concurrent-matrix.txt)); concurrent refresh/key replacement and arbitrary hook interleavings remain unverified. |
| Authentication/token capabilities | JWT client assertion, signed request, resource and revocation tests | Existing tested mechanisms are scoped to CIBA. The [DPoP reference contract](research/dpop-reference-contract.md) now has actual OP issuance/UserInfo/refresh evidence and a Ruby probe demonstrating incompatible jti, stale-proof acceptance and proof reuse. An initial CIBA token-endpoint boundary now fixes identifier/freshness/replay handling with same-DB rollback, proof-required policy and new-key confidential refresh; CIBA opaque/JWT UserInfo now verifies proof/key/ath, live issuance provenance and replay, with conjunctive token/expiry/revocation predicates. DPoP dynamic registration now covers boolean policy, storage, false/default responses, failed-update preservation and future-issuance policy replacement. Required/optional server nonce challenges, old-iat acceptance with valid nonce, cross-endpoint use, nonce expiry/secret rotation and replay-ledger retention now have reference/local evidence. Installed DPoP artifacts now pass DCR, nonce issuance, UserInfo and new-key refresh with explicit loaded-file provenance. POST UserInfo method binding and explicit plaintext/custom hash-column storage also pass the DPoP subset on all three DBs. Opaque CIBA DPoP introspection now returns active/cnf/type without proof presentation, while retaining authentication, token identity, expiry and revocation checks; resource audience/scope also have regression coverage. OIDC Discovery now preserves the introspection URL/auth metadata and DPoP algorithms from OAuth metadata; disabled features remain absent. Node omits the introspection auth-method list, while the gem retains upstream's existing list. The metadata correction passes 43 related local tests and installed-package validation. External resource enforcement, proxy handling, cluster nonce/clock behavior and broader combinations remain incomplete. Issuer-audience private_key_jwt/client_secret_jwt now match the measured CIBA issuance/refresh behavior, including wrong-audience and assertion-replay rejection (59 related tests on three DBs). The [mTLS real-TLS reference and Ruby probe](research/mtls-reference-contract.md) identified wrong certificate digests, missing UserInfo enforcement and self-signed auth500. An initial correction now implements explicit trust callbacks, certificate-DER matching/binding, opaque/JWT UserInfo, introspection and confidential refresh. Final mTLS/DPoP cases pass30 tests on three DBs. Installed artifacts now pass actual Ruby TLS for PKI/self-signed × opaque/JWT, including rejected absent/header-only/foreign certificates and bound UserInfo (mtls-installed-tls.txt). mTLS DCR now covers subject/binding metadata, storage, self-signed keys and management replacement, including actual node TLS clients and gem dynamic issuance. Installed mTLS DCR now passes the real TLS flow and management policy/credential changes in all four PKI/self-signed × opaque/JWT combinations. Capability is now advertised independently of per-client binding: CIBA ignores upstream global forcing while retaining old-token binding; 21 related cases pass on each DB and installed TLS checks pass with global forcing enabled ([contract](research/mtls-reference-contract.md#capability-versus-client-binding-policy)). Application-owned aliases now pass complete reference/installed-gem flows on separate TLS ports with a fixed canonical issuer ([contract](research/mtls-reference-contract.md#endpoint-aliases-are-application-deployment-configuration)); automatic alias routing is not a reference feature. Remote x5c cache retention and forced-expiry replacement now have reference and three-DB gem evidence; retrieval error mapping is corrected, while rejection after failed refresh is intentionally stricter than node ([contract](research/mtls-reference-contract.md#remote-x5c-rotation-and-retrieval-failures)). Installed-artifact remote rotation now passes HTTPS x5c retrieval, forced-expiry certificate replacement, refresh/new binding, retained old binding and failure/recovery in opaque/JWT configurations. A discovered JWT introspection cnf omission is fixed with live issuance validation; 14 cases pass on each DB ([contract](research/mtls-reference-contract.md#installed-https-certificate-rotation-and-jwt-introspection)). Real x5c TTL timing and deployed proxy/path rewriting remain unverified. DPoP alternate-origin binding now has reference HTTP and gem Rack/installed evidence; combined mTLS authentication+DPoP over real alias TLS now passes the reference and installed-gem fixtures (PKI/self-signed, with opaque/JWT gem tokens). Full mTLS support is not established. Remaining authentication combinations are also incomplete. |
| request_context | [Optional implementation](request-context.md), `test/ciba_request_context_test.rb`, full node HTTP harness and installed extension smoke | Implemented callback/storage boundary; app owns semantics. No automatic permission/token claim and no additional CIBA Core conformance claim. |
| Intentional transaction/poll differences | [ADR 0004](adr/0004-retain-atomic-issuance-and-stage-alignment.md), [failure contract](failure-contract.md) | Same-DB rollback and Rodauth hooks are accepted adaptations. Poll throttling and stricter validation are documented differences, not unimplemented node branches. |

The request-context reference test proves request_context is passed (including omission)
to the application's validation callback and stored in request.params; rejection
precedes device dispatch, and it is not automatically an ID Token claim. Node's
default callback raises until configured. The gem now provides an opt-in callback
and explicit nullable-column migration, without expanding claims/RAR to interpret
arbitrary business context.

## 1. Establish the initial release baseline

- Publish the [failure contract](failure-contract.md), including ambiguous responses, replay revocation and external effects.
- Verify current migrations, approval/consent binding, concurrent polling, rollback and revocation on PostgreSQL and MySQL as well as SQLite. Run the supported Ruby matrix starting at 3.3; report actual tested combinations rather than claiming all Sequel adapters.
- Exercise a complete reference OP and the gem with comparable client scenarios: pending, denial, success, replay, expiry, wrong client and issuance failure. Preserve the intentional atomicity difference and record adapter/transaction setup.
- Build and install the gem outside the checkout, run its documented example, and ensure Discovery and protocol coverage match the supported subset. Review the public request/consent APIs against the next stage before freezing them.

Exit evidence: reproducible commands and logs, no unresolved correctness/security defects in the supported subset, documented limitations. The latest three-DB matrix, Ruby3.3/3.4 SQLite matrix and complete reference-OP lifecycle comparison now pass; see [status](node-alignment.md). The [API evolution review](research/consent-api-evolution.md) is recorded. These are initial baseline evidence, not completion of broader alignment or an independent security audit.

## 2. Review how request and consent representations can grow

Compare node's claims, resource, nonce, RAR-related state and result errors with the existing request/saved-consent API. For each proposed extension, identify where requested and approved values differ, how issuance uses only approved values, and whether the upstream grant/token model supports it. Review consent expiry policy, including node's default versus the gem's optional expiry.

Exit evidence: concrete schema/API examples, rejection rules, forward migration and compatibility strategy. Preserve existing pending requests and issued-token provenance. Add fields and abstractions only when a selected capability needs them; do not create a generic framework in anticipation of all possibilities.

The [review](research/consent-api-evolution.md) supplies the proposed representation, compatibility rules and remaining gates. Individual increments still need final protocol mapping and implementation tests before activation.

## 3. Implement additional capabilities in independent increments

The following are comparison workstreams, not already implemented features or a fixed delivery order. Select the next increment using a concrete interoperability need and upstream support; keep the remaining gaps visible.

| Workstream | Required evidence before claiming support |
|---|---|
| Other hints, signed requests and user_code | Specification mapping, issuer/audience/signature or application-validation boundaries, identity binding and negative tests; Discovery/registration accurately describes support. |
| Ping delivery | Client registration and notification-token validation, delivery/retry policy, endpoint security and independent client integration. A need for ping does not require unrelated features. |
| Claims, resources and richer consent | Request/approval separation, scope and audience enforcement, rejection handling and regression tests preventing unauthorized claims or access. RAR needs its own requirements analysis. |
| Completion error types | Explicit supported error mapping, terminal-state/retry semantics and protocol tests for each accepted error. |
| Client registration, subject types, token/authentication capabilities | Check upstream support and node behavior separately; test selected mechanisms without imposing CIBA-specific restrictions on unrelated OP flows. Refresh tokens require lifecycle and revocation coverage before advertisement. |

For each increment, update the protocol coverage, migration/API documentation, independent integration evidence and package smoke test. Push is not a parity target merely because CIBA defines it: the referenced node version supports poll/ping. No certification claim follows from these tests.

## Deliberate differences and reconsideration

Same-DB rollback and Rodauth hooks remain the chosen adaptation. Consider durable one-attempt consumption only if an actual deployment requires consumption to survive issuance failure and process crashes. Consider configurable policies only when actual adopters require incompatible contracts, not from hypothetical demand.

The gem's advertised polling interval and `slow_down` differ from the referenced node handler. Keep the current behavior while reviewing interoperability evidence; absence of a branch in that handler is not evidence that every node deployment lacks rate limiting. Every remaining difference should be classified as an intentional adaptation, an unsupported capability or an unverified behavior before calling broader alignment complete.

Latest authentication-selection validation: [full local regression](validation/authentication-claims-full.txt),
Ruby4.0.6/SQLite385 tests /10,152 assertions, zero failures/errors, two row-lock
skips; [installed artifact](validation/authentication-claims-installed.txt) smoke
passes. The related Ruby3.4 three-DB subset above covers13 tests, not the full385.

Registration defaults: default_acr_values now validates configured strings,
preserves unique order in JSON storage/management GET, and supplies omitted
request acr_values. default_max_age now selects auth_time, including zero.
See the [contract](research/registration-reference-contract.md#default_acr_values-and-authentication-defaults)
for evidence and the remaining immutable max-age policy-input/empty ACR boundaries.

Maximum-age input is now [implemented and documented](max-age.md): the request
value takes precedence over default_max_age, its normalized seconds are saved
before device dispatch, and later metadata cannot reinterpret the request. Zero
represents fresh authentication; the application enforces freshness. Existing
request tables require the explicit nullable max_age migration. This closes the
previous missing device-policy input, not deployment authentication policy.

Latest max_age validation: [Ruby3.3/SQLite full suite](validation/max-age-ruby33.txt)
passes391 tests /10,418 assertions with two row-lock skips; the [Ruby3.4 three-DB
subset](validation/max-age-matrix.txt) passes22 tests /1,317 assertions per DB.
[Installed artifact](validation/max-age-installed.txt) passes smoke checks.
These are the measured combinations, not all Ruby × DB combinations.


The previously noted empty ACR boundary is corrected: an empty string uses
registered defaults like omission, including in signed requests without inheriting
unsigned outer values. [Reference/gem evidence](research/registration-reference-contract.md#empty-acr-request-correction)
covers the changed parameter/defaulting branch. Other parameter limits remain
separately tracked; no blanket relaxation of validation was made.

DPoP alias correction: [comparison](research/dpop-reference-contract.md#alternate-endpoint-origin-and-proxy-trust)
reproduces and fixes acceptance of canonical-origin proofs at another origin.
The issuer remains canonical; forwarding headers are ignored unless the app
explicitly supplies a trusted external endpoint through its callback.

CIBA ID Token projection now removes inherited access-token cnf, matching the
reference DPoP and real-TLS mTLS fixtures. Access-token/introspection confirmation
and proof enforcement remain tested. See the [comparison](research/dpop-reference-contract.md#id-token-versus-access-token-confirmation-claims).

The concrete mTLS-authentication plus DPoP-token alias gap is closed by
[real TLS integration](research/mtls-reference-contract.md#real-tls-aliases-with-certificate-authentication-and-dpop-tokens).
Both authentication methods pass in the reference; installed gem tests cover
all four method × opaque/JWT combinations. No further runtime change was needed.
Deployment proxy and cluster behavior remain application/integration boundaries.
