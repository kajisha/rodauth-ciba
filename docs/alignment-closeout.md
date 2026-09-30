# Alignment closeout

This is the current work queue for alignment with node-oidc-provider 9.12.2,
not a replacement for the original roadmap or its 159-row CIBA catalog.
Earlier validation logs are historical evidence, not a test of later changes.

## Unresolved behavior differences

1. **Completion errors: implemented and verified.** The gem now
   saves a generic error code, consumes it on first poll, rejects replay and
   retains the transactional negative-completion hooks. Existing denials have
   an explicit nullable-column migration. Technical failure emits `failed`
   instead of reporting customer refusal. Three DBs each pass18 tests /339
   assertions ([log](validation/completion-errors-matrix.txt)). The reference
   accepts custom codes but does not round-trip application descriptions, as
   [measured](research/completion-error-boundaries.md). The installed artifact also passes, including the new custom-error flow
   ([log](validation/completion-errors-installed.txt)); the full Ruby3.3 regression passes399 tests /10,719 assertions
   ([log](validation/completion-errors-full-ruby33.txt)), with two SQLite row-lock
   skips. Ruby3.4 three-DB full regression also passes399 tests on each backend.
2. **Remote key cache: standards-informed policy implemented.** Explicit HTTP
   freshness replaces the minimum60-second floor. A failed retrieval can use old
   keys only with publisher stale-if-error, capped at60 seconds with fixed expiry.
   Authentication/encryption share one policy without a dedicated switch.
   This is an intentional reference difference approved after the standards/Jev
   review. See [operations](operations.md#remote-jwks-cache-lifetime) and
   [decision](research/jev-alignment-cache-rfc-review.md).
3. **Hint validation profile: implemented and integration verified.** The gem
   now follows the measured reference azp/typ/time-claim behavior for identity
   hints, including optional iat/exp and fractional times. Unknown critical JOSE
   extensions remain rejected; b64=true is recognized. All accepted hints still
   require new approval. The [three-DB subset](validation/id-hint-validation-matrix.txt)
   passes31 tests /983 assertions per DB. The installed gem also passes the new
   profile scenario and existing smokes ([log](validation/id-hint-validation-installed.txt)).
   The latest full Ruby3.3/4.0 runs include this change and pass400 tests;
   the updated Ruby3.4 three-DB run also passes400 tests on every backend. User-code activation
   remains an explicit opt-in configuration adaptation in CIBA-013.

## Evidence reconciliation

- CIBA-072 is reconciled against the [mandatory parameter inventory](research/required-parameter-inventory.md) and is now verified. CIBA-067 is also reconciled against the [supported parser inventory](research/request-parameter-inventory.md); policy differences remain separate. Do not require every possible extension combination or
  count these aggregate rows as new features. The new signed-request omission
  regression removes each required field, supplies valid unsigned outer values,
  and proves rejection without requests, grants or dispatch. Its valid control
  still dispatches a pending request: [3 tests / 119 assertions](validation/signed-required-omissions.txt).
- Keep the other partial rows explicit: user-code activation policy (013), shared
  lifetime timing (080), retained poll throttling (124), absent conditional
  error_uri output (138), and deployment hint-retention policy (151). Their
  classification does not automatically require new runtime features.
- Review the existing roadmap's remaining authentication, registration,
  refresh and transport claims against the evidence already collected. Identify
  a concrete missing behavior before adding another combination test.

## Final validation gate

Current source is recorded in the
[runtime/test manifest](validation/id-hint-validation-source-manifest.json).
Subsequent gemspec/verifier edits add missing guide files to the artifact without
changing runtime behavior. Latest results:

| Gate | Result |
|---|---|
| Ruby3.3 / SQLite | 400 tests /10,747 assertions, no failures/errors, two row-lock skips ([log](validation/id-hint-validation-full-ruby33.txt)) |
| Ruby3.4 / SQLite | 400 /10,747, no failures/errors, two row-lock skips |
| Ruby3.4 / PostgreSQL | 400 /10,744, no failures/errors/skips |
| Ruby3.4 / MySQL | 400 /10,744, no failures/errors/skips ([three-DB log](validation/id-hint-validation-full-databases.txt)) |
| Ruby4.0.6 / SQLite | 400 /10,747, no failures/errors, two row-lock skips ([log](validation/id-hint-validation-full-ruby40.txt)) |
| Pinned reference npm test | Passed, including completion-error wire checks ([log](validation/alignment-consolidated-reference.txt)); subsequently modified lifecycle fixture also passes [hint-profile checks](validation/node-id-hint-validation-profile.txt) |
| Installed gem | Passed including new hint profile, completion failure/replay, migration guides and existing real-TLS smokes ([log](validation/alignment-closeout-installed.txt)); SHA256 ddf468c63c53e1d78783ff4c2875ce68ff765a3591a6ef54f1dfbdfdc196bf51 |

The containers use existing test images with current lib/test/examples mounted
read-only, not a fresh image build or dependency resolution. Ruby4.0 is local
macOS. SQLite skips are covered by the server-DB runs. The reference mTLS fixture
is separate from npm test and remains backed by its latest real-TLS execution;
it is not implicitly rerun by npm test. The prior395-test consolidated runs are
historical baselines preceding generic completion errors.

A passing test gate does not resolve the policy differences above. Do not
publish or mark the alignment goal complete until those differences and all
original roadmap obligations have been reconciled.

Accepted adaptations remain same-DB atomic issuance and Rodauth hooks
([ADR 0004](adr/0004-retain-atomic-issuance-and-stage-alignment.md)), and the
roadmap's retained polling interval behavior. App-owned UI, identity verification,
business consent, trusted proxy configuration and deployment availability are
application contracts, not automatically gem implementation tasks.

## Current decision gate

The cache-policy decision is now implemented. The user approved the
[standards-informed Jev decision](research/jev-alignment-cache-rfc-review.md).
Older minimum-floor results above and in historical logs do not describe the
current runtime. HTTP freshness directives take precedence; fallback is explicitly
publisher-authorized, bounded, and never renewed by failed retrievals.

The new cache is scoped per Rodauth configuration, bounded to1024 entries,
independent of upstream cache internals, and preserves existing explicit eviction
through `http_request_cache.uncache`. Malformed successful responses and security
failures invalidate stale eligibility; successful replacement/eviction prevents
in-flight stale snapshots from restoring old keys. See the operations guide for
custom-store and multi-process limitations.

This resolves the remote-cache policy work, not every obligation in the original
alignment roadmap. Do not infer overall release readiness from this change alone.

## Current cache validation

- Ruby3.3 and3.4 / SQLite: each10 tests /91 assertions, zero failures/errors/skips
  ([3.3](validation/jwks-stale-ruby33.txt), [3.4](validation/jwks-stale-ruby34.txt)).
- Installed gem: existing HTTP/TLS authentication/encryption smokes passed
  ([log](validation/jwks-stale-installed.txt)). Dependencies reused locally.
- Ruby4.0.6 / SQLite:410 tests /10,838 assertions, zero failures/errors,
  two existing row-lock skips ([full log](validation/jwks-stale-full.txt)).
- Database-specific concurrency is unchanged; this cache revision has not been
  rerun against PostgreSQL/MySQL. Those older matrix results are historical.


## Missing-client-authentication correction

CIBA Core section13 maps absent client authentication to401 invalid_client. The
previous400 invalid_request mapping for a request with neither a header, client_id
nor client_assertion is corrected at the Backchannel and CIBA poll endpoints.
Regression checks fail before the fix and pass afterward; rejected polls preserve
approval, create no grant and allow an authenticated retry. See
[before](validation/missing-client-auth-red.txt) and
[after](validation/missing-client-auth-green.txt). This deliberately differs from
the earlier reference-aligned error mapping. Other optional-authentication error
paths have not been exhaustively reassessed by this narrow correction.

Final Ruby4.0.6 / SQLite validation:410 tests /10,844 assertions, zero
failures/errors and two existing row-lock skips ([full log](validation/missing-client-auth-final.txt)).
The focused error/authentication regression run passed8 tests /171 assertions
([targeted log](validation/missing-client-auth-targeted.txt)).
