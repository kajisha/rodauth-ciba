# 0.1.0 release readiness

RubyGems publication is pending. This document separates the supported release
scope from historical development notes and opt-in experiments.

## Scope

The default integration uses poll, login_hint, public subjects and static
confidential client registration. The README and individual feature contracts
specify optional capabilities and application responsibilities. Refresh tokens,
pairwise subjects and dynamic CIBA registration remain experimental, disabled by
default and excluded from the initial supported release scope. Push and encrypted
ID Token hints are not implemented. This is not OpenID Certified.

The gem requires Ruby >=3.3 and the dependency versions in its gemspec. Application
DB adapters, account/OAuth schemas, trusted identity resolution, approval UI,
notification transport and business authorization are application responsibilities.

## Published baseline evidence

The [authentication-fix commit](https://github.com/kajisha/rodauth-ciba/commit/3791a53caae7ab6fbe6793fdb1646d7e5074c951)
passed [hosted CI](https://github.com/kajisha/rodauth-ciba/actions/runs/36710533803):
Ruby 3.3/3.4/4.0 SQLite and the Docker SQLite/PostgreSQL/MySQL job.
Its local full run passed410 tests /10,844 assertions with two existing SQLite
row-lock skips. The latest pre-release cleanup verification is recorded below.

Jev's3.95/4 score (confidence0.96) concerned only the missing-client-authentication
fix. It is not an overall conformance score or a release gate.

## Cleanup review

- README, CHANGELOG and the release goal now distinguish the current release
  scope from intermediate implementation restrictions. Original changelog notes
  are preserved in the repository's pre-release development history.
- The gemspec declares homepage, source, issue tracker and changelog URLs.
- Static method, constant and instance-variable reference searches were checked
  against Rodauth's dynamic hooks, upstream overrides and public migration APIs.
  A single textual occurrence alone is not evidence of dead code.
- Removed an unreachable recipient-nil check and safe navigation in ID Token
  encryption. The candidate array is local and checked for emptiness before
  min_by, so successful selection always returns a pair.
- No broad authentication/state-machine refactor was justified for this release.
  Existing security boundaries and separate extension modules are retained.

Test execution information is used to identify review candidates, not to prove
that every unused branch is dead or every feature combination is covered.

## Current cleanup verification

The full suite before the one-line recipient-selection simplification passed410
tests /10,844 assertions, zero failures/errors, with two existing SQLite row-lock
skips. Runtime line coverage recorded2369 of2449 executable library lines;
13 uncalled method definitions were application-overridden callbacks or default
error reporters, not unused APIs. All other recorded library method definitions
were exercised. This is execution evidence from Ruby4.0.6/SQLite, not branch
coverage or proof of absence of dead code.

[Full test log](https://github.com/kajisha/rodauth-ciba/blob/main/docs/validation/release-code-review-tests.txt)
and [per-file execution summary](https://github.com/kajisha/rodauth-ciba/blob/main/docs/validation/release-code-coverage.json)
are kept in the repository. Line locations refer to the pre-cleanup source.

After removing the redundant check, the encryption regression selection passed
76 tests /4,873 assertions, zero failures/errors, with one existing SQLite skip
([log](https://github.com/kajisha/rodauth-ciba/blob/main/docs/validation/release-encryption-cleanup-tests.txt)).
The selection includes the shared integration tests loaded by these test files.

The updated gem passed `bin/verify-package`: build, temporary installation outside
the checkout, and all installed HTTP/TLS smoke flows
([log](https://github.com/kajisha/rodauth-ciba/blob/main/docs/validation/release-cleanup-package.txt)).
Dependencies were reused from local installations; this does not test fresh
network dependency resolution. After recording these results, the artifact was
rebuilt with identical runtime code and updated documentation; its final SHA256
is in `pkg/rodauth-ciba-0.1.0.gem.sha256` (local build output, not committed).
The cleanup has not rerun the full Ruby/DB matrix locally; the hosted results
above are for the preceding commit.
