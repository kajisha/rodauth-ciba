# Changelog

## 0.2.0 - unreleased

Prepared on 2026-10-21; RubyGems publication is pending.

The official OpenID Conformance Suite has not been executed. Refresh tokens,
pairwise subjects and dynamic CIBA registration remain experimental and disabled
by default. This release does not claim certification or full CIBA conformance.
Do not run old and new workers together during this upgrade.

- Keep initial and refreshed token identity/key metadata bound to the successful
  client authentication snapshot across concurrent registration updates.
- Preserve issued UserInfo subjects after a client changes its subject_type,
  including opaque/JWT tokens without the optional claims capability.

- Bind refresh ID Tokens to the actual initial issuer/subject/audience and
  disclosed auth_time using versioned JSON in existing storage. Preserve the
  context through rotation and pairwise sector changes; omit refresh nonce.
- Reject legacy or invalid refresh contexts before hooks or mutations. This
  requires reauthentication for old refresh tokens and coordinated worker updates;
  no automatic data migration or new database column is introduced.

- Enforce requested public/pairwise subjects and essential ACR at approval,
  issuance and refresh; preserve ordinary value/values filters on issued tokens.
- Keep pairwise UserInfo subjects bound to their issuance and prevent mandatory
  nonce or signed UserInfo claims from bypassing qualifier validation.
- Accept positive integral JSON numbers in signed requested_expiry.

- Measure CIBA request expiry from handler receipt before client/hint validation,
  without extending it for synchronous processing delays.
- Require saved authentication time for accepted max_age and essential auth_time
  requests during approval, issuance and refresh without inventing timestamps.
- Add a responsibility-separated Core final requirement ledger and explicit
  conformance-suite acceptance gates; no certification or full-conformance claim.

## 0.1.0 - 2026-10-11

First release of the CIBA OpenID Provider extension for rodauth-oauth.

- Require saved-consent authorization for optional refresh issuance and renewal.

- Poll delivery, Discovery, TLS/form request validation and confidential client
  authentication, including integration with upstream JWT client authentication.
- Ruby completion and saved-consent APIs, idempotent completion, account/client
  binding, transactional token issuance and replay handling.
- Same-database Sequel storage, explicit migrations, cleanup, transactional hooks
  and best-effort post-commit observation events.
- Optional ping, additional identity hints, signed requests, user codes, claims,
  resource indicators, authorization details and request context, with documented
  activation settings and application callbacks.
- Optional DPoP, mTLS and ID Token encryption integrations with documented limits.
- Bounded outbound HTTP and JWKS caching with explicit freshness and a capped,
  publisher-authorized stale-if-error allowance.
- HTTP 401 `invalid_client` for absent CIBA client authentication; rejected polls
  preserve approval and allow a legitimate authenticated retry.
- Startup rejection of upstream single-row OAuth token storage, preserving token/consent provenance.
- Saved `require_auth_time` enforcement during approval, issuance and refresh, without fabricating timestamps.
- Local approval/client examples, installed-package smoke tests and Ruby/DB CI.

Refresh tokens, pairwise subjects and dynamic CIBA registration are experimental,
disabled by default and excluded from the initial supported release scope. Push
and encrypted ID Token hints are not implemented. This is not an OpenID Certified
implementation or a claim of conformance for every optional-feature combination.
See [README](README.md) and [release readiness](docs/release-readiness.md).

Detailed intermediate changes are retained in the repository's
[development history](https://github.com/kajisha/rodauth-ciba/blob/main/docs/research/pre-release-development-history.md).
