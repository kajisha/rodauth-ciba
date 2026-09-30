# Changelog

## 0.1.0 — publication pending

First release of the CIBA OpenID Provider extension for rodauth-oauth.

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
- Local approval/client examples, installed-package smoke tests and Ruby/DB CI.

Refresh tokens, pairwise subjects and dynamic CIBA registration are experimental,
disabled by default and excluded from the initial supported release scope. Push
and encrypted ID Token hints are not implemented. This is not an OpenID Certified
implementation or a claim of conformance for every optional-feature combination.
See [README](README.md) and [release readiness](docs/release-readiness.md).

Detailed intermediate changes are retained in the repository's
[development history](https://github.com/kajisha/rodauth-ciba/blob/main/docs/research/pre-release-development-history.md).
