# Deployment and operating boundaries

Optional explicit claims require an additional schema migration and coordinated activation; see [claims operations](claims.md). The default base schema and default-disabled behavior do not require those columns.

The same activation boundary applies to [resources](resources.md) and [RAR](authorization-details.md). Issuance checks both the original request and its saved consent: if either records a capability whose flag is now disabled, collection returns invalid_grant without consuming the request or issuing a token. This includes old requests bound to new-format consent after migration and explicitly stored empty permission values. Legacy request/consent pairs whose new fields are both null retain baseline behavior. Do not use feature deactivation as a way to erase approval restrictions; drain or explicitly resolve affected work before changing capabilities.

## Database migration

New installations use the current base migration. When upgrading an earlier
development snapshot, add missing columns with explicit forward migrations;
do not rerun table creation. The current base request schema requires
`Schema.add_authentication_claims(db)`, `Schema.add_request_max_age(db)` and
`Schema.add_completion_error(db)` if those columns are absent. Each helper
accepts `table:` and `column:` for custom mappings. Existing NULL authentication
selection preserves legacy output; NULL max_age adds no freshness requirement;
NULL completion_error preserves access_denied for prior denials. If refresh is
enabled on existing storage, also add authentication_claims to
`:ciba_refresh_tokens` using `Schema.add_authentication_claims(db, table: :ciba_refresh_tokens)`.
Startup checks require these migrations before enabling the upgraded feature.
See [authentication claims](authentication-claims.md), [max_age](max-age.md) and
[completion errors](research/completion-error-boundaries.md) for the contracts.

Run `examples/migration.rb` as an explicit Sequel migration after the upstream account/application/grant schema exists. Add it under your app's numbered migration directory. Load Sequel's migration extension before running `Sequel::Migrator.run`. The example migration creates `ciba_grants` for saved consent, adds the `oauth_grants.ciba_grant_id` foreign key, creates requests referencing consent, and creates `ciba_client_assertions` for JWT replay protection. The down migration deletes CIBA request/consent/replay state and removes the OAuth grant reference; normal deployment must preserve existing state.

`Rodauth::CibaSupport::Schema.create` accepts the request table/column mapping, referenced account/application table/key and their key types. Pass `account_type:` / `application_type:` when upstream uses a type other than Integer, and configure matching table/column mappings in Rodauth. The helper uses foreign keys with cascading deletion; the request table is not an audit archive. `Schema.add_client_metadata` accepts its own table/column names. These helpers deliberately fail on an existing table/column rather than silently changing it.

The request `interval` column is a 64-bit integer so `slow_down` can continue increasing beyond the initial configuration limit. If you already installed a development snapshot, use an explicit forward migration to add the replay table and widen this column; do not rerun the initial migration or delete pending requests. No published version predates this change.

The consent helpers are `Schema.create_grants` and `Schema.add_grant_reference`; call them before `Schema.create`, as in the example. Match `ciba_grants_table`, request helper `grants_table:`, and the token reference column setting/options when customizing names. Account/application table and key options are available on `create_grants` too. The consent ID remains an integer.

This changes the development schema: existing installations need an explicit forward migration for the consent table, nullable request `grant_id`, and nullable OAuth `ciba_grant_id`. Previously approved requests need a valid saved consent reference before collection; do not silently treat a missing reference as authorization. Previously issued tokens cannot be linked to a consent by guessing: preserve their existing upstream lifecycle or migrate with application-owned provenance. The initial example is for a fresh schema, not an upgrade script.

## Nonce column upgrade

For development schemas created before request nonce support, add a forward migration using `Rodauth::CibaSupport::Schema.add_request_nonce(self)` (nullable TEXT `ciba_requests.nonce`). For custom names pass `table:` and `column:` and match `ciba_request_columns nonce: ...`. Run this before updating application workers. Existing rows remain intact with null nonce; do not infer nonce from hints or other identifiers. Fresh `Schema.create` already includes it, so do not run this helper after a fresh initial migration. It fails on duplicate columns.

Old workers ignore nonce on initiation. Do not enable client use of the extension until every worker has been upgraded. Drain old workers before enabling it to avoid mixing requests that preserve and ignore nonce. A downgrade must not drop or silently ignore the column while nonce-bearing requests are active.

## Transactions and concurrency

State changes and token/grant writes share a transaction/savepoint; signing and transactional hooks execute within that boundary. Only participating DB writes roll back, not external signer or hook effects. An outer transaction may catch an operation failure and still commit its other work; the failed CIBA DB operation stays rolled back. Events are registered with savepoint-aware after_commit and wait for the outermost commit. See the [failure and retry contract](failure-contract.md) for response loss, ambiguous errors and delivery boundaries.

PostgreSQL/MySQL read the request with a row lock; SQLite obtains a write reservation using IMMEDIATE transactions. Approval and issuance also lock the referenced consent grant. Consent revocation locks that grant before revoking linked OAuth rows, preventing issuance from racing past revocation. Conditional version updates also check ownership of the state transition. Reading under a lock avoids using an earlier repeatable-read snapshot for pending-poll updates. The library does not retry application hooks automatically: they can contain side effects. Recognized lock-timeout/serialization failures return HTTP503 with Retry-After. Other unexpected processing errors return a generic500; Ruby API callers receive exceptions and can retry the whole operation according to app policy.

JWT assertion consumption uses an atomic insert into a unique digest key with a savepoint. It occurs during client authentication, before the CIBA request/token transaction; a later request rejection may still consume the assertion. Send a fresh JWT on retry. When the caller encloses the entire request in a transaction, that outer transaction also encloses the ledger write. As with token issuance, do not report successful authentication externally until that transaction commits. Keep ledger entries until assertion expiry; ordinary CIBA request cleanup does not touch them.

An already-open SQLite deferred outer transaction cannot be converted to IMMEDIATE. Start such outer write transactions in IMMEDIATE mode. PostgreSQL/MySQL isolation levels other than the tested defaults, deadlock recovery and failover behavior are not certified. Use short transactions, database lock timeouts, request timeouts, and app-owned admission/rate limiting appropriate to your service.

Never send a constructed successful HTTP response before an enclosing application transaction commits. A response loss after commit does not make the token exchange replayable: the client must initiate a new CIBA request. The request deadline applies to approval and token collection; token expiry is independent once issued.

## Identity and transport

Configure a stable upstream issuer/base URL and trusted reverse-proxy handling. Production communication must use TLS; the app must correctly indicate HTTPS after trusted TLS termination. Backchannel/token requests use form POST bodies, not query parameters or JSON. Reject untrusted forwarded headers at the deployment boundary. This library does not add its own reverse-proxy trust policy.

The login_hint resolver must apply tenant/client eligibility and return a local account reference. The application must verify upstream customer authentication and approval permission before invoking the internal Ruby API. Request IDs are not bearer authority. Browser CSRF protection, customer sessions, notifications and CS delegation are outside the gem. Disabling an account or changing client eligibility is rechecked before approval/issuance, within database transaction visibility; there is no new guarantee of instantaneous revocation across concurrent admin transactions.

Limit unsolicited requests in your application. Optional [user_code](user-code.md) support connects to an application verifier; the gem supplies neither a production verifier nor a rate-limiting service. Store only the needed binding message/authentication context and periodically run bounded cleanup. The library omits raw hints and public request identifiers from its stored snapshots/events; application/proxy request logging and custom reporters must apply their own secret redaction.

## Scope and compatibility

0.1.0 targets poll with login_hint, public subjects and statically provisioned CIBA clients. It delegates confidential client authentication to enabled upstream mechanisms, preserves shared Discovery metadata, and issues signed ID Tokens using upstream's JWT implementation. Basic/post and private_key_jwt/client_secret_jwt have integration coverage; configured JWT algorithms, DPoP and optional mTLS have additional integration evidence in the [alignment status](alignment-closeout.md), including installed real-TLS examples. Production proxy trust remains application-owned. Unsupported features are not silently treated as implemented. Read the gemspec for narrow initial dependency bounds and `docs/release-validation.md` in the repository for actual tested environments.

No OpenID certification, full Conformance Suite pass, security audit, or blanket support for all Sequel adapters is claimed. Existing authorization-code behavior has a regression test, not the complete upstream test suite. Consumers should use the included protocol mapping as a starting point for application-specific interoperability tests.

## Poll response-time deployment contract

CIBA Core10.1 recommends responding to polling requests within30 seconds. The
gem does not impose a hard wall-clock deadline covering server queues, database
waits and application hooks. Fast unit tests cannot establish that production
requirement, and a timeout of the outbound HTTP helper is not a request deadline.

The integrating service must budget those waits together, configure server and
database timeouts, keep transaction hooks short, and measure complete token-
endpoint latency under expected contention. Observe rejected requests and
timeout rates as well as successful requests. The supplied tests establish
transaction behavior and concurrent issuance, not an operational latency SLA.

A response timeout can occur after committed issuance. Treat that outcome using
the [failure contract](failure-contract.md); blindly retrying a completed token
request may trigger replay revocation. Apply normal transaction rollback for
failures before commit, and do not report a timed-out client connection as proof
that the request did not commit. This deployment responsibility remains open
until an integrating service has measured its actual configuration.

## Remote JWKS cache lifetime

CIBA authentication and ID Token encryption share one application-scoped remote
JWKS policy. Successful response max-age takes precedence over Expires; Date,
Age and request time reduce remaining freshness. Explicit lifetimes are not
extended to a60-second minimum. Without explicit freshness metadata, fetch on
each use. No-store/no-cache, invalid or ambiguous cache directives, invalid dates,
and Vary responses do not enable reuse. Shared-cache restrictions are handled
conservatively: s-maxage may shorten lifetime; revalidation directives disable
stale fallback. Requests use the existing guarded transport and unconditional GET.

After normal expiry, retrieval is attempted first. If the last successful response
explicitly supplies stale-if-error, timeout or HTTP500/502/503/504 can reuse the
previous validated keys only until normal expiry plus min(allowance,60 seconds).
Check the deadline after retrieval fails. Failures never extend it. No allowance
means no fallback. TLS/security errors, malformed successful JWKS and other HTTP
statuses fail and invalidate stale eligibility. Empty successful JWKS replaces
the old set; removed keys cannot be recovered by fallback.

The cache is private to each Rodauth configuration/process, bounded to1024 entries,
and prunes expired entries on access. Earlier entries can be evicted at capacity.
`http_request_cache.uncache(URI(jwks_uri))` invalidates both CIBA key entries and
the delegated upstream cache; in-flight fetches cannot restore invalidated entries.
Ordinary HTTP lookups retain the configured upstream store. Custom upstream stores
are not used for CIBA stale-key payload persistence; these entries remain local.
There is no dedicated policy switch or background retry worker. A key source URI
change selects a different entry; already in-flight operations use their captured
client metadata, subject to existing issuance/management snapshot semantics.

Plan publisher key rotation and private-key retention around the declared
freshness and stale allowance. Removing a published key does not instantly
revoke copies within those windows. This policy intentionally differs from
node-oidc-provider's minimum lifetime and failure-induced freshness extension.
