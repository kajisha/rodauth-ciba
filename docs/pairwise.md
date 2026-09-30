# Optional pairwise CIBA subjects (integration in progress)

Pairwise is off by default. First run the explicit migration
`Rodauth::CibaSupport::Schema.add_pairwise_subject(db)` to add nullable
`oauth_grants.ciba_subject` (custom table/column supported; configure
`ciba_token_subject_column` for a renamed column). Enable `ciba_pairwise_enabled true` only together
with `ciba_pairwise_identifier(account_id, oauth_application:, sector_identifier:)`.
The callback must return a stable, nonempty ASCII subject of at most 255 bytes.
The application owns its secret/persistence lifecycle and sector/account mapping;
the gem does not supply a default hash or a reversible identifier store.

This integration supports private_key_jwt and self_signed_tls_client_auth clients
with registered jwks_uri, and no simultaneous inline jwks. Enable upstream
`:oauth_jwt_bearer_grant` and create its CIBA replay ledger with
`Schema.create_client_assertions(db)` if not already migrated. The standard client columns jwks_uri,
sector_identifier_uri, response_types and redirect_uri must be available where
used. Existing public clients retain their behavior. Self-signed TLS clients
require upstream `oauth_tls_client_auth` plus the explicit trusted certificate
callback described in the [mTLS contract](research/mtls-reference-contract.md).
The peer certificate must match x5c from the registered jwks_uri; PKI TLS
authentication alone is not a proof of that key ownership. Signed-request-only
proof with another client authentication method is rejected, matching the pinned
node-oidc-provider registration policy even when signed requests are enabled.
This is a shared policy restriction, not a remaining reference-alignment gap.

For CIBA-only clients with no browser response_types, absent sector_identifier_uri
means the sector is jwks_uri's host including a nondefault port. An explicit
sector_identifier_uri must be HTTPS. Browser response_types require that explicit
URI. Its HTTP 200 JSON array must include jwks_uri and, for browser clients, all
redirect_uris. Fetching uses the bounded address-checked outbound transport;
successful validation is cached per Rodauth application class using a digest of
the complete client row, with a 100-entry LRU bound and no time-based expiry.
Static and dynamically stored clients validate on a cache miss. Registration
and management replacement always fetch afresh, even for unchanged metadata.
Failures are not cached; an unsuccessful replacement does not erase the old
client's valid cache entry. Network I/O occurs outside the cache mutex, so
concurrent cold lookups may fetch twice. Processes do not share the cache.
This does not yet implement node's configurable sector-validation bypass policy.

Only the emitted subject is pairwise: saved requests, consent and OAuth grants
retain the canonical account ID. UserInfo must return the same pairwise subject
as ID Token. With pairwise enabled, new CIBA issuances snapshot their subject in that token
row. JWT UserInfo checks the signed subject against this snapshot and the bound
client before using the internal account for lookup. After a management sector
change, old tokens can therefore authenticate while UserInfo emits the new
sector subject, as measured with node opaque tokens. Refresh also uses the new
sector, and already-issued JWT bytes remain unchanged. Older rows with no
snapshot retain the prior current-subject check; a sector change can invalidate
those old JWTs. The migration does not invent historical subjects.

For id_token_hint, configure the existing `resolve_ciba_id_token_subject` callback
to recover the canonical account in the authenticated client's context. The gem
first verifies the ID Token's issuer, audience and signature; the hint then starts
a new request requiring approval. Do not treat a hashed subject as a new account.

Current tests cover opaque/JWT access tokens with verified ID Token, UserInfo,
app-resolved ID hint, internal identity, same/different sector derivation,
dynamic registration constraints and stubbed sector document membership. Opaque/JWT refresh also verifies subject and internal-account preservation,
rotation/replay, wrong-client refusal, and rollback on invalid identifier results.
Installed-gem tests now fetch sector documents over verified HTTPS and reject
untrusted certificates, invalid membership/JSON, oversize and HTTP errors without
persistence or forwarding the registration bearer. Sector fetching now follows 301/302/303/307/308 (up to 20 redirects), validating
each destination with the outbound policy and limiting the entire chain to
2.5 seconds. The measured same-origin HTTPS 302 case agrees with node. Existing-token UserInfo and refresh after a management sector change are now
verified for opaque/JWT tokens. Pending requests retain their canonical account and unapproved state across a
sector update; subsequent approved issuance uses the new sector subject. The
installed-gem TLS fixture now covers hybrid DCR, real remote-key authentication,
approval, verified ID Token, saved subject and matching UserInfo. Concurrent
sector management/issuance tests now verify one issuance subject across storage
and tokens, followed by current-sector UserInfo, on all three DBs. PostgreSQL and
MySQL force the update to commit while issuance is paused; SQLite tests writer
contention and either serial order. Concurrent refresh/key changes, arbitrary
application hooks and additional deployment combinations remain unverified.
This is not a completed pairwise parity or release-readiness claim.

[Reference contract](research/pairwise-reference-contract.md).
