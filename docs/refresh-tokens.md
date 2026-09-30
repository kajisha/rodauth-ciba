# CIBA refresh tokens — implementation in progress

Disabled by default. This branch implements the basic flow, but it is not yet a
release-ready refresh implementation. The implemented revocation boundaries and
legacy-format differences below still need the overall alignment review. Do not
infer full reference parity from the existence of the flag.

For development tests, explicitly create storage with
`Rodauth::CibaSupport::Schema.create_refresh_tokens(db)` and configure
`ciba_refresh_tokens_enabled true`. Register both the CIBA grant and
`refresh_token` for the client, and allow `offline_access` in both OP and client
scopes. Initial issuance requires `offline_access` on the CIBA source and the
refresh grant registration, matching the reference default policy.

`ciba_refresh_tokens_table` defaults to `:ciba_refresh_tokens` and
`ciba_refresh_token_lifetime` to 14 days. Only the digest of an opaque, namespaced
refresh token is stored. The source retains original scope/resources/claims/RAR,
account/client, consent ID and authentication context separately from each access
token. Short-lived CIBA request cleanup does not remove it.

Updates validate the authenticated client, current grant registration, account,
saved consent and enabled optional capabilities. Scope narrowing applies to the
current access token, not the saved refresh source. Resource selection is computed
against the current consent. Each update creates a new access-token record.

When upstream JWT client authentication is enabled, `private_key_jwt` and
`client_secret_jwt` accept the OP issuer as the assertion audience for CIBA
refresh, as they do for initial CIBA token collection. The current token URL
remains accepted. This extension applies only to the CIBA grant and reserved
`ciba_rt_` refresh namespace; ordinary OAuth token requests retain their existing
audience policy. Wrong audiences and assertion replay remain authentication
failures. [Measured comparison](research/refresh-reference-contract.md#jwt-client-assertion-audience).

For confidential clients the initial implementation follows node's default
rotation policy: rotate after 70% of token lifetime, until one year after initial
issuance. A fresh token can be reused. Rotation preserves consumed digests; reuse
by the correct client revokes the saved consent and its linked access tokens, and
therefore also invalidates successor refresh tokens. A different client's request
does not revoke the rightful client's consent. Simultaneous rotation can produce
one success followed by a replay response that invalidates the returned successor.

Token consumption, rotation and issuance share the DB transaction. Signing failure
rolls them all back, preserving the project's accepted atomic-issuance contract.
This differs from node's nontransactional memory adapter. Existing non-CIBA OAuth
refresh tokens continue through upstream's implementation and rotation policy.

The flag can be disabled without querying the optional table for presented CIBA
refresh tokens; their namespace causes `invalid_grant`. This namespace is reserved
for the extension. Changing ordinary OAuth token generators to use `ciba_rt_`
would conflict with that dispatch boundary.

See the [reference contract](research/refresh-reference-contract.md) for measured
reference behavior and the remaining tests. Current authentication context output
follows the gem's CIBA ID Token behavior; it is not identical to node's optional
claim masking.

## Refresh-token revocation

Enable upstream `:oauth_token_revocation` to expose its advertised endpoint.
The CIBA extension also adds its URL to OIDC Discovery when that feature is enabled.
Presenting a `ciba_rt_` token authenticates the OAuth client (never the browser
account), requires the CIBA form/TLS transport and revokes the entire saved
consent and linked access tokens. This remains possible with refresh issuance
disabled when the refresh table exists. The standard upstream before/after revoke
hooks run in the transaction; an exception rolls the revocation back.

Like the measured reference, missing, wrong or unknown `token_type_hint` does not
prevent finding a CIBA refresh token. Success is HTTP 200 with an empty body.
Unknown, expired and already-revoked tokens are successful no-ops. An authenticated
different client presenting a live token receives `invalid_request`; it cannot
revoke the owner's consent. After revocation, its retry is also a successful no-op.

The endpoint also recognizes saved opaque CIBA access tokens independently of the
hint. Their revocation invalidates related tokens and deletes old request/refresh
sources while retaining saved consent, matching the [reference's distinct AT
policy](research/access-token-revocation-reference.md). Standard transactional
revoke hooks still apply. New opaque CIBA tokens use the reserved `ciba_at_`
namespace, so unknown or cleaned-up tokens return empty 200 after client
authentication. Legacy unprefixed tokens need a saved row to be recognized; after
row cleanup they retain upstream behavior. Calling the consent-revocation API
instead would not preserve consent.

New CIBA JWT access tokens always carry the signed private issuance ID, even with
explicit claims disabled. It is removed from ID Tokens. At revocation the marker
selects a rejecting path, then OP signature/issuer/type are verified. Proven CIBA
JWTs return `unsupported_token_type`, including expired ones; forged markers
return `invalid_request`. This provenance-only verifier never authorizes token use
and does not alter the normal access-token time checks. Node instead rejects all
structured JWTs by header shape; unrelated and unmarked legacy JWTs keep upstream
behavior here. No JWT revocation path mutates saved consent.

The issuance marker also binds new JWT UserInfo access to its saved token row.
Deleting that row invalidates UserInfo access. Unmarked historical JWTs retain the
old scope-based path without borrowing explicit claims from another issuance.

## Claims, authorization details and cleanup

Opaque and JWT access-token tests cover claims/RAR with rotation. The original
request fields are preserved in the successor source; the application's RAR
policy is re-evaluated against saved consent for each update. A token-time claims
parameter does not grant additional attributes. Current rejected claims suppress
attribute reads and output, and disabled capabilities reject updates instead of
silently dropping restrictions. Invalid RAR narrowing rolls rotation back.

The reference test application's policy emits `source.rar`, explicitly supplied
at completion; it ignores token-time expansion. The gem's test policy intersects
the saved request and current consent, with optional narrowing. These are different
application-owned policies, not proof of identical arbitrary RAR semantics.

Run `cleanup_ciba_refresh_tokens(limit: 100)` from an application-owned maintenance
job after creating the refresh table. It deletes at most the limit of sources whose
expiry is at or before the current time, and returns the deleted count. Unexpired
consumed sources must remain for replay detection. Cleanup does not delete saved
consent or access tokens. It participates in an outer DB transaction and does not
schedule itself.

## Update hooks and events

`before_ciba_refresh` and `after_ciba_refresh` run inside the token transaction.
They can use `ciba_current_refresh`, an immutable snapshot of the presented refresh
source with its digest removed. This is not a CIBA request snapshot: its `id` is
the refresh-source row ID. The after snapshot reflects consumption of that source
when rotation occurred. Neither snapshot includes a raw token. It is cleared on
exit, and same-source reentrant updates are rejected.

The source, account, client registration, saved consent, expiry and enabled
capabilities are revalidated after the before hook. Hook exceptions roll back
source consumption, successor creation and access-token issuance. As with other
transactional hooks, external side effects cannot be rolled back by the gem.

A successful update schedules an immutable `token_refreshed` observation event
after the outermost commit. It has `version`, `event_id`, `type`, `occurred_at`,
`refresh_token_id`, `grant_id`, `account_id`, `oauth_application_id` and `rotated`.
It has no `request_id` because refresh can outlive request cleanup. Tokens, token
digests, claims and authorization details are not included. Observer exceptions
go through `report_ciba_observer_error` and do not change the committed result.
This event describes a committed issuance, not proof of delivery to the client.

## Installed artifact verification

`bin/verify-package` builds and installs the gem in a temporary directory, clears
checkout load-path variables and verifies that the feature is loaded from that
installation. The extension smoke runs both opaque and JWT modes with signed
authentication requests, claims/resources/RAR and refresh enabled. It verifies
original identity context, rotation, grant replay revocation invalidating a
successor, Discovery-based refresh revocation and expiry cleanup. Existing basic
and real HTTPS ping smoke also run. Dependencies are reused from local installed
gems; fresh network dependency resolution and publication are not tested.
