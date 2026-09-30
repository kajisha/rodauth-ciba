# Request and consent API evolution review

2026-09-30. Reviewed the installed node-oidc-provider 9.12.2 source, rodauth-oauth 1.7.0 source and the current gem. This is an implementation review and staged design proposal, not an announcement that the additional capabilities are available.

## Finding

Keep the public boundary `backchannel_result(request_id, saved_grant_or_id, ...)`. Reloading consent by ID, checking account/client ownership, and serializing issuance with revocation are appropriate foundations for richer consent. Do not replace that boundary with caller-supplied token claims or authorization hashes. Current snapshots are scope-only; their existence is not evidence of node's complete Grant model.

The next extension needs separate requested and approved representations. Simply copying `claims` or `resource` into upstream OAuth grant columns could bypass consent. In upstream `generate_id_token`, keys from stored ID Token claims are added to the requested scope/claim list before the account provider runs; this is not a substitute for the gem's approval filtering. Resource handling also needs per-resource authorization rather than one global scope intersection.

## Concrete migration and API shape

Update: nonce propagation is now implemented with a nullable request column and explicit forward-migration helper. Its scope/identity separation remains as described below; other additions in this table remain proposals. See [API](../api.md) and [operations](../operations.md).

Further update: [optional explicit claims](../claims.md) now implements request/consent separation and both output targets. The API uses `claims:` and `rejected_claims:` arrays on `create_ciba_grant`; predicates remain available in request JSON for application policy. [Resources](../resources.md) also implement their separate saved permission and token audience. RAR and additional result errors remain proposals; the [RAR reference contract](rar-reference-contract.md) now supplies actual CIBA HTTP evidence and completion-policy boundaries.

These are proposed additions for individually selected increments. They must not be accepted or advertised until implemented and tested.

| Capability | Request storage | Consent storage / proposed API | Issuance and rejection boundary |
|---|---|---|---|
| Explicit OIDC claims | Validated `requested_claims` JSON, split by ID Token/UserInfo target | Optional `oidc_claims:` and explicit rejected claims on `create_ciba_grant` | Intersect requested claims with consent and current client policy before invoking upstream claim acquisition. Preserve essential/value constraints for validation; do not flatten them into unrestricted claim names. Keep protocol-required claims separate from optional disclosure. |
| Resources | Validated requested resource identifiers, preserving multiple values | `resources: {resource_uri => scopes}` on saved consent | Selected resource must be both requested and approved. Limit access-token scope/audience per resource; ID Token audience remains the client. Invalid or unauthorized target must not fall back to unrestricted issuance. |
| Nonce | Validated request nonce | No consent field: it is request correlation, not a permission | Persist through completion and include the original value in the ID Token. A poll parameter must not replace it. |
| RAR | Validated requested authorization details | Separately approved authorization details, with type-specific validation | No generic JSON merge or equality-as-authorization. Specify a type's narrowing rules and downstream enforcement before implementing it. No reviewed upstream RAR bridge currently establishes this behavior. |
| Additional completion errors | Persist explicit terminal error code independently of successful grant ID | Continue accepting a typed result error; extend only a documented allowlist | Define which errors are terminal, their polling responses and retry equivalence. Current `denied` state plus grant absence encodes only access_denied; adding Ruby subclasses alone is insufficient. Never expose exception messages as protocol descriptions. |

The resource increment now accepts `create_ciba_grant(account_id: ..., oauth_application_id: ..., scopes: "openid", resources: {"https://api.example.test" => "read"})` after its explicit migration and activation. Existing scope-only calls and `backchannel_result(id, grant)` retain their meaning; granting `openid` does not implicitly authorize a newly added resource.

Use explicit forward migrations for each selected increment, initially with nullable new columns. Existing rows mean no additional explicit authorization; do not backfill consent from request parameters. Claims implicitly permitted by existing scope semantics need a documented compatibility mapping before enabling explicit claims rejection. Check existing client/application eligibility during issuance as today.

A mixed-version deployment needs a capability gate: migrate first, deploy readers/writers, then enable the feature only once all workers understand it. Old workers must not process richer grants as scope-only grants. If rolling compatibility cannot enforce this, drain old workers before activation. Downgrade cannot silently discard richer approval restrictions; require deactivation and handling of affected pending requests. Keep the existing consent-to-issued-token link and revocation behavior through every migration.

## Consent lifetime difference

node's default `GrantTTL` is 14 days. The follow-up implementation now applies the same default to new gem consent via `ciba_grant_lifetime`. Omitted expiry uses that configured lifetime; explicit nil or a future timestamp remains an application override. This changes the earlier default of nil for newly created rows, including convenience approval.

Existing rows retain their original expiry without migration. Access-token lifetime and request lifetime remain separate. The tests cover default/explicit/custom expiry, preservation of legacy nil rows, expiry at collection and during approval/issuance hooks; the complete node OP test now reloads saved Grant data and checks its actual exp-minus-iat value.

## Acceptance gates

The [resource reference contract](resource-reference-contract.md) supplies real HTTP tests and identifies the need for separate OIDC/access-token scope handling; merely enabling upstream resource_indicators is insufficient for CIBA consent binding.

The [explicit-claims reference contract](claims-reference-contract.md) now provides passing complete-OP cases for requested/allowed/rejected values and ID Token/UserInfo target separation. It also identifies the upstream UserInfo filtering path that the gem implementation must cover.

- Retain tests proving that mutating a supplied grant snapshot cannot broaden consent, that account/client mismatches fail, and that revocation serializes with issuance.
- Each new field needs positive tests and negative tests for unrequested/unapproved values, request/poll tampering and partial consent. Exercise the upstream claim provider with assertions that rejected data is never requested or emitted.
- JSON-bearing snapshots require deep immutability or an equivalent defensive-copy contract; the current snapshot implementation only needs to freeze flat values.
- Add forward migration tests on all three DBs and an explicit mixed-version activation test. Keep current scope-only fixtures to establish compatibility.
- Add the selected capability to the real node HTTP harness and compare behavior, including deliberately unsupported cases. Do not infer RAR or claim enforcement from successful scope-only issuance.

The current API can remain for the initial subset. This review closes the question of whether an immediate wholesale API rewrite is necessary; it does not close the feature gaps. Next implementation work should select one concrete capability and its protocol requirements, rather than introducing all of these schema fields in advance.

Follow-up: the [completion-error analysis](completion-error-boundaries.md) found that node's generic error acceptance must not be equated with terminal poll errors. It preserves the current allowlist and documents an explicit cancellation/failure API as a separate future task.

## Source map

- node v9.12.2: `lib/models/grant.js` (openid/resources/rejected/rar), `lib/models/backchannel_authentication_request.js`, `lib/helpers/grant_common.js`, `lib/provider.js` (`backchannelResult`), `lib/helpers/defaults.js` (`GrantTTL`). Reproducible source is installed by the [locked reference package](../../test/reference/full-op/package-lock.json).
- rodauth-oauth 1.7.0: `lib/rodauth/features/oidc.rb` (`generate_id_token`, `id_token_claims`), `oauth_resource_indicators.rb`.
- Gem: [feature](../../lib/rodauth/features/ciba.rb), [schema](../../lib/rodauth/ciba/schema.rb), [consent tests](../../test/ciba_grant_test.rb).
