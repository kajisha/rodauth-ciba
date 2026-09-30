# Optional explicit claim consent

This capability aligns the request/consent separation and ID Token/UserInfo filtering with node-oidc-provider. It is disabled by default. It does not enable other hints, signed requests, ping, resources or RAR.

## Enable after migration

In an application-owned numbered Sequel migration, after the base CIBA schema:

```ruby
Rodauth::CibaSupport::Schema.add_claims(self)
```

This adds nullable TEXT columns `ciba_requests.requested_claims`, `ciba_grants.claims` and `oauth_grants.ciba_claims`. Custom tables can be supplied with `requests_table:`, `grants_table:`, `tokens_table:`; a custom request column uses `request_column:` and matching `ciba_request_columns`. The consent/token columns have fixed names. Existing rows retain null values; requested data is never copied into old consent. The helper is explicit, not idempotent, and does not run at startup or as part of the base schema.

Then configure `ciba_claims_enabled true`. Upgrade every worker before activation. Old workers cannot enforce the token projection and must not serve UserInfo for tokens issued with this capability. Disabling new claim requests on upgraded workers does not remove enforcement for existing tokens. Do not drop these columns or roll back to old workers while affected tokens remain usable.

## Request and grant

Backchannel requests may include a JSON `claims` parameter containing `id_token` and/or `userinfo` objects. Each claim value is null or an object, matching the tested reference shape. Input is bounded to 8192 bytes, 64 claims per target and nesting depth 10. Invalid JSON or shape returns invalid_request. With the capability disabled this parameter remains unimplemented and is ignored, as before.

```ruby
grant = rodauth.create_ciba_grant(
  account_id: customer_id, oauth_application_id: client_id,
  scopes: "openid", claims: ["email"], rejected_claims: ["email_verified"]
)
rodauth.backchannel_result(request_id, grant, auth_time: authentication_time)
```

Claim names must be in `ciba_supported_claims`; the default includes ordinary standard profile/email/phone claims and address. Applications can explicitly configure additional names and supply their values with upstream `get_additional_param`. Configure upstream Discovery consistently for custom claims; the CIBA option does not rewrite OP-wide metadata. Identity/protocol claims such as sub, iss, aud, nonce and auth_time cannot be supplied through this consent list. They continue to come from the protocol and verified authentication context. Authentication claim output is selected separately as described in [authentication claims](authentication-claims.md).

Requested JSON and consent JSON are stored separately. Snapshot fields are frozen JSON strings. Passing a modified grant snapshot cannot add permission: completion reloads its ID. Convenience approval authorizes requested scopes only, not extra explicit claims; use saved consent to approve those.

## Disclosure rules

- ID Token explicit attributes must be requested for that target and allowed by consent. With this capability enabled, scope-derived profile/email attributes are returned through UserInfo rather than automatically added to the ID Token, matching the reference default.
- UserInfo combines permitted scopes and explicitly requested/approved UserInfo attributes. Rejected names override both sources.
- Rejected/unselected attributes are not requested from the account callback. Poll parameters cannot expand the stored request. Client-supplied `value` never becomes identity data.
- The compiled selection is persisted on the issued OAuth row, separately from the request. UserInfo binds to the exact presented opaque token or a signed JWT's `urn:rodauth:ciba:token_id` reference, with account/client checks and DB revocation checks. The internal reference is omitted from ID Tokens. It is not authorization by itself.

The application remains responsible for evaluating essential/value/values, acr, and localized claim requirements before approving. The stored request preserves those objects for that purpose; default attribute acquisition returns trusted account values rather than asserting that requested constraints were met. Aggregated/distributed claim processing is not implemented by this capability. These limits prevent claiming complete OIDC claims parity.

Legacy JWTs without an exact issuance reference never inherit explicit claims from another OAuth row for the same account/client. They retain the upstream scope-based path; this does not retroactively add per-row revocation to those JWTs. In particular, removing a legacy issuance row is not permission to reuse a newer row's explicit consent. This migration boundary has a regression test using an actual pre-capability JWT.

## Verification

`test/ciba_claims_test.rb` checks the five [reference cases](research/claims-reference-contract.md), both response targets, rejection overriding scope, request-value injection, altered grant snapshots, poll tampering, malformed input, JWT issuance isolation/revocation, and preservation of legacy rows. Existing tests cover capability-disabled scope behavior and ordinary authorization-code integration. The default upstream getter's interpretation of claim request objects is deliberately not used to source identity values.
