# Optional resource indicators

Resource indicators separate an API's permission from the OIDC/UserInfo permission. This capability is opt-in; the initial poll/login_hint profile does not require it. The client repeats `resource` in the Backchannel request and selects at most one at the Token Endpoint.

## Migration and activation

Run the explicit additive migration once, after the base schema:

```ruby
Rodauth::CibaSupport::Schema.add_resources(DB)
```

It adds nullable TEXT fields `ciba_requests.requested_resources`, `ciba_grants.resources`, and `oauth_grants.ciba_resource` / `ciba_resource_audience`. Custom table names and the request column name are keyword arguments; configure the same request column in `ciba_request_columns`. Existing rows retain their values and have no resource permission.

Upgrade every worker before activation. Do not downgrade the enforcing code while resource tokens remain valid. Disabling the flag prevents completion of requests carrying the new resource field, but upgraded code continues to reject resource tokens at UserInfo.

```ruby
ciba_resources_enabled true
ciba_resource_servers(
  "https://api.example.test/data" => {
    scopes: %w[read delete], audience: "https://api.example.test/data"
  }
)
```

Declare these scopes in the OP and client configuration too. The `ciba_resource_server(resource, oauth_application:)` Ruby method can replace the registry lookup for application-specific eligibility. Return a hash with a String `:audience` and Array of String `:scopes`, or nil for an unavailable target. Identifiers must be absolute, fragment-free URIs; neither the gem nor the default lookup fetches these addresses. A resource identifier may map to a different audience.

## Consent and issuance

```ruby
grant = rodauth.create_ciba_grant(
  account_id: customer_id, oauth_application_id: client_id,
  scopes: "openid", # OIDC permission, separate from the API permission
  resources: {"https://api.example.test/data" => "read"}
)
rodauth.backchannel_result(request_id, grant, auth_time: verified_auth_time)
```

Requested targets are stored independently from saved consent. A modified result hash cannot replace the stored grant. At issuance, the effective API scopes are the intersection of the original requested scopes, saved permission for the selected resource and its current configured scopes; client eligibility is rechecked. Policy lookup occurs after `before_ciba_issue`, inside the issuance transaction. An empty intersection grants no scope; it never falls back to OIDC permission. Resource consent is not inferred by the convenience approval method: use an explicit saved grant for API permissions.

When polling omits `resource`, the default follows node-oidc-provider's UserInfo policy: use the saved OIDC scopes. It does not automatically select the only requested API. Override `ciba_use_granted_resource(request_snapshot)` to return true when the application wants to select from the original request's resources. A sole candidate is selected directly. Multiple candidates are passed as a frozen array of frozen strings to `ciba_default_resource(resources, oauth_application:)`; return one original identifier, or nil to retain the OIDC path. The default leaves the array unresolved and returns `invalid_target`. Invalid boolean results raise a configuration error. Neither callback can authorize an unrequested target or replace saved resource consent.

JWT access tokens carry the selected audience and narrowed scopes. Opaque tokens persist these fields and expose audience through the upstream introspection feature, when enabled. Resource servers must verify the audience and required scopes. ID Tokens continue to carry the client audience and approved OIDC context, including an `at_hash` of the actual access token. Resource access tokens are rejected at UserInfo, even if their scope includes `openid`.

Malformed, unavailable or unrequested selections return `invalid_target`; multiple token-time targets are rejected. Duplicate scalar parameters remain invalid. Maximums are 16 initial resource parameters and 1,024 bytes per identifier. Issuance errors roll back consumption and token writes under the accepted same-DB policy; this intentionally differs from the node reference's nontransactional memory adapter.

## Evidence and limits

[HTTP tests](../test/ciba_resources_test.rb) verify separate scopes/audiences, mapped audiences, stored-consent integrity, policy changes in hooks, omission, malformed targets, signing rollback, opaque introspection/revocation, JWT/opaque UserInfo denial and legacy migration. [Reference contract](research/resource-reference-contract.md) records observations from the complete node OP.

Additional integration tests cover omission callbacks, explicit ID Token claims together with API scope/audience (including at_hash), simultaneous polling for different audiences and later activation of upstream `oauth_resource_indicators`. CIBA's saved audience takes precedence over that feature's request-based JWT audience. Resource JWTs are rejected at UserInfo. Introspection of a verified CIBA resource JWT returns HTTP 400 `unsupported_token_type`, matching the node reference's rejection of structured tokens. This is unchanged by replay, grant revocation or deletion of the token row. It avoids presenting a stateless JWT decode as an authoritative active/revoked result. Signature and issuer validation remain enabled; tests reject a modified signature and a different issuer.

Use opaque access tokens plus introspection when resource servers need the OP's current revocation decision. JWT offline verification does not detect a later grant revocation. The reference rejects all structurally recognizable JWTs before verification; this gem restricts the new error to verified CIBA resource tokens, preserving upstream behavior for other OAuth tokens and invalid signatures. This is an explicit integration difference, not a CIBA Core requirement.

This is not complete resource-indicator parity: all upstream feature load orders and all claims/resource combinations have not been tested. For empty API permission, node omits the JWT scope claim while this gem's upstream encoder emits an empty string; both token responses explicitly carry an empty scope.
