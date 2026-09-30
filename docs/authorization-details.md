# Optional authorization details (RAR)

This opt-in CIBA extension accepts RFC9396-style authorization details with registered, application-defined type semantics. It depends on [resource indicators](resources.md). The gem validates protocol shape and identity/client/consent binding; the application must decide which details represent an allowed operation and how to narrow them. It does not compare arbitrary JSON as a substitute for authorization.

## Migration and activation

After the base and resource schemas, explicitly run:

```ruby
Rodauth::CibaSupport::Schema.add_authorization_details(DB)
```

This adds nullable JSON TEXT fields to requests (`requested_authorization_details`), saved grants (`authorization_details`), issued tokens (`ciba_authorization_details`) and clients (`authorization_details_types`). Table names and the request column are configurable keyword arguments. For a custom request column, set the corresponding `ciba_request_columns` mapping. Existing rows have no additional RAR permission; migration does not infer consent or activate the feature.

Configure `ciba_authorization_details_enabled true`, `ciba_resources_enabled true`, `ciba_authorization_details_types` as the supported type-name array, and both policy methods below in the same configuration block. Missing policy methods or missing resource/type configuration prevent startup. Store each statically registered client's allowed type-name array as JSON in `authorization_details_types`. An omitted client value permits no types. Discovery advertises `authorization_details_types_supported` only when enabled; this support currently applies to CIBA, not an added authorization-code RAR implementation.

Upgrade all workers before activation. Requests or their saved consent carrying the new field cannot be redeemed after disabling RAR; they return invalid_grant. This includes an old request bound to a new RAR consent after migration. Already-issued tokens retain their stored authorization details. Do not downgrade readers while such tokens remain active. Existing request/consent pairs without the fields remain compatible; enabling the feature must not backfill requested or approved data.

## Application policies

`ciba_validate_authorization_details(details, oauth_application:)` must return exactly true to accept details. It runs for requests, saved consent and compiled issuance output. Inputs have passed bounded JSON/common-field validation and registered/client-type checks. Define all permitted fields and their values for each supported type. Empty arrays represent no additional permission. This method should not perform external side effects.

`ciba_authorization_details_for_token(requested:, approved:, narrowing:, resource:, oauth_application:)` returns an array of effective details. Inputs come from the original request, the reloaded saved grant, optional token-request details (nil if omitted), selected resource and current client. Arrays, hashes and strings are recursively frozen. The method runs inside the issuance transaction after the before-issue hook. `ciba_current_request` supplies the verified account/client request context. The gem validates the returned shape/type/client eligibility again and persists that output on the issued token.

**The application must enforce type-specific narrowing and resource association in this method.** Generic code cannot determine whether a changed amount, path, customer, operation or target grants more access. An output of valid JSON shape is not proof of proper authorization. Reject invalid narrowing with `Rodauth::CibaSupport::ProtocolError.new("invalid_authorization_details")`; an empty result grants no RAR permission and omits the response field. Exceptions roll back consumption and token writes. The [installed-gem example](../examples/extensions_smoke.rb) demonstrates only a fixed read/delete test type; it is not a production business policy.

Create saved consent with a separate approved value:

```ruby
grant = rodauth.create_ciba_grant(
  account_id: customer_id, oauth_application_id: client_id,
  scopes: "openid", resources: {resource_uri => "read"},
  authorization_details: [{type: "support_data", actions: ["read"]}]
)
rodauth.backchannel_result(request_id, grant)
```

The result API reloads the grant by ID, so editing a returned hash cannot broaden approval. This gem's adapter derives issuance policy input from saved consent; node's CIBA result API takes a separate `rar` completion option. Both require application policy, and their Ruby/JavaScript APIs are not identical. Completion binds the saved grant to the account/client; semantic request/approval/resource comparison occurs in the issuance policy before any token commits.

## Protocol behavior and verification

Requests use a JSON array in the form parameter `authorization_details`. A nonempty RAR request must include a registered resource. At token issuance a resource must be selected explicitly or through the configured resource omission policy. The compiled details appear in the token response, resource JWT and opaque introspection, never the ID Token or UserInfo. Resource JWT introspection remains unsupported; use opaque tokens for online revocation checks. Introspection caller authorization remains an application/upstream responsibility.

Limits: 8,192 JSON bytes, 32 objects, nesting depth 10. Invalid UTF-8 and duplicate keys are rejected, as are invalid common fields, unknown/disallowed types and rejected application policy. Size/depth/duplicate-key restrictions are implementation limits, not claims that CIBA Core requires them.

`test/ciba_rar_test.rb` covers opaque/JWT output, client/type/resource rejection, snapshot tampering, invalid output, poll broadening, hook-time client changes, rollback, disabled pending requests and empty permission. The installed-gem smoke exercises RAR together with claims/resources, signature verification, ID Token exclusion and replay. The [complete reference OP](research/rar-reference-contract.md) establishes comparable application-policy cases.

Additional tests use distinct DB connections to race two polls with different RAR narrowing values and to race issuance with revocation. Only one poll's complete permission is stored; values are never combined. After replay/revocation finishes, opaque introspection exposes neither active permission nor authorization details. Migration tests also reject legacy requests bound to new consent when the corresponding feature is disabled. The node HTTP harness independently verifies RAR introspection becomes inactive after replay.

Remaining review includes RAR-specific concurrent completion, all feature load orders, separate introspection redaction policy, more complex type examples, and bounds on trusted policy execution time. This is not full RFC9396 conformance or certification.
