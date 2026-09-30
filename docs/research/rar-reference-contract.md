# RAR in the CIBA reference OP

Implementation update: the gem now has [optional RAR integration](../authorization-details.md), including registered/client type checks, saved consent, mandatory validation/issuance policy, output validation, JWT/token-response/opaque-introspection representation and ID Token exclusion. Tests now also race different narrowing requests and issuance/revocation on distinct DB connections. The earlier foundation and design notes below describe the implementation sequence; completion concurrency and additional policy/load-order review remain.

2026-09-30. Tested the installed, released node-oidc-provider 9.12.2 with a complete HTTP OP on Node24.21.0. RAR is enabled explicitly with a test-only `support_data` type, registered client permission for that type, and explicit application policy callbacks. The resource server uses opaque tokens for the introspection case. This is not a gem feature announcement.

## Observed behavior

| Scenario | Reference result |
|---|---|
| A client without the requested authorization-details type | `invalid_authorization_details` |
| A valid RAR request without a resource or configured default | `invalid_target` |
| Initial request with read/delete actions | Original JSON is stored in `BackchannelAuthenticationRequest.params`; source `rar` is absent |
| A saved Grant contains read-only `rar`, but completion omits `rar` | Token response has no authorization_details; neither the grant-source nor access-token policy callback ran in this case |
| Completion explicitly supplies read-only `rar` | Source carries that permission; access-token policy runs |
| Token request tries to add delete | The test application's policy returns only completed-source details, so the token response and opaque introspection contain only read |
| ID Token in the successful RAR flow | No authorization_details claim |
| Non-array JSON, unknown type, actions as a string | `invalid_authorization_details` |

The token-time narrowing result depends on the configured application callback. It is not evidence that the library automatically compares arbitrary JSON, intersects `Grant.rar`, or enforces all type-specific constraints. The fixture deliberately implements a simple policy that ignores token-time broadening and returns the previously completed source permission.

Evidence: [executable complete-OP harness](../../test/reference/full-op/lifecycle.mjs), [execution log](../validation/node-full-op-lts.txt). Earlier lifecycle, claims and resource cases still pass with RAR configured.

## Where the boundaries live

- `lib/shared/check_rar.js` parses and normalizes the request, checks registered types and client permission, then invokes the type's validator.
- `lib/shared/check_resource.js` requires a supplied/defaulted resource for these RAR requests. This is observed provider policy; do not label it a universal CIBA requirement.
- `lib/actions/authorization/ciba.js` retains request parameters and creates the asynchronous source. It does not run the authorization-code flow's grant-source RAR policy.
- `lib/provider.js#backchannelResult` accepts a separate `rar` completion option and stores it on the request. `Grant.addRar` alone does not populate it.
- `lib/helpers/grant_authorization.js#applyAuthorizationDetails` calls the configured access-token policy when token parameters or the completed source contain details.
- Introspection has its own policy callback. The fixture permits introspection only to the token's issuing client.

[RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html) defines authorization_details as an array of typed objects, describes token-request comparison and response/introspection representations, and leaves type semantics to the deployment. It does not provide a universal algorithm for narrowing arbitrary application data. Gem design must distinguish these protocol fields from the reference's CIBA completion API and application policy.

## Implementation progress: storage and structural validation only

The gem now contains `Schema.add_authorization_details`, an explicit additive helper for nullable request `requested_authorization_details`, saved-grant `authorization_details`, issued-token `ciba_authorization_details` and client `authorization_details_types` fields. The table names and request column can be overridden. It does not backfill consent, run automatically or enable RAR endpoints.

`Rodauth::CibaSupport::AuthorizationDetails.parse` is an internal structural validator (explicit require `rodauth/ciba/authorization_details`). It accepts bounded UTF-8 JSON arrays of typed objects and validates the common array/identifier fields. Limits are 8,192 bytes, 32 entries and JSON nesting depth 10. Returned arrays, hashes and strings are frozen recursively. Unknown type-specific fields are preserved; no authorization or narrowing semantics are inferred.

Duplicate keys are rejected at all depths using JSON's native `allow_duplicate_key: false`. This is a deliberate stricter input boundary than the reference's ordinary JSON.parse. A custom object-class experiment failed to detect duplicates consistently across JSON versions and was removed. JSON >=2.18,<3 is now an explicit runtime dependency; the lockfile selects 2.18.0. Invalid UTF-8 is checked on the byte sequence, including binary-encoded Ruby strings.

Tests in `test/ciba_authorization_details_test.rb` cover duplicate keys, malformed common fields, byte/count/depth limits, encoding, deep immutability and preservation of existing DB rows. This foundation alone does **not** implement request acceptance or authorization. The subsequent optional feature adds those integration paths with mandatory application policies; do not activate it based only on a successful migration.

## Integration requirements and original proposal

Use an opt-in capability and explicit additive migration. Preserve three distinct JSON values: original requested details on the CIBA request, approved details on the saved consent, and effective details on the issued OAuth token. Existing rows represent no additional permission. Do not infer approved details from the original request or mutate already-issued permissions when a saved grant changes.

Keep the existing saved-grant result API. At completion, bind the approved details to that request with application validation; at issuance, compile effective details from the stored request, saved consent, selected resource and token-time narrowing request. Any configurable policy must operate within that verified account/client/consent context. Fail closed if RAR is enabled without required validation/compilation policy. Do not implement a generic deep-merge or claim JSON equality means authorization.

Required validation includes bounded JSON, array/object/type shape, common field shapes, registered types and per-client allowed types. Type-specific account/operation/amount/target constraints remain application policy. Validate compiled output as well as input. Policy failures during completion or issuance retain the gem's accepted atomic rollback contract.

RAR output belongs in the access token/token response and opaque introspection, not the ID Token. Preserve the resource audience boundary and explicit-claims filtering. Add Discovery and static-client metadata only with implemented enforcement. Reject poll attempts to expand permission; a policy's narrower result must be testable with a concrete type.

Before claiming support: implement the schema/API and client metadata; test missing policy, disabled/mixed-version states, unrequested/unapproved details, request/result snapshot tampering, type/resource/client isolation, hook-time changes, issuance/revocation races, JWT representation and opaque introspection. Add installed-gem smoke coverage. Generic RAR support and the customer's particular support/deletion approval semantics are separate deliverables.
