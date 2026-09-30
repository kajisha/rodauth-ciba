# Explicit claims: reference behavior and implementation contract

2026-09-30. The complete node-oidc-provider 9.12.2 harness now enables `features.claimsParameter` and declares email/email_verified as supported claims. This is opt-in: the reference source defaults claimsParameter to disabled. All scenarios use `scope=openid`, so they isolate explicit claim consent from implicit scope-derived disclosure.

## Observed over HTTP

| Request | Saved Grant | ID Token email | UserInfo email |
|---|---|---|---|
| ID Token email | No allowed claims | Absent | Absent |
| ID Token email | email allowed | Present | Absent |
| ID Token email | email allowed and rejected | Absent | Absent |
| UserInfo email | email allowed | Absent | Present |
| No email request | email allowed | Absent | Absent |

Each scenario also supplies an expanded claims parameter at the Token Endpoint. It cannot broaden the saved request. The account callback returns both email and email_verified unconditionally; the final response must still exclude unrequested/unapproved data. Tests verify ID Token signatures, the target-specific callback mask and HTTP UserInfo responses. Invalid JSON, array containers and boolean claim specifications are rejected with invalid_request. [Executable harness](../../test/reference/full-op/lifecycle.mjs), [Node24.21.0 log](../validation/node-full-op-lts.txt).

Initially the allowed-email case returned no email because the fixture had not declared it as a supported OP claim. Correcting the fixture established a fourth input to the filter: request, consent, rejection and OP-supported claims. This was not a provider defect.

## What the gem must preserve

[OIDC Core §5.5](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter) separates requested claims by response target and supports individual claim request objects. These objects are not themselves consent. The tests above cover null-valued individual requests; they do not prove enforcement of essential, value/values, localized claims, acr requirements or aggregated/distributed claims.

The next implementation should be an explicit capability with a migration/activation gate, retaining current scope-only behavior when disabled. Store requested claims on the request separately from allowed and rejected claim names on consent. Persist the effective target-specific claim selection on issued OAuth rows so later UserInfo calls use the approved projection. Do not infer approval from request JSON or let poll parameters replace it.

Use the existing node-shaped result boundary and reload saved consent at completion and issuance. Required identity/protocol claims must remain protected from arbitrary app-supplied values. Snapshot APIs need defensive handling of nested JSON. Existing rows must not acquire new explicit permissions after migration. Enable only after all workers can enforce the new fields.

## Upstream integration constraint

rodauth-oauth 1.7.0 `generate_id_token` reads the OAuth row's claims column and passes target-specific entries to `fill_with_account_claims`. Its UserInfo route independently reloads that row, adds the UserInfo entries and calls the same claim provider. Therefore filtering only during ID Token generation would leave a second disclosure path unprotected.

The upstream helper also expands scope-derived claims. An explicit rejection must suppress the rejected claim in both acquisition and output, even when a scope otherwise permits it. Do not implement this as merely adding a claims column or copying all requested claims into the upstream row. Tests must additionally cover rejected claims combined with scopes, custom account providers and CIBA isolation from other grant flows before the capability is considered complete.

Follow-up: the gem now implements an optional [explicit-claims capability](../claims.md) and regression tests for these five cases, rejection overriding scopes and exact-token UserInfo isolation. Essential/value/values policy and aggregated/distributed claims remain outside its automatic enforcement; this is not full claims parity.
