# Required CIBA authentication parameters

This inventory reconciles CIBA-072 with the enabled implementation. It concerns
mandatory presence and selection, not a blanket pass for all optional parameter
values (CIBA-067), application policy, or every combination of extensions.

| Condition | Required input | Direct test evidence |
|---|---|---|
| Every authentication request | `scope`, containing `openid` | `ciba_requirements_test.rb:test_scope_syntax_errors_are_invalid_scope`; `ciba_protocol_test.rb:test_request_validation_and_unknown_parameters` |
| Every authentication request | Exactly one enabled hint | `ciba_hint_token_test.rb:test_hint_token_input_exclusivity_size_and_unknown_user`; `ciba_protocol_test.rb:test_request_validation_and_unknown_parameters` |
| Client registered for signed requests | `request` JWT | `ciba_signed_request_test.rb:test_signed_request_registration_discovery_and_client_authentication` |
| Signed request | `iss`, `aud`, `exp`, `iat`, `nbf`, `jti`, and inner scope/hint | `ciba_signed_request_test.rb:test_signed_request_missing_required_fields_cannot_use_outer_values`; `test_signed_request_rejects_bad_claims_and_keys_before_persistence` |
| Ping delivery | `client_notification_token` | `ciba_ping_test.rb:test_ping_rejects_bad_tokens_and_uses_current_registered_destination` |
| User-code verifier requires a code | `user_code` | `ciba_user_code_test.rb:test_user_code_requires_explicit_callback_and_checks_before_device_dispatch` |
| Signed request with ping and required user code | Required authentication fields must be inside the signature | `ciba_ping_test.rb:test_signed_ping_required_fields_cannot_be_supplied_outside_signature` |

Client authentication is independent and precedes request-object processing.
The signed-request registration test rejects a valid JWT without client
authentication; the existing authentication audit covers the registered
credential mechanisms. A JWT does not supply client authentication merely by
containing `iss` or `client_id`.

`binding_message`, `requested_expiry`, `acr_values`, nonce, claims, resources,
authorization_details, max_age and request_context are optional protocol inputs.
Their application policies or content validation must not be confused with an
unconditional presence requirement. A configured application may impose further
policy through the documented callbacks. Push remains unsupported in both the
comparison target and gem.

The route validates transport and client authentication, processes the signed
request, validates scope/hints, validates ping parameters, resolves the account
and invokes application verifiers before inserting a pending request. The
signed omission and combined-feature regressions assert absence of persistence
and device dispatch on rejection, with successful pending controls.

[Current full Ruby 3.3 execution](../validation/alignment-consolidated-ruby33.txt):
395 tests, 10,593 assertions, zero failures/errors, two SQLite row-lock skips.
[Focused omission execution](../validation/signed-required-omissions.txt):
3 tests, 119 assertions, no failures/errors/skips. Test files are under `test/`.
