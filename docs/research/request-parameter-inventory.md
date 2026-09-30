# Authentication request validation inventory

This reconciles CIBA-067 against the implemented request parser. It records
protocol validation, not identical policy defaults in every node deployment or
an independent conformance certification. Required presence and exclusive hint
selection are separately covered by the [mandatory inventory](required-parameter-inventory.md).

All test references below are in `test/`; each named test is included in the
[current400-test run](../validation/id-hint-validation-full-ruby33.txt).

| Inputs | Implemented boundary | Direct tests |
|---|---|---|
| Form and repeated parameters | TLS POST/form, no query parameters, bounded body, encoding and duplicate checks; repeated resource has its defined handling | `ciba_protocol_test.rb:test_ciba_endpoints_require_tls_post_and_form_before_state_changes`, `test_duplicate_parameters_are_rejected`; `ciba_resources_test.rb:test_resource_validation_and_additive_migration` |
| scope | Required openid, scope syntax and registered permissions; offline_access obeys refresh activation | `ciba_requirements_test.rb:test_scope_syntax_errors_are_invalid_scope`; `ciba_protocol_test.rb:test_expiry_binding_context_and_offline_access` |
| login_hint / login_hint_token | Exclusive enabled hint, string/size bounds; application resolution and eligible account | `ciba_protocol_test.rb:test_request_validation_and_unknown_parameters`; `ciba_hint_token_test.rb:test_hint_token_input_exclusivity_size_and_unknown_user` |
| id_token_hint | Signature, configured algorithm, issuer/audience/subject, shape/time checks and account mapping; expired tokens are identity hints | `ciba_id_token_hint_test.rb:test_id_hint_rejects_untrusted_claims_and_signatures_before_subject_resolution`, `test_id_hint_malformed_signed_claims_are_protocol_errors`, `test_id_hint_expired_token_is_only_an_identity_hint` |
| binding_message / requested_expiry | Application binding-message validator, positive integer expiry and configured cap | `ciba_protocol_test.rb:test_expiry_binding_context_and_offline_access`; `ciba_requirements_test.rb:test_requested_expiry_expires_at_the_exact_boundary` |
| acr_values | Bounded string, empty/omitted registered defaults; authentication policy remains application-owned | `ciba_authentication_claims_test.rb:test_empty_acr_values_uses_defaults_in_plain_and_signed_requests`, `test_registered_authentication_defaults_apply_before_dispatch` |
| request / request_uri | Registered signed JWT, key/signature/required claims, inner parameters replace outer; nested/remote request references rejected | `ciba_signed_request_test.rb:test_signed_request_rejects_bad_claims_and_keys_before_persistence`, `test_signed_request_missing_required_fields_cannot_use_outer_values` |
| user_code | Feature activation, bounded string and mandatory application verifier, before persistence | `ciba_user_code_test.rb:test_user_code_input_and_optional_client_policy`, `test_user_code_requires_explicit_callback_and_checks_before_device_dispatch` |
| client_notification_token | Required for ping; bearer syntax and size | `ciba_ping_test.rb:test_ping_notification_token_bearer_syntax_and_maximum_length`, `test_signed_ping_required_fields_cannot_be_supplied_outside_signature` |
| nonce | Optional bounded string, bound to accepted request rather than poll | `ciba_nonce_test.rb:test_nonce_is_optional_and_bounded`, `test_nonce_is_bound_to_start_request_not_poll_and_not_observed` |
| claims | Enabled JSON object/target shape, separate saved consent; claim values are not identity data | `ciba_claims_test.rb:test_claim_input_validation_and_disabled_consent`, `test_claim_rejection_overrides_scope_and_request_value_is_not_identity_data` |
| resource | Enabled registered URI targets, duplicate handling, scope and audience separation | `ciba_resources_test.rb:test_resource_validation_and_additive_migration`, `test_resource_scope_and_audience_match_reference_and_id_token_keeps_oidc_context` |
| authorization_details | Enabled JSON structure, registered types, target and application policy | `ciba_rar_test.rb:test_rar_request_shape_client_types_and_resource_are_validated` |
| max_age | Bounded numeric normalization, safe integer range and defaults; authentication freshness is enforced by the application | `ciba_max_age_test.rb:test_max_age_invalid_values_do_not_dispatch_or_persist` |
| request_context | Enabled bounded string and mandatory application validator before dispatch; signed inner value isolation | `ciba_request_context_test.rb:test_request_context_rejection_precedes_persistence_and_device_dispatch`, `test_request_context_signed_input_replaces_outer_context` |
| Unknown input | Ignored; cannot write server-side state | `ciba_protocol_test.rb:test_login_hint_is_application_defined_and_unknown_fields_cannot_set_state` |

Client authentication is processed independently before these request values.
Content-specific interpretation of opaque hints, authentication strength,
claims, resources, rich authorization details and request context belongs to
the configured application callbacks; parser validation does not establish
production policy correctness. Disabled optional features and unknown fields
follow their documented handling rather than implicitly enabling a feature.

Remaining compatibility choices are explicit: user-code activation (CIBA-013),
hint retention (CIBA-151). The previous stricter ID-hint profile has now been
aligned as documented in [the hint policy](../id-token-hint.md), with a three-DB regression and the updated400-test full run above. They are not hidden missing parser
features, nor are they declared approved by this inventory. Remote key cache
policy is also still pending. A full Cartesian product of extensions is not
necessary evidence for this aggregate parameter-validation row.
