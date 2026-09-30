# Protocol-to-test mapping

Push is not implemented by the selected node-oidc-provider 9.12.2 reference or
this gem. Its conditional requirements are retained as `reference_unsupported`,
not passing tests. [Measured boundary](research/push-reference-boundary.md).

Optional refresh/related revocation coverage is in `test/ciba_refresh_test.rb`,
`test/ciba_refresh_storage_test.rb`, `test/ciba_refresh_permissions_test.rb`,
`test/ciba_refresh_hooks_test.rb`, `test/ciba_access_revocation_test.rb` and
`test/ciba_lock_order_test.rb`. It includes scoped issuance, source persistence,
rotation/replay, current-consent filtering, transaction hooks, cleanup,
access-versus-refresh revocation, token provenance and legacy formats. The
installed extension smoke covers opaque/JWT combinations. See the
[reference boundaries](research/access-token-revocation-reference.md) before
interpreting these tests as full OAuth revocation or node behavior equivalence.

Implementation extension (not a CIBA Core requirement): optional nonce propagation is tested by `test_nonce_is_bound_to_start_request_not_poll_and_not_observed`, `test_nonce_is_optional_and_bounded`, `test_nonce_forward_migration_preserves_existing_request` and the complete node HTTP harness. These tests do not add a CIBA conformance requirement.

Additional optional capabilities have separate coverage: `test/ciba_claims_test.rb` tests explicit claim consent and UserInfo provenance; `test/ciba_resources_test.rb` tests per-resource scope/audience, omission callbacks, saved-consent and original-target binding, JWT/opaque UserInfo rejection, introspection, issuance rollback, concurrent target selection and claims composition. The full node OP harness independently covers comparable claims and resource scenarios. See [claims limits](claims.md) and [resource limits](resources.md); these are not a claim of full OIDC claims or RFC8707 conformance.

This is the release's requirement mapping, not a certification claim. Run `ruby test/run.rb`; method names below are in `test/ciba_*_test.rb` unless otherwise noted. The implementation covers the declared subset; omitted optional features are not counted as passing tests.

| Reference / concern | Test method(s) |
|---|---|
| CIBA §4: Discovery / poll metadata | `test_discovery_describes_poll_and_keeps_existing_oidc_metadata` |
| CIBA §7, §7.1: TLS, form POST, confidential authentication | `test_non_tls_and_json_requests_are_rejected`, `test_client_authentication_is_required_at_both_endpoints`, `test_post_client_authentication`, `test_basic_credentials_are_form_decoded_and_hashed_secrets_work`, `test_two_authentication_methods_are_rejected` |
| CIBA §7.1–7.2: hint, scope, unsupported features, unknown parameters | `test_request_validation_and_unknown_parameters` |
| Optional login_hint_token resolver, exclusive hints, account binding and raw-token exclusion | `test/ciba_hint_token_test.rb`; complete node HTTP comparison and installed-gem extension smoke |
| Optional id_token_hint signature/issuer/audience/time boundary, retained keys and new approval | `test/ciba_id_token_hint_test.rb`; complete node comparison; installed-gem extension smoke; [validation differences](id-token-hint.md) |
| Optional signed request metadata, client keys, required claims and inner-only parameters | `test/ciba_signed_request_test.rb`, `test/ciba_remote_jwks_test.rb`; complete node comparison and installed-gem signed requests; [limits](signed-requests.md) |
| Optional user_code application policy, missing/invalid errors, no raw persistence and new approval | `test/ciba_user_code_test.rb`; complete node comparison and installed-gem signed-request composition; [policy boundary](user-code.md) |
| Optional request_context application callback, persistence, signed input, failure boundaries and no automatic token claim | `test/ciba_request_context_test.rb`; complete node HTTP harness and installed extension smoke; [contract](request-context.md) |
| Optional ping: metadata, private delivery data, completion/notification ordering, retry, cleanup | `test/ciba_ping_test.rb`, installed-gem `examples/ping_smoke.rb`, independent node `test/reference/full-op/ping.mjs`; [limits](ping.md) |
| CIBA §7.1: binding / requested expiry / context | `test_expiry_binding_context_and_offline_access` |
| OAuth request parsing: repeated parameters / encoding / bounds | `test_duplicate_parameters_are_rejected`, `test_invalid_utf8_and_oversized_body_are_rejected`, `test_rack_inputs_without_rewind_work_on_both_endpoints` |
| CIBA §7.3: acknowledgement / no-store | `test_expiry_binding_context_and_offline_access`, `test_approved_request_issues_customer_id_token_once` |
| CIBA §10.1: client-bound request / subject | `test_other_identity_client_and_expiry_cannot_issue` |
| CIBA §10.1.1 / OIDC Core §2: signed ID Token, issuer/audience/context | `test_approved_request_issues_customer_id_token_once`, `test_id_token_audience_is_client_even_with_different_access_audience`, `test_missing_authentication_context_is_not_fabricated`, `test_unsigned_id_token_client_is_rejected` |
| CIBA §10.1.1: one successful redemption | `test_approved_request_issues_customer_id_token_once`, `test_concurrent_polls_issue_one_grant` |
| CIBA §11: pending / slow_down | `test_pending_poll_updates_survive_json_halt`, `test_concurrent_pending_polls_both_receive_retryable_results` |
| CIBA §11: denial / expiry | `test_denial_and_expired_completion`, `test_other_identity_client_and_expiry_cannot_issue`, `test_expiry_during_before_issue_rolls_back_and_returns_expired` |
| App completion contract / retry / identity | `test_approval_is_idempotent_and_context_conflicts_are_rejected`, `test_concurrent_approve_and_deny_choose_one_decision`, `test_client_and_account_changes_are_rechecked` |
| Signing and hook rollback / savepoints | `test_signing_failure_rolls_back_consumption_and_grant_then_allows_retry`, `test_hooks_see_before_and_after_states_and_failure_rolls_back`, `test_completion_hook_failure_rolls_back_and_retry_does_not_repeat_hooks`, `test_failure_reported_inside_outer_transaction_still_rolls_back_inner_work` |
| Commit observations / rollback / callback failure | `test_observation_waits_for_outer_commit_and_does_not_change_result`, `test_outer_rollback_discards_issuance_and_observation`, `test_savepoint_rollback_discards_event_even_when_outer_transaction_commits`, `test_request_callbacks_after_commit_and_observer_secrets`, `test_acceptance_hook_rollback_does_not_notify` |
| Reentrancy / immutable lookup / recovery / cleanup | `test_reentrant_completion_is_rejected_even_from_another_auth_instance`, `test_request_lookup_recovery_and_cleanup`, `test_expired_pending_cleanup_and_live_approved_retention` |
| Schema / migration / uniqueness | `test_custom_table_and_column_mapping`, `test_migration_client_metadata_helper`, `test_explicit_migration_up_and_down`, `test_schema_rejects_duplicate_public_identifier` |
| Upstream coexistence / initial restrictions | `test_authorization_code_flow_still_uses_oidc_wrapper`, `test_dcr_rejects_ciba_but_preserves_other_grant_validation`, `test_unavailable_or_unsupported_client_metadata_is_rejected`, `test_jwt_access_token_configuration_also_works` |
| Demo's browser transport | `DemoTest#test_browser_approval_checks_csrf_and_finishes_request`, `test_default_require_loads_jwt_backend_in_fresh_process` |

## Primary specifications

- [CIBA Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)
- [OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html)

Product policies (size limits, offline_access removal, static/public restriction, internal API semantics) are distinguished in [the API documentation](api.md). The test suite verifies those policies; it does not imply they are universally required by the specifications.

## Conformance Suite cases consulted

The following files were read from the OpenID Foundation's read-only mirror at commit `fc6a65c4ac25a7f1fc8a92205ebc5836f321189d` on2026-09-29:

- [FAPICIBAID1AuthReqIdExpired](https://github.com/openid-certification/conformance-suite/blob/fc6a65c4ac25a7f1fc8a92205ebc5836f321189d/src/main/java/net/openid/conformance/fapiciba/FAPICIBAID1AuthReqIdExpired.java): requested lifetime followed by an expired collection attempt. The local tests use a controlled clock/DB deadline instead of sleeping.
- [FAPICIBAID1EnsureAuthorizationRequestWithMultipleHintsFails](https://github.com/openid-certification/conformance-suite/blob/fc6a65c4ac25a7f1fc8a92205ebc5836f321189d/src/main/java/net/openid/conformance/fapiciba/FAPICIBAID1EnsureAuthorizationRequestWithMultipleHintsFails.java): multiple hints are rejected. Local coverage exercises login_hint combined with the other hint parameters.
- [FAPICIBAID1EnsureAuthorizationRequestWithBindingMessageSucceeds](https://github.com/openid-certification/conformance-suite/blob/fc6a65c4ac25a7f1fc8a92205ebc5836f321189d/src/main/java/net/openid/conformance/fapiciba/FAPICIBAID1EnsureAuthorizationRequestWithBindingMessageSucceeds.java): ordinary binding-message success. The local suite validates storage and the demo displays the message with HTML escaping.

These are references for overlapping behaviors only. Their FAPI profile setup is not implemented here. No Suite code is copied into the gem, and neither the complete Suite nor certification tests have been run.

## Client authentication compatibility follow-up

CIBA Core §4 shares the OP's `token_endpoint_auth_methods_supported` metadata; it does not require basic/post-only OP configuration. §7.1 requires registered client authentication and accepts issuer/token/backchannel audiences for JWT assertions at the Backchannel Endpoint.

- `test_upstream_jwt_authentication_coexists_with_ciba_and_discovery`: private_key_jwt CIBA start/poll, all three start audiences, existing authorization_code, Basic CIBA on the same OP, unchanged Discovery support.
- `test_ciba_jwt_authentication_rejects_wrong_audience_signature_and_mixed_credentials`: wrong audience/signature and duplicate authentication rejected.
- `test_upstream_client_secret_jwt_works_for_ciba`: upstream shared-secret JWT start/poll.
- `test_public_clients_can_exist_but_cannot_use_ciba`: public-client configuration is allowed for the OP, excluded from CIBA.

These tests do not claim all upstream authentication mechanisms are validated. JWT client authentication is distinct from the opt-in signed CIBA authentication requests covered above. See the following additional integration boundaries.

## Additional authentication and registration coverage

| Boundary | Current evidence |
|---|---|
| JWT assertion issuer audience at refresh, wrong audience and replay | `test/ciba_assertion_refresh_test.rb`, `test/reference/full-op/assertion-refresh.mjs` |
| Discovery retention of configured introspection, DPoP algorithms and mTLS capability | `test/ciba_discovery_extensions_test.rb`; installed smoke follows discovered URLs |
| DPoP proof, nonce policy, replay, UserInfo, introspection and refresh | `test/ciba_dpop_test.rb`, `test/ciba_dpop_registration_test.rb`, `examples/dpop_smoke.rb`, `test/reference/full-op/dpop.mjs`; [contract](research/dpop-reference-contract.md) |
| mTLS trust callbacks, exact certificate binding, opaque/JWT UserInfo and introspection, refresh | `test/ciba_mtls_test.rb`, `examples/mtls_smoke.rb`, `test/reference/full-op/mtls.mjs`; [contract](research/mtls-reference-contract.md) |
| mTLS remote JWKS rotation, retrieval failure and recovery | `test/ciba_mtls_remote_test.rb`; installed `examples/mtls_smoke.rb` uses verified HTTPS and forced cache expiry |
| mTLS registration policy and management replacement | `test/ciba_mtls_registration_test.rb`; node and installed TLS fixtures |
| Dynamic registration/management, metadata, credentials and concurrency | `test/ciba_registration_test.rb`, `test/ciba_registration_remote_test.rb`, `examples/registration_smoke.rb`; [contract](research/registration-reference-contract.md) |
| Pairwise subjects, hints, refresh, sector documents and management | `test/ciba_pairwise_test.rb`, installed `examples/ping_smoke.rb`; [contract](research/pairwise-reference-contract.md) |

These rows map integration boundaries, not every normative requirement in the
referenced RFCs. Application-owned endpoint aliases have distinct-port TLS
coverage; arbitrary proxy/path rewriting and distributed cache behavior do not.
Consult [release validation](release-validation.md) for the tested Ruby/DB
combinations; file presence alone is not proof of a successful run.

## Manual requirements and security review

The historical 2026-09-29, 159-item initial-scope classification is in [requirements-audit.md](requirements-audit.md). Its excluded optional features do not describe the subsequently implemented extensions. An incremental [current audit overlay](requirements-audit-current.md) now records reviewed and pending IDs; the full normative re-audit remains incomplete; [the alignment roadmap](alignment-roadmap.md) tracks current evidence and gaps. Classification separates mandatory, conditional, recommended and optional behavior and identifies gem/upstream/application/client responsibilities. The Jev scores are historical inputs, not compliance evidence.

Additional direct tests in `test/ciba_security_test.rb` cover OIDC Core §9 required assertion claims, issuer/subject/client binding, malformed assertions, missing client keys, short HMAC keys, replay across endpoints/flows, concurrent replay, bounded ledger cleanup and persistent slow_down growth. `test/ciba_requirements_test.rb` covers acknowledgement identifier format, exact expiry boundary, HTTP401 authentication errors, missing-vs-invalid scope and optional error-description ASCII constraints. See [security-review.md](security-review.md) for findings and test limits.

## node-oidc-provider alignment

`test/ciba_alignment_test.rb` verifies the v9.12.2 binding-message default and application replacement policy. The demo XSS/CSRF test explicitly relaxes that policy to continue checking output escaping. See [alignment progress](node-alignment.md); this is not a claim that the remaining API or protocol differences are resolved.

`test/ciba_grant_test.rb` verifies persisted consent, client/account binding, requested/approved scope intersection, untrusted snapshot-field rejection, consent expiry/revocation at collection, issuance/revocation races, revocation after request cleanup, completion retries and transactional rollback. That file alone does not cover node-specific claim/resource/RAR consent. Separate tests cover those extensions; executed PostgreSQL/MySQL evidence is recorded in [release validation](release-validation.md).

- AD initiation integration: `test/ciba_alignment_test.rb` verifies saved request handoff before response, synchronous completion, missing implementation/dispatch failure, and rejection before dispatch. This application callback is an implementation boundary, not a standardized CIBA approval HTTP API.

- Shared OIDC issuance: `test_common_oidc_claim_provider_only_receives_approved_scopes` verifies account claims come from the upstream provider using effective consent scopes, without browser-session authentication-time lookup. Full claims-parameter consent and resource/RAR support remain outside this evidence.

- Completion consistency: `test_grant_expiry_during_before_approve_does_not_record_approval` and `test_grant_revocation_during_before_approve_rolls_back_the_completion` check revalidation after transactional hooks. Demo tests cover saved consent reuse, conflicting decision rollback, and another customer’s request rejection.
