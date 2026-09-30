# Changelog

- Return HTTP401 invalid_client with a Basic challenge when CIBA client authentication is absent, following CIBA Core section13. Failed unauthenticated polls retain approval and issue no tokens; an authenticated retry can still succeed.

- Replace the reference-style minimum JWKS cache lifetime with explicit HTTP freshness. Authentication and encryption share publisher-authorized stale-if-error capped at60 seconds, without renewed freshness on failures. Honor restrictive directives and Age/Date; bound per-configuration cache storage and prevent in-flight fetches from restoring evicted keys.

- Accept and save CIBA max_age policy input, with request/default precedence and signed-input isolation. Existing request tables require Schema.add_request_max_age; application code enforces freshness.

- Select CIBA auth_time/acr/amr output from accepted request/client metadata and configured scopes, retaining source context through refresh. Existing development schemas require authentication_claims columns; NULL legacy sources preserve prior disclosure. See docs/authentication-claims.md.

- Add opt-in login_hint_token with a mandatory application resolver receiving the authenticated client. Enforce hint exclusivity and bounded input, preserve approval identity binding, and omit raw tokens from stored requests and observation snapshots. The application owns token-format validation; id_token_hint remains unsupported.

- Fix optional-capability deactivation for legacy requests bound to new-format consent: issuance now checks saved consent as well as request fields before allowing claims/resource/RAR processing to be disabled. Add RAR polling/narrowing and issuance/revocation race coverage.

- Connect opt-in RAR request validation, client/type registration, saved consent and mandatory issuance policy to resource token issuance. Persist effective details in token responses, resource JWTs and opaque introspection while excluding ID Tokens. See `docs/authorization-details.md` for application responsibilities and remaining concurrency/policy review.

- Add internal RAR structural validation and an explicit additive storage migration, with no protocol activation yet. Validate UTF-8, shape, size/depth and duplicate keys; pin the JSON runtime dependency to >=2.18,<3 for native duplicate-key rejection. RAR request/consent/issuance policy integration remains unfinished.

- Reject verified CIBA resource JWTs at introspection with `unsupported_token_type`, matching the reference OP's structured-token boundary. Opaque-token introspection continues to report current revocation. Other upstream OAuth token behavior is preserved; see `docs/resources.md`.

- Add resource omission-policy callbacks and verify claims/resource composition and concurrent target selection. Fix upstream resource-feature composition so request parameters cannot overwrite CIBA's saved JWT audience; preserve signature/issuer validation for OP-side resource-token introspection.

- Add optional resource indicators with saved per-resource consent, narrowed access-token scope/audience, separate ID Token context, opaque introspection audience and UserInfo rejection. Requires the additive `Schema.add_resources` migration and `ciba_resources_enabled`; see `docs/resources.md` for remaining policy and integration limits.

- Fix optional-claims UserInfo isolation for legacy JWTs: an unbound token cannot use another issuance's explicit claim consent after its own row is removed. Require a validated issuance reference before loading the new claim projection.

- Add opt-in explicit claim consent with separate requested/allowed/rejected storage, ID Token/UserInfo target filtering and exact-token UserInfo binding. Requires `Schema.add_claims` and `ciba_claims_enabled true`; see `docs/claims.md` for activation, migration and constraint-policy limits.

- Preserve an optional Backchannel request nonce through the signed ID Token, matching node's extension behavior. Poll parameters cannot replace it. Add a nullable request column and explicit `Schema.add_request_nonce` helper for existing development schemas; fresh schemas include it automatically.

- Default newly created saved consent to 14 days, matching node-oidc-provider's Grant TTL. Configure `ciba_grant_lifetime` or pass an explicit expiry; explicit nil and existing records retain no-expiry semantics. Convenience approval uses the new default too.

- Fix the example down migration to drop the consent foreign key before its column, including on MySQL. Verify all 104 tests on SQLite, PostgreSQL17 and MySQL8.4; add complete node-oidc-provider v9.12.2 HTTP lifecycle comparisons on Node24 LTS.

- Align result collection with node-oidc-provider: expiry precedes replay checks, denied results are consumed once, and replay of an unexpired consumed approved request revokes its saved consent and linked tokens.

- Revalidate saved consent after before-approve hooks; expiry or revocation prevents recording approval. Demonstrate saved Grant/result APIs with transactional creation and retry reuse.

- Default CIBA request lifetime and maximum to 600 seconds, following node-oidc-provider; explicit application overrides remain supported.

- Add required `trigger_ciba_authentication_device` application callback after request persistence and before successful response. Failures return `server_error`; legacy post-commit observation stays best-effort. Update existing integrations to configure the new callback.

## 0.1.0

Initial release candidate (not yet published).

- CIBA poll / login_hint OP extension with Discovery and confidential client authentication.
- Ruby approval, denial, idempotent completion, pending recovery and bounded cleanup APIs.
- Hashed request identifiers, transaction/savepoint boundaries, serialized state transitions.
- Transactional before/after hooks and best-effort post-commit callbacks/events.
- Explicit Sequel migration helper, local browser/RP example and DB/Ruby verification scripts.

Limitations: public subjects and statically provisioned CIBA clients; no refresh tokens, signed authentication requests, user_code, ping/push, other hints or CIBA pairwise/DCR. Not OpenID Certified.

- Removed the OP-wide basic/post-only restriction. CIBA uses enabled upstream confidential authentication, with JWT client-assertion audience handling for CIBA Core §7.1 and mixed-flow regression coverage.

- Security review: enforce OIDC client-assertion claims and single use with an explicit DB replay ledger; block Backchannel authorization-grant authentication confusion and OP-key fallback for missing client JWKS. Validate HMAC key lengths, malformed assertions and explicit client IDs.
- Omit invalid optional error descriptions, distinguish missing scope from invalid scope, and store polling intervals as 64-bit integers to preserve slow_down increases.
- Include effective scopes in CIBA token responses, including when unsupported offline_access was removed.
- Align binding-message defaults with node-oidc-provider v9.12.2 (1–20 display characters) and expose a replaceable validation policy.
- Separate saved CIBA consent from requests and issued OAuth rows; add backchannel_result, scope intersection, and grant revocation with a durable token reference. Requires the new consent schema and references.

- Accept generic completion error codes through `backchannel_result`, return them once and reject replay; add explicit `completion_error` migration preserving existing denials, and distinguish technical `failed` observation events from customer refusal.

- Align identity-hint azp/typ and time-claim handling with the pinned reference, recognize encoded b64 critical headers, retain independent trusted signature/issuer/audience checks and require fresh approval. Other token and client-assertion validation is unchanged.
