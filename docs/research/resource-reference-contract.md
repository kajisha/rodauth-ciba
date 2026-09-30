# Resource indicators: reference behavior and integration boundary

2026-09-30. The complete node-oidc-provider 9.12.2 harness now registers two resource servers with separate read/write consent and JWT access tokens. It runs on Node24.21.0 with the built-in memory adapter; the resource information callback uses a fixed registry and performs no network discovery.

## Verified behavior

| Scenario | Complete reference OP result |
|---|---|
| Start with two repeated resource parameters; select A at the Token Endpoint | Access token audience is A and scope is A's approved read permission, not B's write permission. ID Token audience remains client. Both JWT signatures are verified. |
| Poll selects B when only A was requested, even though saved Grant allows B | invalid_target; the request has already been consumed by the reference's nontransactional lifecycle. |
| Start requests A, but polling omits resource | With default useGrantedResource=false and UserInfo enabled, issuance selects the OIDC/UserInfo path. Token scope is openid and no resource audience is set. |
| Relative URI, fragment-bearing URI, or unregistered resource at start | invalid_target. |
| Introspection of a resource JWT, before and after replay revocation | HTTP 400 unsupported_token_type; the OP does not report active/inactive for this structured token. |

[Executable harness](../../test/reference/full-op/lifecycle.mjs), [LTS log](../validation/node-full-op-lts.txt). Existing completion, claims, nonce, expiry and replay scenarios still pass in the same OP run.

[RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html#section-2) permits repeated resource parameters, requires absolute fragment-free identifiers, and defines invalid_target. An identifier need not be fetched as a URL. Issued tokens should be audience-restricted; the resource value may be mapped to an audience. Omission policy is an authorization-server choice, not a requirement to pick the first requested target.

## Required gem changes

The original integration review found global duplicate-key rejection and one scope set shared by access-token creation and the ID Token gate. The optional implementation now addresses these assumptions; see [activation and current limitations](../resources.md). The following remains the design and verification contract, not a claim that all optional policies are complete.

1. Permit repeated `resource` values only in this extension; keep duplicate rejection for grant_type, hints, credentials and other scalar parameters. Preserve the original validated requested set separately from token-time selection. Signed request arrays remain out of the current profile.
2. Store resource permissions on saved consent as a map from identifier to scope set. Requested resources are not proof of approval. Revalidate client eligibility, resource registration, saved consent and revocation before issuance and after transactional hooks.
3. Keep OIDC scopes and resource scopes separate. Upstream `generate_id_token` requires openid in the grant it receives; a resource-specific access token legitimately has only read/write. Do not solve this by adding openid or all consent scopes to the resource token. Supply the appropriate approved OIDC context to ID Token generation while preserving the access token's narrowed scope and audience.
4. Persist the selected resource/audience and effective resource scope on the issued token row. JWT and opaque/introspection paths must express the same restriction. A resource token must not gain access to UserInfo merely because a scope string resembles an OIDC scope.
5. Specify omission policy explicitly. The reference default is the UserInfo path, not automatic selection of the sole requested resource. An application policy may choose a granted resource; multiple candidates require deterministic selection or rejection, never accidental first-element selection.
6. Add nullable request/consent/token fields with an explicit migration. Old rows carry no resource permission. Activate after every worker enforces the new fields; preserve current scope-only behavior when disabled and do not roll back while restricted tokens remain active.

The existing approved same-DB rollback policy still applies. Do not copy reference consumption-after-invalid_target solely because it is observed with the memory adapter. Determine failure timing and retry behavior in the gem and test it explicitly.

## Upstream integration review

rodauth-oauth 1.7.0 `oauth_resource_indicators` handles repeated form values and can add audiences to JWT/introspection output. Its shown grant validation hooks cover authorization-code and token-exchange-style helpers, not this CIBA saved-consent map. Its JWT audience method also reads request parameters; it does not prove the value was part of a CIBA approval. Enabling that feature alone is therefore insufficient.

Additional reference evidence: selecting a requested target with no saved permission returns a token with no scope claim in its JWT and an empty response scope. It does not fall back to OIDC permission. The gem's upstream encoder represents the same empty permission as an empty JWT scope string.

JWT introspection follow-up: the initial hypothesis that the reference returns active=true then active=false after revocation was disproved by its HTTP response. `lib/shared/reject_structured_tokens.js` rejects decodable JWT headers before introspection (and revocation) handling. The gem now returns unsupported_token_type for a verified CIBA resource JWT. It preserves upstream handling for non-resource tokens and invalid signatures rather than globally changing all OP flows. Opaque introspection remains the online revocation path. This difference is documented rather than mistaken for complete structured-token parity.

The gem now tests request/consent/policy intersection, policy removal in the issue hook, malformed/multiple targets, omission, JWT and opaque audience, UserInfo denial including openid-bearing resource tokens, opaque revocation, signing rollback and additive migration. Follow-up tests add default-resource callbacks, later activation of the upstream resource feature, explicit ID Token claims with resource tokens, and concurrent selection of two different audiences. Node's complete OP confirms opt-in single-target selection, ambiguity rejection and configured default selection. All feature load orders and all claim combinations are not covered. Current reference tests establish a contract subset, not complete RFC8707 or resource-server enforcement.
