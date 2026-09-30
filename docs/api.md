# Configuration and Ruby API (0.1.0)

Optional [login_hint_token](login-hint-token.md) uses `ciba_login_hint_token_enabled` and a required application resolver; no schema migration is needed.

Optional [id_token_hint](id-token-hint.md) uses a dedicated signature/claim verifier and required subject-to-account resolver. It never inherits approval; no migration is needed.

Optional [signed requests](signed-requests.md) require client metadata migration, registered verification keys and `ciba_request_signing_algorithms`. Signature verification does not replace client authentication.

Optional [user codes](user-code.md) require client metadata migration and an application validation callback. Raw codes are never stored by the feature; code acceptance does not replace customer approval.

Optional [ping](ping.md) adds private delivery storage, after-commit notification and `retry_ciba_ping(request_id)`. Notification failure does not roll back saved approval/denial.

Optional [authorization details (RAR)](authorization-details.md) require resource support, a separate migration, client type registration and application validation/issuance policies.

Optional [resource indicators](resources.md) provide saved per-resource permissions and access-token audience restriction after `Schema.add_resources` and `ciba_resources_enabled true`.

Optional [explicit claim consent](claims.md) is available after its separate migration and `ciba_claims_enabled true`. It is not part of the default scope-only profile.

Opt-in [DPoP integration and its tested boundary](research/dpop-reference-contract.md)
requires upstream `:oauth_dpop`, the token thumbprint column and the shared client
assertion replay ledger. To support server nonce challenges, configure
`ciba_dpop_nonce_secret` with a persisted, issuer-specific random 32-byte String
shared by all issuer processes. Set `oauth_dpop_use_nonce true` to require nonces;
otherwise fresh proofs may omit them. Never generate this secret per request or
boot. The CIBA boundary uses the reference minute-based nonce window, not the
upstream `oauth_dpop_nonce_expires_in` lifetime. External resource-server
enforcement is not provided by this UserInfo/token-endpoint integration.

With upstream introspection or DPoP enabled, OIDC Discovery preserves their
configured endpoint/authentication and proof-algorithm metadata from OAuth
server metadata. Disabled features are not advertised. Renaming the introspection
route changes the discovered URL accordingly.

The initial [mTLS integration](research/mtls-reference-contract.md#initial-ciba-correction)
requires upstream `:oauth_tls_client_auth`, its grant thumbprint column and an
explicit `ciba_tls_client_certificate` callback returning the verified TLS
connection's peer certificate (OpenSSL certificate or PEM), or nil. PKI clients
also require `ciba_tls_client_certificate_authorized?` and
`ciba_tls_client_certificate_subject_matches?(property, expected)` to return true
for the chain and registered DN/SAN identity. These callbacks default to denying
access; the gem does not trust forwarded certificate headers. The application
must provide a trusted TLS server or terminator integration. Self-signed clients
are matched against registered x5c certificates. The packaged `mtls_smoke.rb`
demonstrates one actual Ruby TLS adapter and is verified after temporary gem
installation. Installed HTTPS certificate-rotation tests also pass; verification of a production proxy remains the application's responsibility. See the [mTLS contract](research/mtls-reference-contract.md).

With this feature enabled, both Discovery documents advertise
`tls_client_certificate_bound_access_tokens: true` as a capability. For CIBA
issuance and refresh, binding is required only by the client's
`tls_client_certificate_bound_access_tokens` metadata. The upstream global
`oauth_tls_client_certificate_bound_access_tokens` policy does not force CIBA
clients to bind tokens; it remains unchanged for other upstream OAuth grants.
Disabling client binding affects new access tokens, never existing bound tokens.

`mtls_endpoint_aliases` is application deployment metadata, not an automatically
created set of gem routes. Publish the alias URLs through Discovery middleware,
route them to the same application, keep `base_url` and
`authorization_server_url` fixed to the canonical issuer, and obtain certificates
from the trusted TLS adapter on each listener. The installed `mtls_smoke.rb`
exercises a second TLS port for CIBA, token, introspection and UserInfo while
verifying the canonical ID Token issuer. Arbitrary path rewriting and reverse
proxy behavior are not covered by that example.


Enable `:ciba` after requiring `rodauth/ciba`. It depends on upstream `:oidc`. Configure your usual accounts, OAuth application/grant tables, signing keys and issuer first. Existing authorization-code behavior is delegated to upstream.

## Application configuration

```ruby
ciba_request_lifetime 300 # Optional override; default is 600.
ciba_max_request_lifetime 600 # Default upper bound.
ciba_grant_lifetime 14 * 24 * 60 * 60 # Optional override; default consent lifetime.
resolve_ciba_login_hint do |hint, oauth_application:|
  # Validate your own identifier format and tenant/client authorization here.
  # Return a local account primary key, or nil for an unknown/ineligible user.
  db[:accounts].where(email: hint).get(:id)
end
trigger_ciba_authentication_device do |request|
  # Start your application-owned approval flow with request[:id].
end
```

The default request lifetime and maximum are both 600 seconds, matching node-oidc-provider’s default BackchannelAuthenticationRequest TTL. A valid requested_expiry is capped at the configured maximum. Lifetime values are seconds, positive integers; default must not exceed maximum (maximum <= 2^31-1). There is no implicit email lookup. Explicit signing keys are required; `none` is rejected. Default account eligibility is an existing open Rodauth account; override `ciba_account_eligible?(account_id)` for another account model.

Both endpoints use upstream client authentication. CIBA uses the upstream enabled confidential client authentication methods and preserves the OP-wide Discovery metadata. It does not restrict other OAuth flows. Public clients (`none`) cannot use CIBA. CIBA Basic credentials are strictly base64-decoded and form-decoded before upstream secret verification; supplying Basic and post credentials together is rejected. Shared secrets should retain upstream's default hashing configuration. The demo explicitly disables hashing for its disposable fixture only.

Enable upstream `:oauth_jwt_bearer_grant` to use `private_key_jwt` or, where upstream permits shared-secret storage, `client_secret_jwt`. JWT signature/key verification uses upstream, with CIBA-side checks for required client claims, issuer/subject/client-ID binding, client key availability and one-time use. At the Backchannel Endpoint, assertion audiences accept the OP issuer, token URL or backchannel URL as required by CIBA Core §7.1; CIBA grant token requests accept either the OP issuer or token request URL as audience; both string and string-array audiences are supported. This does not enable signed CIBA authentication requests (`request`). Basic/post and both JWT methods have integration coverage. An explicit twelve-algorithm RS/PS/ES/HS matrix verifies advertised client assertion algorithms on both endpoints; see the [matrix and limits](research/client-assertion-algorithm-contract.md). Other upstream mechanisms require deployment-specific validation.

Create the assertion replay ledger using `Schema.create_client_assertions(db)` before enabling JWT client authentication. The example migration includes it. The `ciba_client_assertions_table` setting and helper's `table:` option customize its name. CIBA-capable clients share this ledger across Backchannel and other grant flows, preventing reuse through another endpoint. Clients without the CIBA grant retain upstream behavior. The ledger stores a SHA-256 digest of client ID plus jti and the assertion expiry, not the assertion itself.

JWT client assertions require `iss`, `sub`, `aud`, `exp`, `jti`. Issuer and subject must identify the same registered client. Use a fresh assertion for every attempt, including polling and retries. jti is limited to 1024 bytes. Shared-secret JWT keys must be at least 32/48/64 bytes for HS256/384/512 respectively. An absent client JWKS cannot fall back to OP signing keys. The OP's own signing keys and client keys are separate trust inputs.

`cleanup_ciba_client_assertions(limit: 100)` deletes only expired ledger rows in bounded batches (limit 1..1000). Schedule it in the host application; do not delete live rows. Custom error descriptions containing characters outside OAuth's allowed ASCII repertoire are omitted from CIBA responses.

Statically provision each CIBA application with:

- `grant_types` containing `urn:openid:params:grant-type:ciba` (space separated, as upstream stores it).
- `backchannel_token_delivery_mode = 'poll'`.
- `subject_type = 'public'` (or the OP's public fallback).
- Allowed `scopes` containing `openid` and a registered supported authentication method.

CIBA DCR requests are rejected. Existing non-CIBA registration validation is forwarded to upstream. Pairwise remains advertised for upstream flows; CIBA rejects a pairwise client.

## Other settings

| Rodauth setting | Default / meaning |
|---|---|
| `ciba_requests_table` | `:ciba_requests` |
| `ciba_grants_table` | `:ciba_grants`, saved consent scopes |
| `oauth_grants_ciba_grant_id_column` | `:ciba_grant_id`, durable link from an issued OAuth grant to consent |
| `ciba_request_columns` | `{}`; canonical column symbol → physical column symbol |
| `oauth_applications_backchannel_token_delivery_mode_column` | `:backchannel_token_delivery_mode` |
| `ciba_poll_interval` | `5` seconds, positive integer <= 2^31-1 |
| `ciba_max_request_bytes` | `16384`, maximum form-body bytes |
| `ciba_require_tls` | `true`; disable only for local test/demo |
| `backchannel_authentication_route` | `"backchannel-authentication"`, normal Rodauth route setting |

`binding_message` is optional. Its default policy matches node-oidc-provider v9.12.2: 1–20 characters from `A-Z a-z 0-9 - . _ + / ! ? #`. Configure `validate_ciba_binding_message` to replace that policy; it receives the string or nil and must raise `ciba_error("invalid_binding_message")` to reject it. The form-body limit and string/encoding validation apply independently of the callback. A custom policy may require a message or allow localized text. Applications must still HTML-escape displayed values. Hint/acr_values are limited to1024 bytes and scope to4096 bytes. These are library policies, not limits imposed by CIBA. Unknown parameters are ignored. `request_uri` is rejected. Signed `request`, additional hints and `user_code` require their documented feature configuration; unsupported use is rejected. `offline_access` is removed by default; the token response reflects effective scopes. The optional [refresh implementation](refresh-tokens.md) retains it when enabled, but that implementation is still in progress. `requested_expiry` is capped at the configured maximum.

To publish Discovery in a Roda app, use upstream routing explicitly:

```ruby
route do |r|
  rodauth.load_openid_configuration_route
  rodauth.load_oauth_server_metadata_route # optional OAuth metadata endpoint
  r.rodauth
end
```

## Completion API

These are trusted in-process calls; none creates an HTTP approval endpoint. Authenticate the customer and authorize the decision in your application before calling them. Use the internal integer `id`, never the client's `auth_req_id` as proof of approval.

The canonical result API mirrors the request/saved-Grant boundary of node-oidc-provider. A CIBA grant represents consent, independently of both the pending request and upstream rows containing issued tokens:

```ruby
request = rodauth.ciba_request(id)
grant = rodauth.create_ciba_grant(
  account_id: local_customer_id,
  oauth_application_id: request.fetch(:oauth_application_id),
  scopes: "openid read", # the scopes the authenticated customer actually approved
  expires_at: Time.now.to_i + 300 # optional; omitted defaults to 14 days, explicit nil disables expiry
)
rodauth.backchannel_result(id, grant,
  auth_time: authentication_time.to_i, acr: "urn:example:mfa", amr: ["pwd", "otp"])
# A saved grant's integer ID can also be passed as the second argument.
```

`create_ciba_grant` returns a frozen snapshot. Scope syntax and the account/client's eligibility are validated; the initial CIBA profile requires `openid`. This method does not authenticate the customer or issue a token. The application must authorize creation. The grant may cover several requests for the same account/client; each request still needs its own completion call.

`backchannel_result` reloads the saved grant by ID: modifying a supplied hash cannot grant extra scope or claims. It checks client/account identity, expiry and revocation. Token issuance intersects requested scope with saved consent and current client eligibility. Requested scopes remain unchanged in the request snapshot. A different grant on a completion retry is a conflict. Optional [claims](claims.md), [resource permissions](resources.md) and [RAR consent](authorization-details.md) have separate configuration and saved-consent contracts.

To report refusal through the same result API:

```ruby
rodauth.backchannel_result(id,
  Rodauth::CibaSupport::ProtocolError.new("access_denied"))
```

`ProtocolError` now supports standard or application-defined error codes. The call is trusted: authenticate and authorize the application actor before recording a result. Codes must be nonempty OAuth error ASCII (no quotes, backslashes or control characters), at most1024 bytes. The first poll returns the saved code and consumes the request; later polls return `invalid_grant`. Submitting `authorization_pending` or `slow_down` as a completion therefore terminates the request, like the reference API; use ordinary pending state for ongoing work. No description parameter is exposed: the pinned reference does not retain an application-provided description through this path. See the [comparison](research/completion-error-boundaries.md).

Existing databases must explicitly run `Rodauth::CibaSupport::Schema.add_completion_error(db)` before upgrading. Custom tables/columns use `table:`/`column:` plus `ciba_request_columns`. New schemas include the nullable text field. NULL preserves `access_denied` for existing denials. Negative completions retain the internal `denied` state, `:denied` return value and transactional `before_ciba_deny` / `after_ciba_deny` hooks. Inspect `completion_error` to distinguish technical failure from customer refusal. Non-denial failures emit a post-commit `failed` event with `error`; customer refusal continues to emit `denied`. An identical completion retry does nothing; changing its code or replacing it with approval/refusal raises `Conflict`.

The existing convenience API is retained. Approval creates a saved consent grant for the whole requested scope in the completion transaction; identical retries do not create duplicate grants:

```ruby
request = rodauth.ciba_request(id)
rodauth.approve_ciba_request(id, account_id: local_customer_id,
  auth_time: authentication_time.to_i, acr: "urn:example:mfa", amr: ["pwd", "otp"])
rodauth.deny_ciba_request(id, account_id: local_customer_id)
```

Returns `:approved` / `:denied` on a new decision; `:already_completed` on an identical retry. Approval retries compare account, auth_time, acr and sorted/deduplicated amr. An identical approval after consumption is permitted until request expiry but never returns a token. Completion retries do not repeat hooks/events. Expiry wins over retry, including terminal states. Authentication context is optional; do not substitute approval time for unknown authentication time. Requested `acr_values` is visible in the snapshot; your application decides which authentication is necessary and reports the achieved acr.

Exceptions in `Rodauth::CibaSupport`:

| Class | Meaning |
|---|---|
| `NotFound` | Request absent/cleaned up |
| `IdentityMismatch` | Supplied customer differs from the fixed request target |
| `Expired` | Deadline reached |
| `Conflict` | Different decision/context, or a conflicting modification |
| `Ineligible` | Account/client no longer eligible |
| `ReentrantMutation` | Another mutation of this request is active in the same execution context |

All inherit `CompletionError`. Invalid argument shapes raise `ArgumentError`. DB and application-hook failures propagate to the Ruby caller and roll back its operation. HTTP processing failures roll back first and return a generic server error; exception text is not returned.

## Request correlation extension

An optional `nonce` on the Backchannel Authentication Request is persisted and copied into the signed ID Token, matching node-oidc-provider v9.12.2. This is additional implementation support, not a mandatory CIBA Core request parameter or a new Discovery field. If supplied, it must be a nonempty valid string of at most 1024 bytes; that bound is a gem policy. Omission produces no nonce claim. The saved snapshot exposes it to the trusted application, but observation events omit it. A Token Endpoint nonce cannot overwrite the saved value. This value does not authenticate a customer or authorize completion.

Existing development databases require the explicit nullable-column migration described in [operations](operations.md) before running the updated code. New schemas already include the column. Old requests with a null nonce retain their original behavior.

## Saved consent and revocation

`ciba_grant(id)` reads a frozen consent snapshot. `revoke_ciba_grant(id)` serializes with issuance, marks consent revoked and sets upstream `revoked_at` on all OAuth grant rows linked to it. This link survives request cleanup. It prevents further CIBA issuance; it does not make an already distributed JWT disappear from an offline resource server. Use the upstream revocation/introspection and resource-server enforcement appropriate to the access-token format.

New consent defaults to 14 days, matching node-oidc-provider's Grant TTL. `ciba_grant_lifetime` configures the default in positive integer seconds (maximum 2^31-1). Omitting `expires_at` applies it; an explicit future timestamp overrides it and explicit nil retains the application's choice of no consent expiry. Convenience approval also uses the default. Existing rows keep their stored expiry, including nil; no schema migration or retroactive expiry is applied.

Consent expiry is checked at completion and token collection. Issued access tokens have their own expiry. Request cleanup does not delete consent records. The application owns consent retention; deleting a consent row cascades to its linked requests and issued OAuth rows, so deletion is a destructive action and is not used for ordinary request cleanup.

## Snapshots and recovery

`ciba_request(id)` returns a frozen hash with frozen strings; canonical column names are used even with custom columns. It excludes the public-ID digest. The stored status can remain pending/approved after expiry; always check `expires_at` when displaying it. Completion and polling check deadlines themselves.

```ruby
rodauth.pending_ciba_requests(after_id: nil, limit: 100)
rodauth.cleanup_ciba_requests(before: Time.now.to_i - 86_400, limit: 100)
```

Pending lookup returns unexpired pending requests sorted by internal ID, limit1..1000. For notification recovery, periodically restart scanning from the beginning and deduplicate deliveries in the app; do not permanently advance a cursor past undelivered requests.

Cleanup returns the deleted count. The cutoff must be an integer epoch second not in the future. It removes bounded batches of expired pending/approved rows, denied rows completed before cutoff, and consumed rows consumed before cutoff. It never deletes OAuth grants/tokens. No background worker or automatic migration is installed.

## Authentication Device initiation

Implement `trigger_ciba_authentication_device(snapshot)` to initiate your application’s authentication/approval flow. It runs synchronously after the request transaction/savepoint finishes and before the successful Backchannel response. The frozen snapshot contains the saved internal request ID and account/client references, not the public auth_req_id or its digest. The callback may enqueue work or call the Ruby result API. It must return normally to allow a success response; it must not perform a Rack halt/throw. Its default raises `CibaSupport::ConfigurationError`, reported as HTTP 500 `server_error`. A deliberate no-op is appropriate only if the application already processes pending requests independently (as the local demo does).

Dispatch should enqueue work promptly instead of waiting for customer interaction.
Its synchronous execution consumes the saved request lifetime; `expires_in` is not
reduced for this elapsed time. Both the gem and reference OP can acknowledge an
already expired request if dispatch outlasts its lifetime. See the
[measured timing contract](research/acknowledgement-time-contract.md).


A callback exception goes to `report_ciba_processing_error`, not the observer-error reporter. Without a surrounding application transaction, the saved request remains: notification may already have happened, so failure cannot safely undo external effects. The client does not receive an auth_req_id on that failed response. A client retry creates a new request; the app must deduplicate notifications and expire/recover abandoned requests. This is not durable delivery.

The callback is outside the gem’s request transaction, but it does not wait for an application-owned outer transaction. Do not wrap the HTTP route in a larger transaction if notification workers need committed state. For durable dispatch, save an outbox record in `after_ciba_request` and use the trigger only to wake your worker (or explicitly do nothing when a worker scans the outbox). The worker must read committed records and own delivery/retry policy.

This follows the persistence-before-trigger ordering in node-oidc-provider v9.12.2's CIBA route. Both the gem and complete reference OP harness now test a trigger exception leaving a pending request while initiation returns 500 without its identifier. Neither test establishes durable notification delivery.

## Hooks and events

Configure `before_ciba_request`, `after_ciba_request`, `before_ciba_approve`, `after_ciba_approve`, `before_ciba_deny`, `after_ciba_deny`, `before_ciba_issue`, `after_ciba_issue` using Rodauth's usual block configuration. They run in the state change's transaction/savepoint. Exceptions roll back. `ciba_current_request` is a frozen snapshot: before hooks see the previous state, after hooks see the resulting state; the before-request hook has no assigned database ID yet. Hooks must not perform a Rack halt/throw or send an HTTP response; signal failure by raising an exception.

Use a transactional after hook to persist required audit data or an outbox entry in the same database. Avoid external network calls there. After does not mean after commit.

`ciba_request_accepted(snapshot)` is retained as a legacy best-effort post-commit callback. Move required initiation logic to `trigger_ciba_authentication_device`; do not configure both to send the same notification. `observe_ciba_event(event)` receives post-commit events: `request_accepted`, `approved`, `denied`, `failed`, `token_issued`.

Events contain `version: 1`, `event_id`, internal `request_id`, `occurred_at` (epoch seconds), local `account_id`, local `oauth_application_id`, `type`, `from`, `to`. Tokens, raw hints, public auth_req_id, secrets and binding messages are excluded. Event hashes are frozen. Observer/legacy-callback failure is passed to `report_ciba_observer_error(error)`; failure of that reporter cannot change an already committed result. The default reporter writes only the exception class to stderr. Callbacks are best-effort, not durable delivery, and process death can lose an event.

## Collecting results and replay

See the [failure and retry contract](failure-contract.md) for confirmed rollback, ambiguous HTTP outcomes and external side effects.

An unexpired approved or denied result can be collected once. A negative result first returns its saved error code (`access_denied` for customer refusal) and becomes consumed; another collection returns `invalid_grant`. Replaying an unexpired consumed approved request revokes its saved consent and every OAuth token row linked to that consent before returning `invalid_grant`, following node-oidc-provider. This includes tokens from other requests if the same consent was reused. Expired requests return `expired_token` before replay handling. Ruby completion retries are separate from Token Endpoint collection and do not trigger replay revocation. Do not repeat a successful poll; after a lost token response, start a new authorization rather than treating polling as idempotent. Database revocation alone does not invalidate offline-verified JWTs.


CIBA dynamic registration accepts optional `token_endpoint_auth_signing_alg`
when it matches the JWT client authentication method and the OP's advertised
algorithms. Add its nullable String storage column (configurable with
`oauth_applications_token_endpoint_auth_signing_alg_column`) before accepting
this metadata. The registered value restricts subsequent client assertions;
it is separate from `backchannel_authentication_request_signing_alg`.


### Remote certificates for self-signed mTLS clients

With `jwks_uri`, certificate `x5c` values are fetched through the guarded CIBA
HTTP transport and cached by upstream HTTP cache policy. A certificate mismatch
does not force a refetch. Publish overlapping keys/certificates as needed and
account for cache lifetime during rotation. After cache expiry, retrieval or
malformed-JWKS failure returns `invalid_client_metadata`; an empty key set or
nonmatching certificate returns `invalid_client`. The gem does not fall back to
expired cached keys after retrieval failure. See the [measured reference
boundary](research/mtls-reference-contract.md#remote-x5c-rotation-and-retrieval-failures).

### Hint and display policy communicated to clients

Publish the accepted hint formats and, where relevant, trusted issuers and
maximum ages as part of the deployment's client integration contract. The gem's
resolver methods do not communicate that policy automatically. `login_hint`
can be an application-defined reference rather than an email address.
Applications and clients also own safe display of binding_message and actual
user correlation across AD/CD. A stored message or callback does not prove that
the user saw it or approved the intended action.

### Explicit pre-interaction policy denial

An application authentication-request callback may call
`ciba_error("access_denied", 403)` to reject a start request before device dispatch.
For example, a login-hint resolver can reject a client/account combination by
policy. Do not use this for an unavailable policy service; unexpected failures
remain server_error. `CibaSupport::ProtocolError` uses HTTP400 by default, so
raising that error with access_denied does not choose HTTP403 automatically.
After a request exists, use the completion denial API instead; poll then returns
the normal token error response. The pinned reference likewise needs an explicit
HTTP403 application error; its default AccessDenied maps to HTTP400.
The supplied callback fixture proves the response and absence of persistence,
not the correctness of a deployment's access policy.

The JWT assertion-type URN belongs in the `client_assertion_type` request field.
Register `private_key_jwt` or `client_secret_jwt` as the authentication method;
CIBA registration rejects the URN as a method. Shared OAuth/OIDC Discovery
removes this upstream legacy advertisement while retaining all actual method
names. Upstream authentication dispatch for other OP flows is unchanged.

## Edwards client assertion authentication

Enable `oauth_jwt_bearer_grant` and configure, for example,
`ciba_client_assertion_signing_algorithms %w[RS256 Ed25519 EdDSA]`. The default
`nil` keeps existing registration defaults. An explicit list governs CIBA client
assertions, including other grant flows for those CIBA clients. Register Edwards
clients with `private_key_jwt`, a matching `token_endpoint_auth_signing_alg`, and
a public OKP/Ed25519 JWK. No Edwards OP signing key is needed.

Shared OAuth/OIDC authentication metadata retains upstream capabilities and adds
this list. This does not install Edwards signing/verification globally in
ruby-jwt or enable Edwards ID Token issuance. Non-CIBA-only clients continue to
use upstream authentication. See the
[implementation and evidence](research/client-assertion-algorithm-contract.md#initial-edwards-authentication-implementation).

## Edwards CIBA ID Tokens

`ciba_id_token_signing_keys({"Ed25519" => private_key, "EdDSA" => private_key})`
adds explicit CIBA ID Token signing keys without changing the OP's default key
configuration or JWT access-token signing. Register a matching
`id_token_signed_response_alg`. An array value uses its first private key for
new signatures and retains remaining keys for hint verification; only public
keys are exposed through JWKS. Default is `{}`.

[Configuration and current limits](id-token-hint.md#explicit-edwards-id-token-keys)
include optional [recipient encryption](id-token-encryption.md) when
`ciba_id_token_encryption_enabled true` is configured.

For CIBA HS256/HS384/HS512 ID Tokens, signing and hint verification now use the
client secret. Successful Basic/POST authentication supplies it within the
request even when the DB stores a hash. Other methods can use plaintext storage
or `ciba_id_token_hmac_secret(oauth_application:)` to retrieve the original secret
from application-managed storage. Missing/short keys fail with rollback; OP keys
are never substituted. See [the HMAC contract](id-token-hint.md#hmac-client-secret-ownership).

Authentication results are stored separately from their ID Token disclosure. See [authentication claim selection and migration](authentication-claims.md) for require_auth_time, explicit claims, scope configuration and the required authentication_claims storage.

The device request snapshot includes saved `max_age` (nil, zero for fresh login, or seconds). See [maximum authentication age](max-age.md) for request/default precedence, signed-input isolation and the required request-column migration.

CIBA DPoP binds proofs to the reached endpoint through `ciba_dpop_endpoint_uri`. Its default ignores forwarding headers; trusted-proxy applications may supply their validated external URL. See [alias and proxy trust](research/dpop-reference-contract.md#alternate-endpoint-origin-and-proxy-trust).
