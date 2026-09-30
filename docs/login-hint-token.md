# Optional login_hint_token

The default profile continues to accept `login_hint`. Enable `login_hint_token` explicitly and supply an application resolver in the same configuration block:

```ruby
ciba_login_hint_token_enabled true
resolve_ciba_login_hint_token do |token, oauth_application:|
  # Your service validates the token and returns its local account ID or nil.
  HintService.resolve(token, client_id: oauth_application[:client_id])
end
```

`HintService` is an application example, not a class supplied by the gem. The resolver is required at configuration time when enabled. It receives the already-authenticated OAuth client. Like node-oidc-provider's `processLoginHintToken`, this API does not mandate a token format. It can accept an opaque reference or an application-defined signed token. The application owns authenticity, permitted issuer/audience/client, expiry, replay rules where needed and mapping to the OP's local account. For JWT formats, use appropriate signature/claim validation with trusted keys; decoding alone is not identity verification.

The Backchannel Authentication Endpoint requires exactly one supplied `login_hint`, enabled `login_hint_token`, or enabled `id_token_hint`. Empty, non-string, multiple or oversized hints return invalid_request. The token limit is 8,192 bytes, also bounded by the total form-body limit; ordinary login_hint remains limited to 1,024 bytes. This capability adds no custom Discovery field and needs no DB migration.

Return nil for a token that does not identify an eligible local account; the response is unknown_user_id. The gem also checks the resulting account is active. Resolver exceptions use the existing server-error boundary and do not create a request. Configuration does not replace the existing `resolve_ciba_login_hint`, which remains required for the default mechanism.

For an expired token, raise `Rodauth::CibaSupport::ProtocolError,
"expired_login_hint_token"` to return the corresponding HTTP400 response.
Other unexpected resolver failures produce HTTP500 rather than claiming that
the customer is unknown. The application must document accepted token formats,
issuers and age policy for its clients. Signature policy, single-use references
and discovery-service encrypted tokens are application implementations, not
built-in token formats provided by this gem.

After successful resolution, only the account binding enters the stored request. The raw token is removed before request hooks, persistence, device callbacks and observation events. The incoming Rack request necessarily still contains the submitted parameter; application/request logging must apply its own filtering. The reference OP retains raw hint parameters in its asynchronous request; discarding the value is this gem's deliberate storage adaptation.

Approval and saved-consent account/client checks remain unchanged. Token-endpoint parameters cannot re-resolve or replace the subject. Disabling this hint mechanism prevents new hint-token requests but does not invalidate already-resolved pending requests: those continue using their saved identity and ordinary completion/expiry/revocation checks.

## Evidence and scope

`test/ciba_hint_token_test.rb` verifies opt-in/resolver requirements, invalid shapes/size, mixed hints, client-aware resolver behavior, active-account and approval identity checks, raw-token exclusion from DB/snapshots/events, poll tampering and completion after deactivation. The complete node HTTP harness checks an application-defined opaque hint, client policy, mixed hints, unknown user and the signed ID Token subject. The installed-gem extension smoke now uses this mechanism with claims/resource/RAR.

These tests validate the protocol-to-application boundary, not an arbitrary production token format. The fixture resolver recognizes fixed local test references; it is not a reusable production verifier. [Signed authentication requests](signed-requests.md) and [ID Token hints](id-token-hint.md) have separate opt-in implementations and evidence.
