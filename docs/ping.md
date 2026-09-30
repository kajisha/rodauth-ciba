# Optional ping delivery

Run the explicit migration and enable the capability:

```ruby
Rodauth::CibaSupport::Schema.add_ping(db)
# Rodauth configuration:
ciba_ping_enabled true
```

Register each ping client with backchannel_token_delivery_mode = ping and an
HTTPS backchannel_client_notification_endpoint. Poll clients remain supported.
Discovery advertises poll/ping only while enabled. The migration adds the client
endpoint column and a separate ciba_ping_deliveries table, leaving existing
requests and grants intact. Custom migration keywords: applications_table,
endpoint_column, table, requests_table, request_key. Configure the corresponding
Rodauth endpoint-column and ciba_ping_deliveries_table settings when renamed.

The initiation request must provide a nonempty client_notification_token using
Bearer token characters, at most 1024 bytes. Entropy is the client's responsibility.
Clients must generate at least128 bits of entropy (160 is recommended). The gem
validates syntax/length, not the randomness of a supplied token. The application
should verify that the registered notification endpoint is controlled by the
client; HTTPS validation and destination filtering alone do not prove ownership.
The receiving client must check the notification bearer and its association
with auth_req_id before collecting tokens. An OP-side send test does not prove
that receiver behavior. See [CIBA Core §§7.1,10.2,14](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html).
Poll ignores this parameter. Signed requests use only its signed inner value.
Invalid metadata, userinfo/fragments or non-HTTPS endpoints cannot enable a ping
client. Network destination checks apply at send time using the
[CIBA HTTP boundary](outbound-http.md), which rejects special-use destinations
by default. There are no redirects, ambient proxies or automatic retries.

## Persistence and API behavior

The private delivery table stores request_id, original auth_req_id, the
notification token and the registered endpoint at acceptance. The endpoint column
is retained as acceptance-time data for schema compatibility; dispatch uses the
current client registration, not that saved endpoint. Unlike the
request table's hashed identifier, the original identifier is needed to send
the notification. These fields are recoverable plaintext database values;
protect access/backups and apply deployment encryption controls as appropriate.
They are excluded from public request APIs, state-change hook snapshots, device
snapshots and observation events. The normal request cleanup cascades deletion
to delivery data. Credentials remain until request cleanup, including after
successful delivery/collection, to avoid inventing a separate retention system.

Approval/denial commits before notification. An outer application transaction
delays notification until its outermost commit; rollback sends nothing. A
successful send returns normally from completion. Network/non-200-or-204 errors
raise PingDeliveryError **after** approval/denial is saved. If completion happens
inside an outer transaction, that error arises from the outer commit. It does
not mean the result rolled back. Observers remain independent best-effort hooks;
notification failures are not suppressed as observation failures.

`retry_ciba_ping(request_id)` sends separately from completion and returns
`:delivered` or `:not_deliverable` for pending, consumed, expired or non-ping
requests. Unknown IDs raise NotFound. It refuses execution inside a transaction.
Each send uses the client's current registered HTTPS notification endpoint,
matching node-oidc-provider's freshly loaded Client behavior. An authenticated
registration-management update can therefore redirect subsequent notifications,
including their saved notification credential, to the replacement endpoint.
A client that no longer supports ping or has invalid metadata raises Ineligible.
A request already constructed for dispatch keeps its selected endpoint even if
management updates the registration during delivery; updates do not cancel
in-flight network operations. Repeated identical completion retains the
existing idempotent completion behavior; use the retry API to resend.

Delivery is a POST with Bearer authentication and a JSON body containing only
auth_req_id. Approval and denial have the same notification shape. The client
authenticates separately to obtain tokens or the denial result. Failure to
deliver does not prevent retrieval of an already saved result.

There is no durable automatic retry scheduler or exactly-once claim. An
application may schedule explicit retries. Concurrent retries can send duplicate
notifications, and a result can be consumed/expire while a send is in flight.
The receiver must deduplicate notifications by identifier before collecting
tokens; fetching twice would trigger replay revocation. Process death after
commit and before send is another reason to use application-managed retries.

## Evidence and remaining work

Integration tests cover approval/denial, exact payload, private snapshots,
post-commit delivery, rollback, failed-send persistence, retry, expiry, metadata,
endpoint changes and cascading cleanup. The installed-gem ping smoke uses a
real HTTPS receiver with a temporary CA and an exact loopback policy exception;
TLS verification stays enabled. It tests 200/204, 503/302, a stalled response,
retry and collection. A separate process without trust in the test CA rejects
TLS before credentials reach the receiver while retaining the saved result.
The independent [node comparison](research/ping-reference-contract.md) establishes
the reference save-before-send behavior.

Barrier-based tests hold automatic delivery open while another DB connection
collects tokens, and hold two explicit retries open during collection. There is
no active DB transaction in the send callback; one token issuance occurs, both
in-flight notifications may finish, and subsequent retry is not_deliverable.
A duplicate token collection still revokes the grant. Signed requests with
user_code use the signed notification token only, ignoring outer replacements.

Process-crash recovery, multi-process delivery, hostname-mismatch/expired TLS
certificates and every feature combination remain unverified. These scenarios
do not establish full node parity or certification.

### Notification response bodies

A200 or204 status acknowledges delivery. The gem closes the response connection
without reading its body, so an ignored body cannot fail delivery because of its
size or a body-read timeout. TLS verification, endpoint/address validation,
redirect rejection and the header-receipt timeout remain enforced. Other HTTP
consumers (JWKS and sector documents) retain their bounded body reads.

[Protocol/transport tests](validation/ping-response-body-current.txt) include a
response declaring10MB but sending no body: the sender returns after headers
and the peer observes closure. The [installed TLS fixture](validation/ping-response-body-installed.txt)
and [reference TLS fixture](validation/node-ping-response-body.txt) both accept
a200 response containing140,000 ignored bytes. Response-header stalls and failed
statuses remain separate failures; successful headers do not require a complete
response body.
