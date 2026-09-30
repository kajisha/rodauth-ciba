# Ping delivery boundary

2026-09-30. Reference: released node-oidc-provider 9.12.2, Node24.21.0,
complete HTTP OP plus a real HTTPS notification receiver. The gem now supports
optional [ping](../ping.md) as well as poll; the following evidence defined the
implementation boundary and still records remaining review criteria.

## Measured behavior

[Test](../../test/reference/full-op/ping.mjs),
[full reference log](../validation/node-full-op-lts.txt).

| Scenario | Reference outcome |
|---|---|
| Missing notification token, spaces in token, >1024 characters | invalid_request |
| Accepted request before completion | No notification; token request returns authorization_pending |
| Approval | Save result, then POST notification; token retrieval remains a separate authenticated request |
| Denial | Same notification shape, followed by access_denied at token endpoint |
| Notification contents | Bearer client_notification_token; application/json with only auth_req_id |
| Receiver returns 200 or 204 | Delivery succeeds |
| Receiver returns 503 | Completion call raises; saved grant binding remains |
| Receiver returns 302 | Completion call raises; redirect is not followed |
| Delivery retry | Client.backchannelPing(savedRequest) sends explicitly without recompleting approval |
| Token retrieval after failed delivery and explicit retry | Succeeds from the saved result |
| Loopback notification destination under default transport | Rejected by special-use-IP protection before receiver obtains the HTTP request |

`Provider.backchannelResult` saves before calling `Client.backchannelPing`.
The sender accepts 200/204, uses manual redirects and has no built-in durable
retry queue. Source sets a 2500ms fetch timeout; delayed-network timeout behavior
was not measured here. The default transport checks the connected socket's IP
against special-use ranges, rather than relying only on registration syntax.

The harness first proves loopback rejection. It then allows exactly its owned
HTTPS endpoint through a test-only fetch override, retaining certificate
verification, timeout and redirect policy. A temporary self-signed test CA is
trusted only by the test process. The override is not production configuration
or evidence of delivery to a publicly routed endpoint.

## Protocol requirements

[CIBA Core sections 4, 7.1, 9 and 10.2](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)
define registered ping mode and an HTTPS client notification endpoint, the
request's client_notification_token, and notification using that bearer token
with the auth_req_id. The client subsequently authenticates at the token
endpoint. Notification does not deliver access or ID tokens.

## Gem implementation boundary

1. Opt-in ping alongside default poll; explicit client-metadata/storage migration
   and accurate Discovery. Preserve existing poll clients and pending requests.
2. Validate the registered endpoint and bearer-token syntax/size before request
   persistence. Registered destinations need network-level protection, not just
   an HTTPS prefix check. Do not follow redirects or use request-supplied URLs.
3. Persist sufficient private delivery data. Current requests store only a hash
   of auth_req_id, which cannot produce the notification body. Both the original
   ID and notification credential must survive completion by another worker.
   Exclude these from all public request APIs, hook snapshots and observations;
   define cleanup/retention and any storage-protection requirements explicitly.
4. Save approval/denial transactionally, send only after the outermost commit,
   and leave that result intact on delivery failure. Retain the agreed Rodauth
   rollback behavior for before/after state-change hooks. Network delivery must
   not occur while holding the request's DB transaction/row lock.
5. Provide explicit notification retry, separate from completion; do not add an
   automatic queue or claim exactly-once delivery. A delivery failure does not
   invalidate a saved approval. Handle response loss, duplicate notification,
   expired/consumed requests and concurrent retry explicitly in tests/docs.
6. Keep token issuance/replay revocation and customer/client binding unchanged.
   Test full acceptance, approval, denial, delivery and token collection using
   an independent TLS receiver and the installed gem, including failure cases.

The initial comparison found the gem's registered remote-JWKS helper lacked
node's special-use-IP guard. The [dedicated CIBA transport](../outbound-http.md)
now checks DNS answers and pins a validated address; its limits and different
policy are documented. Unrelated OP HTTP routes remain unchanged. This closes
part of the transport gap, not ping delivery itself.

The research increment itself did not implement ping. The subsequent optional
implementation adds private delivery storage, after-commit notification and
explicit retry. Production egress policy and concurrent delivery remain review
work; the feature documentation records credential retention and failure behavior.

## Ignored response body parity

The shared HTTP transport previously read up to65,536 bytes even for ping,
turning a valid200 acknowledgement with a larger ignored body into a delivery
failure. Node's notification method checks status without consuming the body.
The gem now requests headers-only handling for ping and closes its Net::HTTP
connection through the normal start/ensure cleanup. It does not follow redirects
or disable certificate/address validation. Key and sector fetches still read and
bound their bodies.

The real TCP test sends200 headers declaring10MB and never sends a body, then
observes peer closure; this proves the Ruby path does not implicitly drain.
Both installed gem and pinned Node TLS fixtures now send140,000 bytes on200 and
pass. [Local12 tests /113 assertions](../validation/ping-response-body-current.txt),
[installed artifact](../validation/ping-response-body-installed.txt),
[reference TLS](../validation/node-ping-response-body.txt).
The artifact also reruns oversized sector/JWKS rejection and untrusted TLS
scenarios, so the ping exception does not remove their protections.

## Initial management-update comparison (superseded below)

The gem snapshots the endpoint at request acceptance and checks current client
metadata before each dispatch. A deterministic barrier test now performs actual
registration-management PUT requests while completion's sender is paused. Both
endpoint replacement and switching to poll preserve the already approved result;
a subsequent retry raises Ineligible without sending, token collection succeeds
once, and replay is rejected. The in-flight sender retains only the original
endpoint and notification credential and runs outside a database transaction.
This is not atomic cancellation of a network operation.

Source comparison: provider9.12.2's `Client.backchannelPing` in
`lib/models/client.js` takes its destination from the Client instance on which it
is invoked, and the credential from the saved authentication request. It has no
comparison with an acceptance-time endpoint in that method. Consequently the
gem's snapshot check is a deliberate stricter credential-routing policy, not a
claim of identical management-update semantics. The real HTTP management race is now measured below.

[Gem barrier test](../../test/ciba_ping_test.rb),
[local execution](../validation/ping-management-current.txt).

[Three-database execution](../validation/ping-management-matrix.txt): three tests,
42 assertions per database, no failures/errors/skips.

### Reference HTTP management race

[Execution](../validation/node-ping-management.txt) uses provider9.12.2 with
actual authenticated registration and management PUT, and the existing verified
TLS receiver. A promise barrier pauses completion at the configured fetch
transport before the network request. The management update completes before
the barrier is released; no timing sleeps determine ordering.

| Update while completion is dispatching | Reference result | Gem result |
|---|---|---|
| Replace notification endpoint | In-flight send uses original endpoint; retry on a freshly loaded Client sends the saved bearer credential and request ID to the replacement endpoint | In-flight send uses original endpoint; subsequent retry raises Ineligible |
| Switch ping to poll | In-flight send uses original endpoint; retry on fresh Client raises TypeError without sending | In-flight send uses original endpoint; subsequent retry raises Ineligible without sending |
| Collect completed result after either update | First token request succeeds; repeated request returns invalid_grant | Same |

This establishes a concrete remaining policy difference, not failed CIBA token
issuance or unknown behavior. Matching the reference on endpoint replacement
would require changing the gem's acceptance-time destination binding and its
documented credential-routing guarantee. It has not been silently relaxed.
The current test does not establish cancellation, distributed-client cache
coherence, or every possible ordering of management and dispatch.

### Alignment correction: current registered destination

The earlier snapshot restriction was an extra gem policy, not a requirement
established by the reference. To follow the requested reference design,
`retry_ciba_ping` now reads the current eligible client's registered endpoint
when constructing each outgoing request. The saved endpoint column is retained
for schema compatibility but no longer controls routing. This replaces the
gem outcomes in the endpoint-replacement row above: subsequent retries now
reach the replacement endpoint with the saved credential, as the reference does.

Mode changes to poll still reject retries. Existing sends retain their selected
endpoint; result persistence and single token collection are unchanged. HTTPS
metadata validation, DNS/IP filtering, verified TLS and redirect rejection remain
active. Registration-management authority includes authority to receive pending
notification credentials at a replacement endpoint, matching the reference.

The updated tests first reproduced the old Ineligible failures
([red](../validation/ping-current-endpoint-red.txt)).
All ping tests then passed on three databases
([execution](../validation/ping-current-endpoint-matrix.txt)).
