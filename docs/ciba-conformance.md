# CIBA Core conformance boundaries

This local change targets [CIBA Core 1.0 final](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0-final.html), not every optional OpenID/OAuth profile. Supported release scope is poll plus documented opt-in ping, signed requests, identity hints and user codes. Push is not implemented or advertised. Pairwise and CIBA dynamic registration remain experimental and disabled by default.

[Requirement ledger](ciba-core-requirements.json) separates mandatory, prohibited, recommended, conditional and optional requirements, as well as gem/upstream/application/client/deployment responsibilities. Its 159 inherited CIBA decomposition rows plus five OIDC conditional rows are an authored inventory, not an official denominator. Historical evidence is not promoted to a current conformance pass. Grouped tests support specific boundaries, not an exhaustive proof for each row.

## Design and changes

The backend additionally enforces requested public/pairwise subjects and essential ACR value conditions at approval, issuance and refresh. Issued projections retain ordinary value/values filters for both targets. Generic essential claim absence is allowed; voluntary ACR has its specific semantics. Mandatory nonce and final signed UserInfo claims cannot bypass filtering, and pairwise UserInfo retains its issuance subject. Positive integral JSON numbers are accepted for signed requested_expiry. See claims and operations for legacy-token migration limits.

1. Capture request receipt at entry to the backchannel POST handler, before client authentication, signed-request verification or hint resolution. Store created_at at that point and expires_at = created_at + chosen lifetime. This is the earliest protocol-handler timestamp, not a guarantee about time spent in a reverse proxy or Rack body parsing before the handler.
2. Keep expires_in equal to the selected positive lifetime, measured from that receipt point as specified in CIBA section7.3; do not reinterpret it as seconds remaining at response.
3. Do not add a new Backchannel error for slow processing. Section7.3 does not independently forbid acknowledgement after processing exhausts the lifetime; polling an expired source returns expired_token. The token endpoint503 provision is not a Backchannel authentication error permission. Applications must promptly enqueue AD work and clean up/reconcile abandoned requests; fixed expires_in is not guaranteed remaining lifetime on receipt of the response.
4. Save auth_time_required when client require_auth_time=true, max_age is selected, or claims.id_token.auth_time.essential=true. Reuse the existing approval/issuance/refresh guards. Null or essential=false requests remain voluntary. No fabricated timestamps or schema migration.
5. Continue delegating actual authentication and freshness to the application. max_age=0 requires fresh authentication; merely supplying an arbitrary timestamp is insufficient. The gem checks required context presence and requested essential ACR values; the truth of authentication and attribute evidence remains an application obligation.

Refresh stores the actual initial iss/sub/aud and disclosed auth_time in versioned
existing JSON storage, preserves the context through rotation, rejects old or
invalid contexts before mutation, and omits refresh nonce. See the
[migration contract](refresh-tokens.md#original-id-token-binding-and-migration).
This fifth conditional OIDC requirement is in the backend ledger
(164 total authored rows) even though
refresh/pairwise remain experimental. The latest local validation does not
establish the official suite or every optional combination.

## Requirement ownership and acceptance gates

| Area | Gem / upstream boundary | Application or deployment gate |
|---|---|---|
| Discovery and registration, section4 | Advertise only enabled modes/algorithms/flags; require configured confidential client, delivery mode and CIBA grant. Upstream owns ordinary OP metadata/authentication. | Stable HTTPS issuer/endpoints, approved client/key ownership. Experimental pairwise/DCR needs separate profile verification. |
| Request, sections7–7.2 | TLS/form/UTF8, one hint, openid, size/type checks, registered authentication, JWT verification, signed inner inputs, unknown parameters ignored. | Correct hint-to-account/tenant mapping; login_hint_token signature/issuer/profile validation; required hint retention policy. |
| Signed request, section7.1.1 | Asymmetric registered keys, mandatory claims, issuer/audience/date/type verification; client-auth JWT replay ledger is separate. | Client supplies unique request jti and no unsigned authentication parameters. The gem does not consume request-jti and does not claim request replay prevention. It creates new requests requiring new consent. |
| Binding/user code, sections7.1–7.1.2 | Optional metadata and bounded inputs, required validation callbacks, errors. | Display quality, user-code enrollment/change/password distinction, code verification/rate limit. Client never stores user code. |
| Acknowledgement, section7.3 | 256bit opaque ID, allowed alphabet, receipt-based lifetime, positive interval; processing never extends the deadline. | Proxy/queue delays before the handler, prompt dispatch and client expiry tracking. |
| Authentication/consent, section8 | Completion account/client/scope binding, trusted context types, transactional decisions. | Real AD authentication, consent UI, CSRF/authority checks, achieved acr, freshness and business policy before approval. |
| Token, sections10–11 | Client-bound source, current consent/openid/account/client checks, one-time issuance, locks/CAS/rollback, pending/slow_down+5/expiry/denied errors. | Same database, supported schema; RP does not overlap polls and obeys intervals. Outer transactions/overrides need integration tests. |
| Ping, sections9/10.2 | HTTPS POST after commit, auth_req_id-only body, Bearer notification token,200/204, no redirects; SSRF/DNS/TLS/size/time boundaries. | Client notification-token entropy and callback validation; endpoint administrative ownership; durable delivery/retry and logs. |
| ID Token, section10.1.1 / OIDC Core2 | Upstream core fields and signature plus RP audience, saved authcontext/nonce, required auth_time guard. | Valid signing setup, real authcontext, freshness and business policy. Push-only hash/id claims are not applicable. |
| Errors, sections11/13 | HTTP/JSON envelope, safe descriptions, client-auth401, policy403, token-state errors. | Custom callback error handling and log confidentiality. Optional error_uri absent; its output-specific restriction is not applicable. |
| Recommendations, sections14/15 | Optional hint validation and privacy-preserving persistence; protected outbound transport. | Reasonable expired-hint retention, notification ownership, privacy identifiers/retention, user matching and anti-abuse controls. |

The gem cannot certify an arbitrary consuming OP: several mandatory requirements explicitly need application authentication/consent and trusted deployment configuration. Referenced RFCs and OIDC Core bring their own requirements. DPoP/mTLS/resources/RAR tests cover documented extension boundaries, not all profile combinations.

## Regression evidence

The initial exploratory regression run on unmodified0.1.0 had5tests/4failures/0errors. One expectation rejected an expired acknowledgement; independent specification review showed that expectation added an unsupported503 and was removed. The retained regressions cover late receipt timestamp, approval without requested required auth_time, and issuance after authentication context was removed. The delayed-dispatch test checks that polling returns expired_token without extending the receipt-based deadline. Final test results are recorded in the delivery report.

The existing requirements timing test now expects the Core receipt-based policy rather than equality with node-oidc-provider9.12.2. The reference fixture still describes the reference's old measured behavior; that difference is deliberate and is not a conformance oracle.

The complete suite, installed-package verification and applicable platform coverage are reported with actual command results in the delivery report. Older checked-in validation logs apply to their recorded source snapshots only.

## Official conformance suite

The [OpenID Foundation suite](https://gitlab.com/openid/conformance-suite) is available for local or hosted testing; [testing is free](https://openid.net/certification/about-conformance-suite/), formal certification has a separate submission process. The published [CIBA OP testing instructions](https://openid.net/certification/fapi_ciba_op_testing/) address FAPI-CIBA: that profile imposes additional requirements and is not an automatic Core-only test result.

An executable OP deployment, suitable registered clients/keys, reachable TLS endpoints, and an AD flow capable of completing the suite's user scenarios are needed. Hosted testing additionally requires the suite to reach the OP; local suite setup depends on its Java/database/container runtime. No hosted account, client authorization configuration, public endpoint, credentials or certification submission is created by this change. No official suite run or certification is claimed.

Next acceptance gates: run a pinned official plan against an isolated complete OP/AD deployment, document any profile-specific extras, retain machine-readable results, and audit each enabled optional combination plus all application contracts. Full Core conformance remains unproven until those gates and the ledger's open responsibilities are verified.
