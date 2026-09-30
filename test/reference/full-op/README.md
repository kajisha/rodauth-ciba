# Full reference OP lifecycle

This harness installs the published `oidc-provider` **9.12.2**, starts its complete HTTP application on an ephemeral loopback port, and uses its built-in memory adapter. No provider modules, token generation, revocation, authentication middleware or cryptography are stubbed. Application-owned hint resolution, account claims and device dispatch are supplied; no browser or real notification delivery is involved.

```sh
cd test/reference/full-op
npm ci --ignore-scripts --no-audit --no-fund
npm test
```

Use a supported Node LTS release and OpenSSL for temporary test certificates. Node26.5.0 also passed but emits an unsupported-runtime warning; do not treat that as supported-runtime evidence. `package-lock.json` fixes dependency versions and integrity. The test has no production credentials, binds only loopback and closes its listeners in `finally`.

The passing LTS run used the official `node:24-bookworm-slim` image at digest `sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6`, with this directory mounted read-only at `/app`. After installing dependencies, reproduce from this directory:

```sh
tls_dir=$(mktemp -d "$PWD/node_modules/.ping-tls.XXXXXX")
trap 'rm -rf "$tls_dir"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$tls_dir/key.pem" -out "$tls_dir/cert.pem" \
  -subj /CN=localhost -addext subjectAltName=IP:127.0.0.1,DNS:localhost
docker run --rm --network none --mount "type=bind,src=$PWD,dst=/app,readonly" \
  --env "CIBA_TEST_TLS_DIRECTORY=/app/node_modules/$(basename "$tls_dir")" \
  --env "NODE_EXTRA_CA_CERTS=/app/node_modules/$(basename "$tls_dir")/cert.pem" \
  --workdir /app node:24-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6 \
  sh -c 'node --version && npm test'
```

## Compared outcomes

`mtls.mjs` has a separate real-TLS runner, `mise exec ruby -- sh bin/test-mtls-reference`
(from the repository root). It generates temporary client/server certificates
and checks both TLS authentication methods and certificate-bound UserInfo.
See the [measured mTLS contract](../../../docs/research/mtls-reference-contract.md).

`assertion-refresh.mjs` exercises both `private_key_jwt` and `client_secret_jwt`
through CIBA initiation, token collection and refresh using the issuer audience.
It also checks wrong audiences and assertion replay against the actual OP.

`dpop.mjs` measures CIBA proof-required polling, bound opaque access tokens,
UserInfo key/ath checks, and confidential refresh with a new proof key. It uses
real ES256 proofs, first without nonce support and then with required and optional
nonces. It checks challenge/retry, old iat with a valid nonce, cross-endpoint nonce
use, and proof replay rejection. See the
[DPoP contract and Ruby integration gaps](../../../docs/research/dpop-reference-contract.md).

`registration.mjs` exercises authenticated dynamic CIBA registration, invalid
metadata, and use of generated poll-client credentials through approval and token
issuance. See the [registration contract](../../../docs/research/registration-reference-contract.md).
It runs without the TLS fixture required by the separate ping test.

The [refresh contract](../../../docs/research/refresh-reference-contract.md)
covers default issuance gates, scope and resource selection, stored authentication
context, age-based rotation, client isolation and replay revocation. Rotation and
expiry use persisted model timestamps to avoid waiting for production lifetimes;
token requests and introspection still use the real HTTP handlers. The gem now
implements optional refresh support; see [its contract](../../../docs/refresh-tokens.md).

`npm test` also runs [ping.mjs](ping.mjs). This uses a real HTTPS receiver,
proves the default SSRF guard rejects loopback, then makes a test-only exception
for exactly that receiver while retaining TLS validation. See the
[ping contract](../../../docs/research/ping-reference-contract.md) for result
persistence, explicit retry and no-redirect evidence. Node slim lacks OpenSSL,
so the Docker command generates temporary certificates on the host first.

The [signed-request contract](../../../docs/research/signed-request-reference-contract.md)
uses a separately registered RSA client and explicitly enables requestObjects.
It covers client authentication separately from request signatures, required
claims, parameter isolation, new approval/issuance, expiry representations and
the reference's default acceptance of repeated jti values. The gem now has an
optional implementation; see its documented validation differences and gaps.

The [resource contract](../../../docs/research/resource-reference-contract.md) additionally covers repeated resource parameters, per-resource consent, signed access-token audience/scope, ID Token audience separation, unrequested targets and the default omission policy. Resource servers are a fixed in-process registry; no real resource server is contacted.

The harness explicitly enables optional claimsParameter and declares email/email_verified support. The [claims contract](../../../docs/research/claims-reference-contract.md) records five consent/target combinations, poll-parameter tampering and malformed JSON rejection, using signed ID Tokens and HTTP UserInfo responses. The gem now implements optional explicit claims; see the current [alignment audit](../../../docs/alignment-roadmap.md) for remaining policy boundaries.

| Scenario | Complete node OP with built-in memory adapter | Gem evidence |
|---|---|---|
| Repeated pending poll | Both return `authorization_pending` | Advertises interval and returns `slow_down` for early repeat (`test_pending_poll_updates_survive_json_halt`) |
| Denial | `access_denied`, then `invalid_grant` | Same (`test_denied_result_is_consumed_on_first_collection`) |
| Generic error completion | Application-supplied transaction_failed or authorization_pending is consumed once, then invalid_grant | Rejects those completion inputs without mutation; the poll profile derives pending/expiry from state. See [analysis](../../../docs/research/completion-error-boundaries.md). |
| Device dispatch throws | 500 without auth_req_id, saved pending request survives | Same (`test_device_failure_is_not_an_observer_failure_or_success_response`) |
| Approval and issuance | Saved Grant/result API, signed ID Token; signature, subject, audience, issuer and expiry checked | Full upstream Rack stack and real signing (`test_approved_request_issues_customer_id_token_once`); installed-gem HTTP smoke test |
| Nonce extension | Start-request nonce survives in the verified ID Token despite a different nonce on poll | Same; optional, omitted from observer events, and carried by a migrated nullable request column |
| Wrong client | `invalid_grant`, original Grant remains usable | `test_another_client_cannot_revoke_consent_by_replaying_a_request_id` |
| Replay after success | `invalid_grant`, stored Grant and access token removed | Saved consent and linked token rows revoked (`test_replayed_result_revokes_its_saved_consent_and_tokens`) |
| Expiry | Requested one-second lifetime expires before collection | Expiry tests, including precedence over consumed state |
| Issuance exception | Injected account-claims failure during ID Token generation returns 500; request stays consumed; retry revokes Grant | Injected signing failure rolls back consumption and token row; retry succeeds (`test_signing_failure_rolls_back_consumption_and_grant_then_allows_retry`) |

The injected failures occur at different steps, both inside issuance; this is not a same-instruction crash simulation. The retained difference is intentional under [ADR 0004](../../../docs/adr/0004-retain-atomic-issuance-and-stage-alignment.md). The node result applies to its built-in nontransactional adapter, not every deployment adapter.

Gem scenarios run through the actual upstream Rack application against three DBs; most use Rack mock HTTP requests rather than TCP. The installed-gem smoke test additionally uses TCP. The node harness uses TCP for all protocol requests and its public internal API for completion. These are compared scenarios, not an identical cross-provider client or a conformance suite.

Logs: [DB matrix](../../../docs/validation/db-matrix-latest.txt), [Node26 diagnostic run](../../../docs/validation/node-full-op.txt), [Node LTS run](../../../docs/validation/node-full-op-lts.txt). Actual external side-effect recovery, response-loss recovery, process crashes and durable/multi-process node adapters remain untested.


`registration-remote.mjs` adds real HTTP JWKS retrieval with dynamically
registered private_key_jwt clients. It verifies default loopback refusal, then
uses a test-only fetch exception for exactly two owned fixture URLs to compare
fresh max-age cache reuse, same-URL key replacement without unknown-kid refresh,
and management PUT changing the URL. It runs with `node registration-remote.mjs`
and is included in `npm test`. No production client keys or external servers are
used. Expiry timing and multi-process caches are not covered.
