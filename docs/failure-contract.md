# Failure, retry and external effects

Accepted policy: [ADR 0004](adr/0004-retain-atomic-issuance-and-stage-alignment.md). This contract describes current behavior, not proof that a particular deployment handles every failure. It intentionally retains same-database atomic issuance while aligning the successful and replay paths with node-oidc-provider.

## Client recovery

| Observed outcome | State and recovery |
|---|---|
| `authorization_pending` | Continue polling within the request lifetime, respecting the advertised interval. |
| `slow_down` | Increase the polling interval as instructed; do not immediately retry. |
| Issuance failure with rollback confirmed by trusted server-side inspection | Participating token writes and consumption roll back. Retry is possible only while the request, account, client and consent remain eligible. Use a fresh client assertion if JWT client authentication is used. |
| Timeout, disconnected connection, generic 500 or 503 | The response alone does not prove rollback. `Retry-After` is a timing constraint, not an idempotency guarantee. If the client cannot establish the outcome through application-owned recovery, start a new CIBA request rather than blindly replaying collection. |
| Successful issuance committed, response lost | Tokens may already exist. Start a new authorization; there is no token-response replay cache. Recovery/revocation of an uncertain earlier issuance is an application responsibility. |
| Unexpired, already collected approved request is polled again | Revoke its saved consent and linked token rows, then return `invalid_grant`. Reusing consent across requests extends this revocation to those linked tokens. |
| Negative completion | First collection consumes the result and returns its saved error code (`access_denied` for customer refusal); another collection returns `invalid_grant`. It cannot become a successful issuance through retry. |
| Request expired | Return `expired_token` before replay handling. An expired replay does not execute the replay-triggered revocation path. |

Database revocation does not by itself invalidate a JWT verified offline by a resource server. Trusted Ruby completion retries are separate from Token Endpoint polling; their idempotent behavior does not make token collection idempotent. A new request may notify the customer again and requires its own valid completion.

## Transaction and delivery boundaries

Request consumption and token writes participate in the same DB transaction. Signing and before/after hooks execute within that boundary, but only participating DB writes can be rolled back. A remote signer, HTTP notification or other external action may have completed before an exception or process failure. The gem does not automatically retry hooks.

For required audit records or durable dispatch, write to the same DB from a transactional hook. An application-owned outbox worker can deliver committed records with its own retry and deduplication policy. Do not interpret an `after` hook as after commit. Observers run after the outermost commit and their failures do not change the result; they are best-effort and can be lost on process death.

The authentication-device trigger runs after saving the request and before the successful initiation response. Without an application-owned outer transaction, a trigger exception leaves the saved request; notification may already have happened, while the client did not receive its identifier. Retrying initiation creates a new request. The application owns notification deduplication and abandoned-request cleanup. A trigger inside an application-owned outer transaction does not wait for its commit: use committed outbox records when workers require visibility.

Never send a successful response before an enclosing transaction commits. A savepoint cannot make consumption durable independently of an outer rollback. JWT client-assertion consumption normally precedes the CIBA transaction, so a failed CIBA operation can still consume the assertion; generate a fresh one on retry.

## Evidence and remaining validation

The latest SQLite/PostgreSQL/MySQL matrix covers signing-failure rollback and retry, outer rollback, hook exceptions, savepoint-aware observers, device-trigger failure, replay revocation and client isolation. See the [DB log](validation/db-matrix-latest.txt) and [alignment status](node-alignment.md). In addition to the isolated handler harness, the [complete node OP test](../test/reference/full-op/README.md) verifies HTTP behavior with real signing and its built-in nontransactional memory adapter.

Before deployment, test the actual client's response-loss recovery and any external signer/notification side effects under faults. The latest DB matrix, Ruby3.3/3.4 SQLite matrix and the documented complete-OP lifecycle scenarios have passed. Process-crash recovery and production node adapters remain outside that evidence.
