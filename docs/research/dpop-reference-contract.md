# CIBA DPoP integration: measured contract and open implementation

The complete node-oidc-provider 9.12.2 runs over loopback HTTP with a confidential
Basic client, `dpop_bound_access_tokens: true`, ES256 proof keys, poll delivery,
offline_access and refresh. The initial cases disable nonce challenges; later
providers exercise required and optional nonce policies. The
built-in memory adapter is used; no protocol or cryptographic code is stubbed.
[Harness](../../test/reference/full-op/dpop.mjs),
[initial static-client run](../validation/node-dpop-reference.txt).
The harness now creates its proof-required client through authenticated dynamic
registration and also exercises management replacement.
[Current registration run](../validation/node-dpop-registration.txt).

## Measured reference behavior

- Initiation needs client authentication but no DPoP proof. Poll without proof
  returns invalid_grant for this client. A valid proof before approval returns
  authorization_pending.
- A random nonempty jti is accepted. Wrong method, wrong target URI, old iat and
  empty jti produce invalid_dpop_proof without consuming the approved request.
- Successful issuance returns token_type DPoP and stores the proof's JWK
  thumbprint in the access token's jkt.
- UserInfo rejects bearer presentation of the bound token, another proof key,
  and incorrect ath. Matching key and access-token hash succeeds. Reusing the
  same proof jti is rejected with HTTP401.
- This confidential client's refresh token has no jkt. Refresh still needs a
  proof due to the client's policy, but a new key is accepted and binds the new
  access token. Reusing exactly the same refresh proof is rejected.

The distinction between access-token binding and confidential refresh-token
authentication is intentional in the measured code (`set_rt_bindings.js`). Do
not impose a fixed refresh key based solely on the access token's jkt. Public
clients are not part of this CIBA fixture. Nonces, DCR, JWT resource access
tokens, revocation, key changes during issuance, all URI-normalization cases,
and concurrent proof replays are not established by this run.

## Baseline Ruby integration gaps

Enabling upstream `oauth_dpop` alone is not CIBA DPoP support. A separate
characterization probe enables it in the actual gem Rack stack with the
upstream proof table and token thumbprint column:

```sh
mise exec ruby -- ruby test/ciba_dpop_test.rb
```

The probe confirms that a cryptographically valid random-jti proof is rejected
with invalid_dpop_proof / Invalid DPoP jti. The upstream claim validator requires
the SHA256 hex digest of method, full URL and iat instead of an arbitrary unique
identifier. With that custom identifier, a one-hour-old proof issues an access
token; the identical proof also issues a second independently approved request.
The upstream first-use table does not reject reuse within its configured window.
[Evidence](../validation/upstream-dpop-probe.txt): 1 characterization test,
13 assertions. That historical characterization probe has now been replaced
by the normal regression tests above; it is no longer an executable expectation
of defective behavior.

These observations do not show bypass of client authentication or customer
approval: both were valid in each request. They show why proof freshness and
replay guarantees must not be inferred from the advertised upstream feature.
The initial production correction is described below; this historical log does
not describe the corrected token endpoint.

## Initial CIBA token-endpoint correction

When upstream `oauth_dpop` is enabled, a prepended CIBA boundary now validates
proofs for the CIBA grant and this gem's refresh tokens. Other OAuth grant types
retain upstream behavior. It accepts nonempty random jti values, verifies the
embedded public key/signature and the configured asymmetric algorithm, rejects
critical extensions and private key material, and checks method, token URI and
iat within 300 seconds in either direction. Query/fragment are removed from the
proof URI before comparison. Limits are 8192 proof bytes and 1024 jti bytes.

Proof replay is claimed only when issuing a token, in the same DB transaction
as request consumption and token insertion. The existing explicit
`Schema.create_client_assertions` ledger is reused with a distinct `ciba_dpop`
digest namespace and client ID; no raw proof or jti is stored. Expiry extends
beyond the last accepted proof instant, so `cleanup_ciba_client_assertions`
cannot reopen replay within the validation window. The upstream token table
must have its configured `oauth_grants_dpop_jkt_column`; missing storage prevents
startup when the upstream feature is enabled. Ordinary upstream DPoP flows still
need their own upstream proof-table setup.

Pending polls do not reserve a proof. Simultaneous use across two approved
requests produces only one issuance; the losing request remains approved.
Signing failures roll back both consumption and replay insertion, permitting a
retry. This follows the accepted gem atomicity policy instead of node's
nontransactional failure consumption. A proof-required client without a proof
gets invalid_grant. Required proofs no longer implicitly enable nonce challenges;
`oauth_dpop_use_nonce` remains an explicit option.

Opaque and JWT confidential refresh accepts a new proof key and binds the new
access token to it. Reusing that proof fails without changing refresh state.
Seven local tests pass (90 assertions), including failure rollback, replay
concurrency, malformed/old proofs, URI handling and preservation of ordinary
grant validation. [Local log](../validation/ciba-dpop-current.txt).
The full three-DB suite passed 273 tests before the last malformed JOSE/signature
assertions; all seven final DPoP tests (90 assertions) then passed on each DB.
[Full run](../validation/ciba-dpop-matrix.txt), [final cases](../validation/ciba-dpop-final.txt).

This is **not full DPoP support**. External resource integration,
cleanup/retained-key combinations,
broader algorithm and URI normalization equivalence, and deployment tests still
need integration. The nonce extension below supersedes the unconditional
300-second iat restriction. Do not advertise a completed DPoP feature on this basis.

## CIBA UserInfo binding and replay

Upstream's UserInfo route calls `authorization_token` directly, bypassing
`require_oauth_authorization`. The extension therefore applies its proof checks
at that actual entry point for recognized CIBA credentials. Namespaced/legacy
opaque tokens and marked JWTs select this path; unverified JWT metadata is used
only to select stricter validation, never to authorize access. Signature,
expiry, client/subject provenance and a stored grant are still required.

A DPoP presentation must have a fresh, signed proof with the UserInfo method and
URI, matching ath, and a key thumbprint matching both the access-token claims
and the saved issuance row. Replay is claimed only after token and key checks.
Unknown tokens, wrong keys/hashes, forged JWTs, expired/revoked rows and bearer
presentation of bound tokens return HTTP401. Unbound CIBA Bearer Tokens continue
to work. Successful UserInfo proof claims commit before account-claim rendering;
a later application rendering failure requires a fresh proof on retry.

The upstream DPoP datasets append an OR for matching keys to the whole query.
That can admit revoked/expired rows, or rows not matching the presented token.
The CIBA UserInfo path rebuilds the predicates conjunctively: identity/token,
type, expiration, revocation and key binding must all match. Both the initial
lookup and UserInfo's later grant lookup retain those constraints. Other OAuth
flows are delegated unchanged; this is not a global upstream security repair.

The opaque/JWT tests verify concurrent proof reuse has one success and one401,
negative requests do not claim proofs, a known key cannot authorize an unknown
token, and expiration/revocation remain effective. Local DPoP tests pass
**9 tests / 135 assertions**. [Log](../validation/ciba-dpop-userinfo-current.txt).
Full Ruby4.0.6 suites pass **275 tests** on SQLite, PostgreSQL and MySQL
(SQLite skips two row-lock-specific tests).
[Three-DB log](../validation/ciba-dpop-userinfo-matrix.txt).
The original failure is retained in [this log](../validation/ciba-dpop-userinfo-red.txt).
The later POST/storage checks below extend this evidence. Pairwise combinations
and external resource-server enforcement remain to be exercised for this addition.

## Dynamic registration of proof-required clients

With `oauth_dpop` enabled, CIBA registration accepts only JSON booleans for
`dpop_bound_access_tokens`. Strings such as "true"/"false", numeric values,
arrays and objects are rejected before insertion. Supplying the property requires
a Boolean client column at `oauth_applications_dpop_bound_access_tokens_column`
(default `dpop_bound_access_tokens`); an absent storage column causes rejection.
Omission means false. When that column exists, the default is persisted as false;
when it is absent and the property is omitted, the implicit false needs no storage.

The returned registration credentials can initiate CIBA normally, but the token
endpoint rejects collection without a proof if the registered flag is true.
Valid proofs issue bound tokens. Invalid management PUT preserves both policy
and management credentials. A full replacement that omits the flag resets it to
false, including the management response; false must not disappear because of
upstream's truthy-only serializer. New token issuance can then omit the proof,
but already-issued bound tokens still require it at UserInfo.

With the upstream DPoP feature disabled, this metadata is ignored and is not
stored or echoed. Both reference and gem fixtures check this explicitly, even
when a similarly named DB column exists in the gem application.

The node harness performs DCR, CIBA issuance, UserInfo, confidential refresh and
management with the issued client. Gem tests additionally check missing storage,
no insertion for invalid values, whole-row preservation on failed updates and
retention of the old token's binding. [Reference](../validation/node-dpop-registration.txt),
[local integration](../validation/dpop-registration-current.txt).
The registration/management/DPoP subset passes **44 tests** on each of SQLite,
PostgreSQL and MySQL, without failures/errors/skips.
[DB log](../validation/dpop-registration-matrix.txt). This is targeted evidence,
not a rerun of the complete Ruby/version/package matrix.

## Server nonce policy and replay retention

The CIBA boundary now follows the reference nonce policy: a missing required
nonce produces `use_dpop_nonce` with `DPoP-Nonce` (HTTP400 at token, HTTP401 at
UserInfo). A valid nonce replaces proof iat freshness, but never replaces
signature, method, URI, key, token, client or approval checks. Non-string nonce
claims are invalid proofs; an incorrect or expired string nonce gets a fresh
challenge. One server nonce can be used across these endpoints with distinct
proofs. Reusing a proof still fails. With nonce support enabled but not required,
a fresh proof may omit it; an old proof gets a challenge.

Enable upstream `oauth_dpop` and configure `ciba_dpop_nonce_secret` with an
independent random **32-byte String**, persisted and shared by all processes of
the issuer. Keep different issuers' secrets separate. Set `oauth_dpop_use_nonce`
to true to require nonces; its default remains false. A missing secret with
required nonces, or a supplied secret of the wrong type/length, prevents startup.
Do not regenerate the secret per request or process start. Rotation invalidates
old challenges; clients obtain a fresh one and retry. No raw secret is stored in
the replay ledger.

The construction follows reference `helpers/challenge.js`: HKDF-SHA256 with
`DPoP` info, a big-endian 64-bit minute counter as salt, and a 32-byte base64url
result. The accepted counters are current minus two through current plus two;
the issued counter is current plus one. This is a moving five-step window, not
a fixed five-minute lifetime after receipt. It supersedes upstream's
`oauth_dpop_nonce_expires_in` setting for the CIBA boundary only.

Nonce-validated proof claims remain in the shared DB replay ledger until at
least validation time plus 301 seconds. Using an ancient proof iat for this
expiry would let cleanup reopen replay while the nonce remains valid. Opaque
and JWT integration tests exercise cleanup followed by replay, token/UserInfo
challenge and retry, expiry and secret rotation. Without a verified nonce, the
ledger still retains the proof beyond its accepted iat window.

[Real OP nonce run](../validation/node-dpop-nonce.txt),
[local gem run](../validation/dpop-nonce-current.txt): **13 tests / 218 assertions**.
Both implementations also reject zero iat even with a valid nonce; the added
regression originally failed for both opaque and JWT gem issuance.
[Failure before correction](../validation/dpop-nonce-zero-iat-red.txt).
The local cases include both opaque and JWT access tokens; the reference uses
opaque access tokens. Multi-process deployment, clock-skew boundaries and
installed-package validation are not established by these runs.

## Installed-artifact integration

`bin/verify-package` now builds the gem, installs it into a temporary directory,
and runs the packaged `examples/dpop_smoke.rb` without repository load paths.
It explicitly checks that both the CIBA feature and DPoP module were loaded from
the installed gem. No test helpers or stubbed proof validators are used.

For opaque and JWT access tokens, the example dynamically registers a
proof-required confidential client, initiates and approves CIBA, receives a nonce
challenge and issues tokens with an old-iat proof plus valid nonce. It verifies
the ID Token signature/issuer/audience, JWT access-token signature and cnf when
applicable, and stored key binding. Cleanup followed by proof replay cannot
consume a second approval. UserInfo rejects bearer presentation, a wrong ath,
another proof key and replay, while the correctly bound proof returns the
customer subject. Refresh accepts a new proof key, returns a token bound to it,
and that token accesses UserInfo with the same customer subject. Reusing the
refresh proof fails.

[Package run](../validation/dpop-installed-package.txt). This uses Ruby4.0.6,
SQLite and Rack requests in-process, along with the existing independent HTTPS
ping/JWKS/sector-document fixtures. It does not prove DPoP reverse-proxy/header
handling, external resource-server enforcement or multi-process behavior.
Dependencies are reused locally; fresh network dependency resolution and
publication are not part of this verification.

## POST UserInfo and token storage

The reference OP accepts POST UserInfo with a POST-bound proof, rejects a
GET-bound proof on that route and rejects replay of the accepted proof.
[Reference run](../validation/node-dpop-post.txt).
The gem exercises POST for both opaque and JWT tokens with the same checks as
GET: unbound bearer success, bound bearer rejection, key/ath/method validation,
subject matching, concurrent proof exclusion, unknown/forged credentials and
expired/revoked token rejection. These cases pass without a production change.

Correction to the earlier coverage assessment: upstream defaults
`oauth_grants_token_hash_column` to `:token`. The original gem fixtures already
used hashed opaque-token storage, despite the column name; they did not test
only plaintext storage. Tests now explicitly assert the stored hash and add
POST cases for a custom `:token_digest` column and for the opt-in plaintext
configuration (`oauth_grants_token_hash_column nil`). The custom-column case
also asserts that the ordinary `:token` column remains empty. No storage default
has changed. [Local run](../validation/dpop-post-storage-current.txt):
**17 tests / 321 assertions**.
Including DPoP registration cases, all **19 tests / 370 assertions** pass on
SQLite, PostgreSQL and MySQL with no failures/errors/skips.
[DB run](../validation/dpop-post-storage-matrix.txt).

These Rack tests use Authorization headers. They do not establish support for
body/query token presentation or every proxy/header transformation.

## Opaque-token introspection binding

The real reference OP returns `active: true`, `token_type: DPoP` and `cnf.jkt`
for an active opaque bound token without a DPoP proof on introspection. The
caller authenticates as an introspection client; this is distinct from presenting
the access token to a resource server. A refreshed token reports the new proof
key. Unknown and revoked tokens return only `active: false`.
[Reference](../validation/node-dpop-introspection.txt).

The gem initially returned inactive for these valid tokens: upstream's grant
lookup filtered for a nil DPoP key when no proof was present. Also, upstream's
introspection serializer read cnf from JWT claims, not the opaque issuance row.
The CIBA-only correction looks up recognized opaque CIBA tokens by their exact
stored token/hash, grant type, expiry and revocation, and returns the saved jkt
with token type DPoP. It retains existing client authentication. It does not
change ordinary OAuth grant lookup or authorize resource access.

Regression tests cover both ordinary OIDC and resource-targeted CIBA opaque
tokens, cnf/type, resource audience/scope, wrong client credentials, unknown,
expired and revoked tokens, and unchanged handling of an unrelated bound OAuth
grant. Introspection does not claim a DPoP proof or touch the replay ledger.
[Original failure](../validation/dpop-introspection-red.txt),
[local tests](../validation/dpop-introspection-current.txt).
The full Ruby4.0.6 suite passes **287 tests** on each of SQLite, PostgreSQL and
MySQL; SQLite skips two row-lock-specific tests.
[Full DB matrix](../validation/dpop-introspection-matrix.txt).

Applications still own which authenticated introspection callers may receive
token information. Resource servers must themselves enforce cnf/proof matching,
signature, ath, HTTP method/URI, freshness, replay and their audience/scope policy.
This change supplies the OP-side binding information; it does not implement an
external resource server. Existing resource-JWT introspection restrictions remain.

The installed-package fixture initially retrieved the introspection URL from OAuth
authorization-server metadata and verified active/cnf/type for an opaque token.
[Package run](../validation/dpop-introspection-package.txt).
Upstream's OIDC metadata allowlist had removed that URL and DPoP algorithm
metadata. The correction below supersedes this earlier restriction.

## Discovery extension metadata

OIDC Discovery now retains introspection endpoint/auth metadata and
`dpop_signing_alg_values_supported` from the actual OAuth authorization-server
metadata. It does not hardcode a URL or a new authentication method. Disabled
features remain absent. Tests cover a renamed introspection route, its caller
authentication and response, a configured ES256-only DPoP list, and disabled
features. [Failure before correction](../validation/discovery-extensions-red.txt),
[tests](../validation/discovery-extensions-current.txt).

The actual node 9.12.2 OP advertises the introspection endpoint and DPoP algorithms
when enabled, and omits these when disabled. It does **not** advertise an
introspection authentication-method list in this fixture. The gem retains the
upstream list (currently Basic) in both metadata documents; this is additional
metadata, not an assertion that both responses are byte-for-byte equivalent.
[Reference](../validation/node-discovery-extensions.txt).

The installed-gem DPoP smoke compares those values across both discovery
documents and now uses the OIDC-discovered introspection URL to verify an opaque
token's active/cnf/type response. All package smoke fixtures pass.
[Installed run](../validation/discovery-extensions-package.txt).

## Implementation requirements

Reuse upstream JWT/JWK primitives and token thumbprint storage where suitable,
but provide a CIBA-scoped validation boundary with the measured nonempty jti,
proof freshness, method/URI and proof-key rules. Persist replay claims atomically
and test concurrent use across requests without changing unrelated OAuth flows.
Preserve the gem's accepted same-DB rollback behavior explicitly; do not silently
adopt node's nontransactional consumed-on-failure behavior.

Cover initial issuance, confidential refresh, proof-required client policy,
opaque/JWT token key binding and proof-aware UserInfo before advertising support.
Malformed keys, private key material, unsupported algorithms, stale/future
proofs, duplicate proofs and incorrect ath must fail without granting access.
Configuration/migrations, key-selection scope and nonce policy must be explicit.
The reference cases above are the initial executable comparison, not completion
of this workstream.

## Alternate endpoint origin and proxy trust

A fixed canonical base_url previously made CIBA DPoP compare htu with token_url /
userinfo_url even when the application served the route at another origin.
A proof for the canonical endpoint was incorrectly accepted at the alternate
endpoint, while an actual alternate-origin proof was rejected. The
[pre-fix test](../validation/dpop-alias-red.txt) reproduces issuance with the wrong
origin in both opaque and JWT access-token modes.

The CIBA boundary now compares against the actual endpoint URL, excluding query
and fragment as before. It retains a fixed ID Token issuer independently of the
origin handling the HTTP request. Initial issuance, UserInfo and refresh reject
cross-origin/cross-path proofs; failed initial proofs do not consume approval or
create grants. Normal OP DPoP handling outside the CIBA boundary is unchanged.

The default `ciba_dpop_endpoint_uri` reconstructs the Rack URL without Forwarded
or X-Forwarded-* headers. Incoming authority/path and server-provided scheme are
used; accepting Host names and routing aliases remains the application's job.
A trusted ingress deployment can override the callback with a validated external
URL, for example a value placed in an internal Rack environment key by trusted
middleware. Do not populate that key directly from arbitrary client headers.

```ruby
ciba_dpop_endpoint_uri do
  request.env.fetch("myapp.trusted_external_endpoint")
end
```

[Reference HTTP evidence](../validation/node-dpop-alias-trust.txt) uses two actual
listeners sharing one issuer and verifies that forwarded-header spoofing alone
does not authorize a canonical proof at the other origin. Gem tests cover
opaque/JWT tokens, wrong origin/path, initial/refresh/UserInfo, unchanged issuer,
spoofed forwarding headers and an explicit trusted-URL callback.
[Local regression](../validation/dpop-alias-trust-current.txt).
The installed smoke additionally exercises alternate-port URLs through Rack and
verifies ID Token signatures against published JWKS. That Rack fixture alone is not real-TLS evidence. The subsequent
[combined mTLS/DPoP integration](mtls-reference-contract.md#real-tls-aliases-with-certificate-authentication-and-dpop-tokens)
now verifies actual TLS aliases. Production reverse-proxy behavior remains separate.

The intermediate dpop-alias-installed.txt failed because the new smoke expected
invalid_token instead of invalid_dpop_proof; its verification code was corrected
to use published JWKS. It is not a passing artifact run.

Final validation: [Ruby3.4 three-DB subset](../validation/dpop-alias-trust-matrix.txt)
passes21 tests /390 assertions on SQLite, PostgreSQL and MySQL with no
failures/errors/skips. [Installed artifact](../validation/dpop-alias-trust-installed.txt)
passes the full smoke harness; alias cases use Rack transport. The earlier full
391-test Ruby3.3 run predates this correction and is not a full regression of it.

## ID Token versus access-token confirmation claims

The pinned reference emits no cnf in initial or refreshed ID Tokens for DPoP or
certificate-bound access tokens. Reference fixtures now verify ID Token signatures
and assert this absence, while retaining their access-token binding and UserInfo
checks ([DPoP](../validation/node-dpop-id-token-binding.txt),
[real TLS mTLS](../validation/node-mtls-id-token-binding.txt)).

The gem's CIBA ID Token builder called upstream jwt_claims, which includes the
access-token sender binding. The [pre-fix test](../validation/id-token-binding-red.txt)
reproduces inherited cnf in both DPoP and mTLS cases (the same run also contains
an unrelated local-listener permission error and is not a passing suite).
The builder now removes that inherited claim in the CIBA ID Token projection,
just as it already removes token provenance/resource/authorization_details fields.
Access-token generation, stored proof/certificate thumbprints, introspection cnf,
and resource proof enforcement retain their existing behavior. Ordinary OIDC
flows are not modified by this CIBA-scoped correction.

The installed smoke checks both initial and refreshed ID Tokens and verifies
access-token/introspection binding remains present; mTLS cases use actual TLS
with PKI and self-signed authentication, each in opaque/JWT access-token modes.
This is separation of automatically inherited sender constraints, not a ban on
application-defined custom ID Token claims.

Final evidence: [Ruby3.4 three-DB subset](../validation/id-token-binding-matrix.txt)
passes35 tests /729 assertions on each of SQLite/PostgreSQL/MySQL, with no
failures/errors/skips. [Installed artifact](../validation/id-token-binding-installed.txt)
passes its full smoke harness, including the new ID Token assertions. This is
focused regression evidence; the earlier full-suite logs predate this correction.
