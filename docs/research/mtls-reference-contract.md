# CIBA mutual TLS: measured reference and unresolved Ruby integration

> Latest policy supersedes the historical minimum-floor notes below: use explicit
> HTTP freshness, and permit failed-fetch reuse only with publisher stale-if-error,
> capped at60 seconds without renewing deadlines. See [operations](../operations.md#remote-jwks-cache-lifetime).


> Cache policy update: the user approved a minimum60-second successful JWKS
> lifetime shared by CIBA authentication and encryption, without a new policy
> switch. Earlier shorter-TTL comparisons below describe the previous runtime.
> Failed-refresh reuse remains excluded; expiry followed by failed retrieval
> does not renew freshness. See the current alignment closeout and Jev review.


## Real TLS reference

Node-oidc-provider 9.12.2 is configured with both `tls_client_auth` and
`self_signed_tls_client_auth`, certificate-bound access tokens, CIBA poll,
refresh and introspection. Its TLS listener requests a client certificate.
Application callbacks obtain the certificate from the TLS socket, use the
socket's chain-verification result for PKI clients, and compare the subject DN.
No HTTP header supplies certificate identity. The client also verifies the local
server certificate. The temporary self-signed test certificates are not
production credentials. The in-memory adapter and development OP signing keys
are used; protocol handlers, TLS and cryptography are not stubbed.

Run with the installed reference dependencies and Ruby/OpenSSL/Docker:

```sh
mise exec ruby -- sh bin/test-mtls-reference
```

The runner creates and removes temporary certificates. It uses the pinned Node
image with no external network. [Harness](../../test/reference/full-op/mtls.mjs),
[certificate generator](../../test/reference/full-op/mtls-certificates.rb),
[reference log](../validation/node-mtls-reference.txt).

Measured outcomes for both client authentication methods:

- CIBA initiation, approved token collection and confidential refresh succeed
  with the registered certificate.
- Missing certificates fail client authentication. Supplying certificate/verify
  HTTP headers without a TLS certificate also fails.
- Introspection reports `cnf["x5t#S256"]` equal to base64url SHA256 of the **entire
  certificate DER**, not the JWK thumbprint of its public key.
- UserInfo requires the bound certificate. A different certificate with the
  same public key is insufficient. Matching certificate returns the customer.
- Self-signed client authentication likewise rejects a distinct certificate
  with the same public key; registered x5c identifies the certificate.

This fixture covers a DN-based PKI callback and static x5c registration. It does
not cover every SAN policy, remote JWKS rotation, dynamic registration, proxy
deployment or multi-process replay/lifecycle behavior.

## Upstream Ruby characterization: not a passing support claim

The historical `test/reference/upstream_mtls_probe.rb` ran the actual
gem Rack stack with upstream `oauth_tls_client_auth` enabled. Rack server
variables model a verified TLS peer; unlike the node fixture this probe does not
perform a TLS handshake. It is deliberately outside the normal regression
suite and records current defects rather than codifying them as desired behavior.
[Observed log](../validation/upstream-mtls-probe.txt).

- PKI CIBA initiation/issuance succeeds with matching DN and `SSL_CLIENT_VERIFY`.
- The stored certificate thumbprint is **not** SHA256 of certificate DER.
  Source inspection shows upstream hashes the public JWK instead.
- The resulting bound token accesses UserInfo with no certificate (HTTP200).
  Upstream's UserInfo path does not enforce the certificate binding here.
- Header-only `HTTP_X_SSL_CLIENT_CERT` plus `HTTP_X_SSL_CLIENT_VERIFY=SUCCESS`
  is accepted. This is safe only under an explicit trusted TLS terminator that
  removes/replaces client-supplied headers; there is no such trust configuration
  in this probe. It is not evidence that every deployment is exposed.
- A registered self-signed x5c client returns HTTP500. Upstream's JWKS iteration
  and comparison use incompatible shapes/values for this registration.

## Required correction boundary

Do not advertise CIBA mTLS support based on enabling the upstream feature alone.
The default gem configuration does not enable mTLS. Implement an explicit trusted
certificate/verification boundary for CIBA, correct full-certificate identity
and digest handling, and connect binding enforcement to the actual UserInfo
entry point, refresh and introspection. Keep other OAuth grant behavior separate.
Preserve the distinction between PKI chain/subject validation and registered
self-signed certificate matching. Then replace characterization expectations
with rejection/positive regression tests and real TLS installed-artifact checks.
The initial correction below implements part of this boundary; integration work remains.

## Initial CIBA correction

The extension now requires an explicit `ciba_tls_client_certificate` callback
when upstream `oauth_tls_client_auth` is enabled, plus the configured grant
certificate-thumbprint column. The callback returns the TLS peer certificate as
an OpenSSL certificate or PEM String, or nil. It must derive that value from a
trusted server/terminator integration that already proved possession of the
certificate key. No forwarded certificate or verification header is read by the
CIBA path. Other OAuth routes retain upstream behavior.

For PKI authentication, configure `ciba_tls_client_certificate_authorized?` and
`ciba_tls_client_certificate_subject_matches?(property, expected)`. Both default
to false. The first reports actual chain verification; the second checks the
single registered DN/SAN value. These are application-owned TLS integration
policies like the reference callbacks. Multiple registered identity properties
or mixed TLS authentication method lists are rejected. For self-signed clients,
the first x5c certificate of a registered key must match the full peer certificate
DER digest; a same-key/different-certificate presentation fails. Remote JWKS uses
the existing guarded HTTP path, but TLS-specific remote rotation remains untested.

Certificate-bound CIBA issuance now stores SHA256(DER) and exposes it in signed
JWT cnf and opaque introspection. UserInfo verifies the live saved issuance and
requires the matching certificate. Confidential refresh authenticates again and
binds the new access token; it does not add public-client refresh-token binding.
A missing required certificate or simultaneous DPoP binding is rejected before
upstream's nested persistence transaction. Rejecting the combination later had
consumed approval; validation was moved before proof reservation/persistence and
the regression now verifies unchanged approval and zero token/proof rows.

The old upstream-only characterization probe has been replaced by
`test/ciba_mtls_test.rb`; its historical output above is retained as failure
evidence, not current behavior. The new tests cover both authentication methods
and opaque/JWT tokens, default/header-only rejection, wrong certificate, wrong
PKI authorization/subject, configuration checks, issuance-signing rollback,
UserInfo expiry/revocation, introspection, refresh and DPoP coexistence rejection.
[Local regression run](../validation/ciba-mtls-current.txt).

This is not complete mTLS alignment. DCR metadata/management,
remote certificate-key rotation, all SAN
callback policies, aliases/discovery and additional client-method combinations
still need work. The reference real-TLS fixture does not prove the new Ruby
callbacks are correctly wired in a deployment.

## Installed gem with a Ruby TLS server

`bin/verify-package` now runs the packaged `examples/mtls_smoke.rb` from its
temporary gem installation. It checks the loaded mTLS module's filesystem path
against that installation. A WEBrick TLS listener invokes the actual Rack app;
the requests are sent over HTTPS with Net::HTTP, not Rack mock dispatch. Rack's
environment helper is used only to adapt the incoming HTTP request. The trusted
certificate value is assigned from WEBrick's TLS peer certificate after all
HTTP headers have been mapped, so caller headers cannot populate that value.

The listener requests peer certificates and allows self-signed chains to reach
the application, like the node fixture. For PKI authentication the application
callback independently verifies the peer against the test trust store and
checks the registered DN. A foreign certificate with the same DN fails that
verification. Self-signed authentication matches registered x5c. The HTTP client
verifies the server's certificate and hostname against a separate local trust
store. Keys and certificates are generated in memory for each run.

All four combinations (PKI/self-signed, opaque/JWT) pass CIBA initiation,
approved token collection, UserInfo and confidential refresh. Absent certificates
and forwarded-header-only certificate claims fail authentication; missing and
same-key/different certificates cannot use bound UserInfo tokens. A new access
token after refresh still requires its certificate. ID Token signatures,
issuer/audience and customer subject are checked; JWT access-token cnf and opaque
introspection cnf match SHA256 of the certificate DER.
[Installed TLS run](../validation/mtls-installed-tls.txt).

This verifies one in-process Ruby TLS adapter and application trust policy with
static client registration on SQLite/Ruby4.0.6. It does not cover a production
reverse proxy, intermediate-chain policies, all SAN policies, dynamic certificate
registration/rotation or multiple application processes. No gem is published and
no network dependency resolution is performed by this verification.

## Dynamic registration and management

The CIBA metadata allowlist now includes the five PKI subject properties and
`tls_client_certificate_bound_access_tokens`. When the TLS feature is enabled,
binding accepts only JSON booleans and defaults to false. Explicit properties
require their configured storage columns; missing storage fails registration.
PKI clients must supply exactly one nonempty string subject DN/SAN property.
Other authentication methods discard subject properties, as the reference does.
Self-signed clients require registered `jwks` or `jwks_uri`. Requiring both DPoP
and TLS token binding fails registration. With TLS disabled, TLS properties are
ignored instead of passed through as arbitrary DB fields.

Full management replacement resets omitted binding to false and preserves false
in its response. Invalid updates preserve the saved row and the management
credential. Changing issuance policy does not remove existing access-token
binding: the gem regression dynamically registers a self-signed client, issues a
bound token, disables future binding through management, and verifies certificate
requirements on the old token while the new token is unbound.
[Local cases](../validation/mtls-registration-current.txt).

The real-TLS node harness now obtains its PKI and self-signed clients through
authenticated DCR and uses the generated client IDs for the complete CIBA flow.
It measures boolean validation, one-subject validation, required self-signed keys,
default false, incompatible dual binding and failed/successful management
replacement. [Reference run](../validation/node-mtls-registration.txt).

The static-registration installed-gem evidence above is historical; the fixture
now uses DCR as described below. Remote certificate rotation,
all SAN callback semantics and aliases remain to be aligned. The global binding
policy/capability distinction is addressed below.

## Installed DCR and management over TLS

The packaged TLS fixture now creates both PKI and self-signed clients through the
actual authenticated registration endpoint. It uses the returned client ID for
initiation, token collection, introspection and refresh, and checks that ID Token
audience matches that generated ID. All existing TLS certificate rejection and
opaque/JWT binding checks still run in all four combinations.

An invalid management PUT leaves policy and the credential usable. A successful
full replacement omitting the binding flag returns false and rotates the
management credential: the old credential is rejected and the new one can read
the client. Old access tokens still require their original certificate. A later
refresh authenticates through mTLS but, under the new policy, issues an unbound
access token which can use UserInfo without a certificate. This distinguishes
TLS client authentication from access-token certificate binding.

[Installed DCR TLS run](../validation/mtls-dcr-installed-tls.txt). This is the
temporarily installed artifact on Ruby4.0.6/SQLite using the same explicit TLS
trust boundary described above. It does not prove certificate rotation or
arbitrary deployment/trust-policy behavior. Existing package smoke checks also
pass; no production code changed in this verification increment.


## Capability versus client binding policy

The node TLS harness advertises binding capability true while a client with
binding false obtains unbound new access tokens. Existing bound tokens still
require their certificate. This is measured after management replacement and
refresh, not inferred from metadata alone.
[Reference run](../validation/node-mtls-capability.txt).

The gem previously let upstream's global binding flag override a CIBA client's
false policy; both opaque and JWT regressions reproduced it.
[Failing cases](../validation/mtls-capability-red.txt). CIBA issuance and refresh
now use only client binding metadata. The upstream global setting is not mutated
and its ordinary OAuth grant handling remains delegated to upstream. Enabling
`oauth_tls_client_auth` advertises capability true in both metadata documents,
regardless of that global policy. A prepended metadata method avoids feature
load order overwriting the value; the OIDC allowlist preserves it.

The related mTLS/Discovery suite passes **21 tests / 311 assertions** on each of
SQLite, PostgreSQL and MySQL, with no failures/errors/skips.
[Matrix](../validation/mtls-capability-matrix.txt). The installed TLS fixture now
sets upstream's global policy true and still verifies management replacement to
false, certificate-free use of new refreshed tokens, and certificate enforcement
on old tokens in all four PKI/self-signed × opaque/JWT combinations.
[Package](../validation/mtls-capability-package.txt). This does not establish
identical configuration APIs, remote rotation, endpoint aliases or arbitrary
proxy/SAN policy equivalence.


## Endpoint aliases are application deployment configuration

Inspection of the pinned node9.12.2 `lib/actions/discovery.js` finds no automatic
`mtls_endpoint_aliases` generation. The real TLS fixture now first verifies that
absence, then adds aliases through application middleware and serves the same
provider on a second HTTPS port. Discovered aliases for backchannel authentication,
token, introspection and UserInfo are used in the complete existing CIBA flow.
Canonical endpoint metadata and issuer remain unchanged; ID Token issuer remains
canonical too. [Reference run](../validation/node-mtls-aliases.txt).

The installed gem fixture follows the same deployment boundary: application
Discovery middleware publishes the four aliases and two WEBrick TLS listeners
serve the same Rack application. `base_url` and `authorization_server_url` remain
pinned to the canonical issuer. Request environments use the actual listener
origin, while the peer certificate comes from the TLS socket. The client follows
the discovered alias URLs; absent/header-only/foreign certificates still fail,
UserInfo still checks certificate binding, and management still changes only
future issuance policy. The ID Token signature, issuer and audience are verified.
All PKI/self-signed × opaque/JWT combinations pass.
[Installed package](../validation/mtls-aliases-package.txt).

No gem routing API is needed for this measured deployment. Aliases are not
created automatically and the application owns both published URLs and actual
TLS routing. This is evidence for distinct ports and unchanged paths, not for
arbitrary path rewrites, reverse proxies, alias-only access enforcement, DPoP
proof URLs on aliases, or certificate rotation. Earlier references to aliases as
an unimplemented parity feature were too broad: automatic alias routing is not a
behavior of the pinned reference. Deployment-specific cases remain unverified.


## Remote x5c rotation and retrieval failures

The node TLS fixture now registers a self-signed client with a remote `jwks_uri`.
Its locally owned HTTP JWKS receiver is explicitly allowed through the provider's
fetch policy; inbound authentication still uses real TLS peer certificates.
Both reference and gem tests verify: a cache with `max-age=3600` retains the old
certificate; a new certificate with the same public key does not force a fetch;
after forced cache expiry, only the newly published certificate authenticates.
Tests expire the actual cache directly rather than waiting an hour. This proves
replacement semantics, not a wall-clock TTL or distributed-cache guarantee.
[Reference run](../validation/node-mtls-remote.txt).

The gem had reused the signed-request key-lookup flag during TLS authentication.
A remote 503 therefore returned `invalid_request`, incorrectly treating this as
key lookup after successful client authentication. A distinct TLS lookup flag
now selects guarded HTTP transport and returns `invalid_client_metadata` for
retrieval/JSON/structure failure, matching the observed reference response.
An empty key set is structurally valid but cannot authenticate, so returns
`invalid_client` with401. Failed requests do not create pending CIBA requests.
[Regression before fix](../validation/mtls-remote-red.txt).

There is a deliberate failure-cache difference: after refreshing a populated
reference key store fails with503, its new freshness timestamp retains old keys
and the next authentication can succeed without another fetch. The gem does not
restore an expired cached key set after failure and continues to reject until a
successful fetch. This stricter behavior is retained rather than copying stale
credential acceptance. Neither behavior instantly revokes already cached keys;
rotation/revocation must account for the configured cache lifetime. Node also
uses a minimum60-second freshness interval; the gem retains upstream's HTTP
cache policy, including `no-cache`, without claiming identical TTL behavior.

The final gem case checks repeated503 rejection, blocked destinations without
network requests, absence of pending records on failure and successful recovery.
[Final three-DB case](../validation/mtls-remote-final.txt). The broader mTLS/remote
JWKS subset passes17 tests /304 assertions per DB before those final additions.
[Related cases](../validation/mtls-remote-matrix.txt).

This increment does not yet exercise remote certificate rotation in the
installed artifact, simultaneous issuer processes, or a real HTTPS JWKS rotation
receiver. The installed package's existing TLS/aliases and other smoke flows
are separately rerun; outbound TLS transport has separate earlier JWKS evidence.


## Installed HTTPS certificate rotation and JWT introspection

The installed mTLS smoke now runs in a child process whose `SSL_CERT_FILE` trusts
only the locally generated fixture certificate file in addition to the process's
normal trust-path behavior. Verification is never disabled. This isolates the
fixture CA from the parent process and later smoke fixtures. Self-signed clients
use a dynamically registered HTTPS `jwks_uri`; the real outbound transport reads
`x5c` from the owned receiver, with only loopback explicitly allowed by the app.

Both opaque and JWT flows pass remote cache reuse and certificate mismatch
without refetch. After publishing a different certificate containing the same
key and explicitly expiring the cache, the old certificate cannot authenticate,
while the new one can refresh an existing confidential client's token. The new
access token's UserInfo and introspection binding refer to the new certificate.
Previously issued tokens still require the original certificate. Repeated503
responses produce invalid_client_metadata without adding pending requests;
restoring the receiver allows authentication again.

The expanded fixture exposed a runtime defect: JWT introspection discarded cnf
because the upstream serializer receives verified claims rather than a grant
row. The mTLS serializer now resolves the live CIBA issuance, checks client and
subject provenance plus the saved/claimed certificate digest, then includes
`cnf.x5t#S256`. Expired or revoked issuance returns inactive. This is scoped to
CIBA tokens with the TLS feature; unrelated JWT handling stays upstream-owned.
[Failing installed run](../validation/mtls-remote-installed-tls.txt).

The corrected package passes the entire installed smoke suite, including both
remote-rotation variants. [Final package](../validation/mtls-remote-installed-final.txt).
The mTLS subset passes **14 tests /307 assertions** on each of SQLite, PostgreSQL
and MySQL, including opaque/JWT introspection cnf, expiry and revocation.
[DB regression](../validation/mtls-jwt-introspection-matrix.txt).

These tests use forced cache expiry and one application process on Ruby4.0.6;
they do not establish real-time TTL behavior, distributed invalidation, arbitrary
proxy trust configuration, or all TLS subject-matching application policies.


## Pairwise self-signed TLS client authentication

The reference TLS harness dynamically registers a pairwise self-signed client
with remote jwks_uri and verifies CIBA issuance and matching UserInfo subject.
[Reference](../validation/node-pairwise-mtls.txt). The gem's private_key_jwt-only
pairwise gate rejected this combination ([regression](../validation/pairwise-mtls-red.txt)).
It now accepts self_signed_tls_client_auth when the TLS feature is enabled,
while still requiring remote JWKS and rejecting simultaneous inline keys. Actual
certificate verification remains in the mTLS authentication boundary.

The new gem cases cover opaque/JWT initiation, different-certificate refusal,
approval, pairwise subject snapshot, canonical stored account, UserInfo and
refresh. The installed fixture now combines DCR, pairwise self-signed clients,
HTTPS x5c rotation and mTLS aliases. It exposed a JWT introspection failure:
upstream tried to look up the pairwise subject as a local account identifier.
The mTLS serializer now supplies the already-validated issuance's internal
account ID to that lookup while keeping the public pairwise sub in the response.
[Local failure](../validation/pairwise-mtls-introspection-red.txt),
[initial installed failure](../validation/pairwise-mtls-package.txt).

The initial related matrix passes30 tests on each DB; final focused and installed
results are recorded separately after the introspection correction.
[Related](../validation/pairwise-mtls-matrix.txt),
[final DB](../validation/pairwise-mtls-final.txt),
[final package](../validation/pairwise-mtls-package-final.txt).
Signed-request-only proof of remote-key ownership remains a separate missing
pairwise path. These checks do not establish arbitrary app identifier policy or
multi-process key/sector rotation.


The installed pairwise JWT also exceeded Rodauth's default1024-byte parameter
limit. Its introspection token became empty before CIBA client-auth selection.
CIBA introspection now permits identified CIBA token input up to8192 bytes;
other parameters/routes and unrelated tokens retain upstream limits. This
unverified marker selects parsing/authentication handling only; signature and
live issuance validation still precede an active response. The final focused
case uses a254-character pairwise subject and asserts the JWT exceeds1024 bytes.
The final installed run passes remote certificate rotation and introspection
with the pairwise subject; no debug tracing remains in the fixture.

### Long JWT introspection security regression

The pairwise mTLS JWT fixture now rejects four otherwise plausible token inputs:
a foreign signing key, an unsigned JWT, an OP-signed changed subject, and an
OP-signed unknown CIBA issuance identifier. Each authenticated introspection
returns active=false. Missing and foreign caller certificates return 401 even
for the valid long token. These checks exercise actual HTTP routes and the
stored issuance boundary, not only JWT decoding.

A separate request-parameter check confirms that the CIBA marker only permits
up to 8192 bytes at introspection's token parameter. An 8193-byte candidate,
a non-CIBA 1025-byte string, the token parameter at another route, and an
oversized client_secret still yield no parameter value. The fabricated marker
in this parser test is not authenticated; the route tests above establish that
selecting the larger parsing limit does not authorize a token or caller.

[Local regression](../validation/pairwise-mtls-introspection-security.txt):
3 tests, 45 assertions, no failures/errors/skips. No runtime change was needed.
This is not a new three-database or full-suite execution.

## Real TLS aliases with certificate authentication and DPoP tokens

The previously unverified combination now has a complete real-TLS flow in the
pinned reference OP and installed gem. A separate registered client uses either
`tls_client_auth` or `self_signed_tls_client_auth`, requires DPoP-bound access
tokens, and explicitly does not require certificate-bound access tokens.
These are separate responsibilities: the certificate authenticates the client;
the DPoP key constrains access-token use.

Both fixtures discover application-owned aliases on a second TLS listener while
retaining the canonical issuer. They verify:

- initiation, approval and token collection through the alias;
- rejection of missing client certificates and missing DPoP proofs at collection;
- rejection of a proof whose htu names the canonical endpoint instead of the alias;
- signed ID Tokens with canonical issuer/client audience and no inherited cnf;
- introspection returning exactly the DPoP jkt, with no x5t#S256 binding;
- UserInfo rejecting a Bearer request even with the certificate, and accepting a
  DPoP proof without a client certificate;
- refresh requiring both client certificate authentication and DPoP, and retaining
  the exact expected DPoP-key confirmation in the new access token.

The gem fixture additionally runs both opaque and JWT access-token modes and keeps
upstream's global certificate-binding setting enabled, proving the explicit CIBA
client binding policy remains authoritative. Its four combinations use actual
WEBrick TLS peer certificates and trusted server certificates, not forwarded
certificate assertions. UserInfo uses GET in this integration fixture.

[Reference execution](../validation/node-mtls-dpop-alias.txt),
[installed gem execution](../validation/mtls-dpop-alias-installed.txt).
No runtime change was needed after the earlier DPoP endpoint-URI correction.
This closes the concrete combined-alias coverage gap. Production reverse proxies,
cluster nonce/key distribution and arbitrary application trust policies are not
established by this local integration test.
