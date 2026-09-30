# Pairwise CIBA reference contract

Reference: installed node-oidc-provider 9.12.2, compared with rodauth-oauth 1.7.0
and the current gem. This is an implementation workstream, not a support claim.

## Measured behavior

`test/reference/full-op/registration-remote.mjs` now enables subjectTypes public
and pairwise, with an explicit application pairwiseIdentifier callback. The
callback uses HMAC over a JSON array of sector and account for the fixture; this
is application policy, not a node default or an algorithm mandated by CIBA.

The real registration and CIBA endpoints demonstrate:

- Pairwise plus Basic authentication is rejected with invalid_client_metadata.
- private_key_jwt with only inline JWKS and no jwks_uri is rejected.
- A CIBA/authorization-code hybrid with response_types code but without
  sector_identifier_uri is rejected.
- Two CIBA-only private_key_jwt clients with the same jwks_uri are registered,
  authenticated against a real local JWKS server, approved via separate saved
  Grants, and obtain ID Tokens. OP signatures, issuer and client audience are
  verified. Both subjects differ from the internal account ID and match each
  other under the configured same-sector application policy.

[Execution log](../validation/node-registration-remote-reference.txt).
This does not yet test different sectors, hint inversion, hybrid completion or
sector document validation through HTTP.

## Source boundaries that affect the gem

`lib/helpers/client_schema.js` requires jwks_uri for pairwise CIBA and an
explicit sector URI when response_types is nonempty. It permits private_key_jwt
or self_signed_tls_client_auth for such clients. Self-signed TLS is now implemented and verified separately in the
[mTLS contract](mtls-reference-contract.md#pairwise-self-signed-tls-client-authentication).

`lib/helpers/sector_identifier.js` selects the sector URI's URL.host when given.
For a CIBA-only client without that URI it selects jwks_uri's URL.host. URL.host
includes a nondefault port. Hybrid clients use the explicit sector URI because
registration requires it. `lib/helpers/sector_validate.js` validates a fetched
array: all redirect URIs (when applicable) and the client's jwks_uri must appear.
The application's sectorIdentifierUriValidate policy controls this fetch.

Node's default pairwiseIdentifier raises until configured. Its CIBA hint code
(`lib/actions/authorization/ciba.js`) verifies id_token_hint and then passes its
sub to findAccount. It does not invert a hash itself. The application must map
that pairwise subject to its canonical account in the authenticated client's
context; returning the pairwise string as a new account would change identity.
This source observation has not yet been covered by the fixture's hint flow.

Upstream Ruby `oidc.rb#jwt_subject` instead derives a missing sector from
redirect_uri and hashes host, account ID and its configured secret. A CIBA-only
client need not have redirect_uri, so removing the gem's public-only guard is
insufficient. An opt-in CIBA wrapper now supplies the sector/callback boundary; the public-only
default remains. The initial integration and remaining verification are described
in [pairwise.md](../pairwise.md).

## Implementation requirements

1. Opt-in pairwise capability with an explicit application identifier callback,
   leaving the current public default intact. Subject generation must work for
   ID Token, UserInfo, access-token claims and refresh without changing unrelated
   OAuth clients' subject handling.
2. Validate the pairwise client authentication/URI requirements on static use,
   dynamic registration and management replacement. Derive the CIBA-only sector
   from jwks_uri; handle explicit sectors and hybrid clients with the reference's
   document-membership rules and bounded outbound transport.
3. Pass the authenticated client and selected sector to identifier generation;
   reject unusable callback results. Avoid pretending a hashing function supplies
   the application's persistence, stable-key lifecycle or identity mapping.
4. Keep internal account IDs in saved requests/consents. ID Token hint resolution
   must recover that account through the existing application resolver, followed
   by the ordinary account/client/consent checks. A hint must not grant approval.
5. Verify same-sector stability, different-sector separation, hints, UserInfo,
   refresh, invalid registration and management updates, plus ordinary public
   clients. Compare real node and gem scenarios before advertising support.

The approved staged plan still includes this whole boundary. Registration-only
acceptance is not completion of pairwise alignment.


## Refresh integration

The real node fixture now requests offline_access for pairwise clients and
verifies refreshed ID Token signatures, stable subject, matching UserInfo and
canonical accountId on the saved RefreshToken. offline_access does not become
a UserInfo attribute.

The gem's opaque/JWT integration additionally checks forced refresh rotation,
old-token replay revoking the successor, refusal to exchange through another
client, and transaction rollback for nil/empty/non-ASCII/overlong identifier
callback results. Refresh source and OAuth token counts remain unchanged after
failed issuance, and a subsequent valid callback can issue successfully.

This exposed upstream UserInfo passing offline_access to its generic attribute
callback and raising when no custom callback exists. CIBA's non-projected account
claim path now removes that capability scope before delegation, preserving other
scopes and unrelated OAuth behavior. The fix is shared by opaque/JWT tokens.
[Reproduction](../validation/pairwise-refresh-red.txt),
[DB validation](../validation/pairwise-refresh-matrix.txt).


## Real HTTPS sector documents and installed artifact

The installed gem reuses the existing TLS fixture in `examples/ping_smoke.rb`.
A hybrid pairwise client is registered through the real upstream DCR route with
jwks_uri and a redirect URI in its sector document. Missing either URI, invalid
JSON/object shape, oversized body, 503 and 302 are rejected without creating a
client. The untrusted-certificate child process rejects registration before the
HTTPS application handler receives a request. No registration bearer is sent to
the document host. All existing installed-package smoke scenarios also pass.
[Artifact execution](../validation/pairwise-sector-package.txt).

The node TLS fixture in `test/reference/full-op/ping.mjs` now measures the same
membership/JSON/error cases. It **follows** same-origin 302 and accepts a valid
resulting document; the gem's bounded transport refuses redirects. This is a
newly measured remaining difference, not evidence of full transport parity.
A future redirect implementation must validate every destination and bound the
whole operation; changing the transport globally would also affect ping, whose
measured contract rejects redirects. Cross-origin redirects were not tested.
[Node execution](../validation/node-sector-tls-reference.txt).

The fixture generates and trusts an ephemeral CA in a child process only. No
production trust-store modifications or external service calls are involved.
Installed dependencies are reused; clean network dependency resolution is not
part of this artifact test.


## Sector redirect implementation

The previously measured 302 difference is now repaired in the sector fetch path.
It follows 301/302/303/307/308 with relative URI resolution, at most 20 redirects,
and an outer 2.5-second deadline for the entire chain. Each hop calls the existing
bounded transport with the same address policy and a fresh unauthenticated GET.
Invalid schemes, credentials in URLs, blocked destinations, loops and timeouts
are refused. The shared HTTP primitive and ping/JWKS behavior are unchanged.

The installed TLS fixture now accepts a valid redirected document and rejects
loops, file URLs and a redirected address outside its test allowlist without
client persistence or bearer forwarding. Unit tests cover all five statuses,
cross-origin dispatch through the policy, exact loop bounds, invalid URI forms
and an actual elapsed-time timeout spanning repeated stubbed responses.
[Installed artifact](../validation/sector-redirect-package.txt),
[DB tests](../validation/sector-redirect-matrix.txt).
The node same-origin 302 observation remains the comparison evidence. Arbitrary
cross-origin live TLS deployments, IDN host normalization, sector-document cache
lifecycle and registration-management effects remain separate work.


## Sector validation lifecycle

Source inspection located node sector validation in add_client, Client.validate,
and the first static-client lookup. Dynamic lookup hashes stored metadata and
reuses a Client in a 100-entry LRU. The real TLS fixture confirms an unchanged
loaded client survives a sector endpoint 503 without another fetch; changed
management metadata fails revalidation, preserving the old client/credential,
and succeeds when the endpoint recovers.

The gem now stores successful validation in a per-Rodauth-class 100-entry LRU
keyed by a SHA-256 digest of the complete DB client row. A cold lookup fetches;
warm unchanged metadata does not. Registration and management always validate
fresh. Failed attempts are never cached or used to invalidate an old success.
The bounded map uses a mutex only around cache operations, not HTTP. Concurrent
cold misses may duplicate fetches; no cross-process cache guarantee is made.
Using the full DB row means app-owned column changes also trigger revalidation,
unlike a cache keyed only by protocol metadata. Static clients share this bound,
whereas node maintains a separate static-client map. These are explicit storage
adaptations, not proof of identical eviction in every deployment.

[Node lifecycle evidence](../validation/node-sector-tls-reference.txt),
[gem DB tests](../validation/sector-cache-matrix.txt),
[installed TLS regression](../validation/sector-cache-package.txt).
Tests cover warm reuse, failed refresh, changed metadata, recovery, and eviction
past 100 entries. Pending/issued token behavior after sector changes is still a
separate unfinished comparison.


## Management sector changes and issued subjects

The real node fixture now changes a registered pairwise client's jwks_uri to a
second owned loopback server with a different port (thus a different sector).
The existing opaque token still obtains UserInfo, whose sub uses the new sector.
Refresh produces a verified ID Token with that new sub. Old signed tokens are
not rewritten. This outcome is fixed in the reference assertions.

Gem opaque tokens already matched; JWT tokens failed because the original signed
sub was compared with a recomputation using new metadata. The explicit nullable
`Schema.add_pairwise_subject` migration now records the issuance subject on each
new CIBA token row while pairwise is enabled (including public subjects).
Claims use the saved issuance value; UserInfo authenticates the JWT against that
value and then emits the current client's pairwise sub. Invalid signed-subject
substitutions are still refused. The DB/internal account remains unchanged.
Configuration requires the column before enabling pairwise. Legacy null rows
use the earlier current-subject comparison and may fail after sector changes;
there is no automatic historical backfill.

The gem tests perform real authenticated management PUT after refresh rotation,
then test old-token UserInfo, new refresh subject, and replay revocation for both
opaque and JWT variants. [Initial JWT failure](../validation/pairwise-sector-update-red.txt),
[DB suite](../validation/pairwise-sector-update-matrix.txt),
[reference OP](../validation/node-registration-remote-reference.txt).
The node comparison uses opaque access tokens. Its JWT resource-token profile is
not a UserInfo token profile, so this is a gem adaptation preserving its existing
JWT UserInfo capability, not a claim of identical token formats.


## Pending requests and installed issuance

Both real node and gem fixtures now start a request before changing the client's
sector through authenticated management PUT. The pending record keeps its
canonical account and no grant; the update does not supply approval. Subsequent
application approval and token collection produce a verified ID Token using the
new sector subject. The gem opaque/JWT variants pass on three databases.
[DB comparison](../validation/pairwise-pending-matrix.txt),
[node comparison](../validation/node-registration-remote-reference.txt).
These are sequential transitions, not proof of all concurrent interleavings.

The installed-gem TLS fixture now goes beyond registration: a hybrid pairwise
client authenticates using private_key_jwt against real HTTPS JWKS, begins a
CIBA request, receives application approval, obtains an issuer/audience/signature
verified ID Token, persists its issued subject and returns the matching UserInfo
subject. It explicitly migrates both subject storage and the assertion replay
ledger. Trusted and untrusted certificate cases remain separate child processes.
[Artifact evidence](../validation/pairwise-issuance-package.txt).
This installed pairwise flow uses opaque access tokens; JWT/refresh variants
are covered in the DB integration suite, not this specific installed example.

## Management changes overlapping issuance

Two gem tests now cover management PUT during opaque/JWT issuance. PostgreSQL
and MySQL pause issuance after it loads the client and force management to commit
before token generation resumes. Both tokens and the stored issuance subject
retain the old sector, while subsequent UserInfo uses the new sector. Only one
OAuth grant is created and the request is consumed. SQLite uses simultaneous
requests without a cross-writer commit barrier, accepts either serial order,
and checks the same token/storage consistency; a temporary busy response may
be retried with a fresh client assertion.

All three databases pass: SQLite **2 tests / 21 assertions**, PostgreSQL and
MySQL each **2 tests / 19 assertions**. [Log](../validation/pairwise-concurrent-matrix.txt).
No runtime change was needed. This validates the gem's same-DB issuance boundary;
it is not a concurrent reference-OP comparison. Client deletion, authentication
key replacement, refresh and arbitrary application hooks during these pauses are
not covered by these two sector-update cases.

## Signed requests do not replace pairwise client authentication

The pinned 9.12.2 client schema unconditionally restricts pairwise CIBA clients
to private_key_jwt or self_signed_tls_client_auth. Enabling
backchannel_authentication_request_signing_alg does not waive that condition.
A real HTTP DCR regression registers a public-subject Basic client with RS256
request metadata and remote jwks_uri successfully, then rejects the same
metadata with pairwise using invalid_client_metadata and the explicit
client-authentication-method error. The provider explicitly enables both subject
types so an unsupported-subject rejection cannot satisfy the test.

The gem regression accepts the same public configuration and rejects its
pairwise counterpart without saving a client. No runtime change was needed.
Earlier notes treated signed-request-only proof as unfinished parity; that
classification was incorrect. It is a shared restriction of the selected
reference policy. This registration test does not claim to exercise a signed
CIBA authentication request or all authentication methods.

[Node 24 / pinned provider execution](../validation/node-pairwise-signed-auth-policy.txt),
[gem: 1 test, 4 assertions](../validation/pairwise-signed-auth-policy.txt).
