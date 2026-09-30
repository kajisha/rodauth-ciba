# Dynamic CIBA registration: measured reference contract

DPoP client metadata now has a [separate measured contract](dpop-reference-contract.md#dynamic-registration-of-proof-required-clients): strict boolean validation when enabled, storage requirements, false/default serialization, issuance enforcement, full-replacement updates and ignored metadata when the feature is disabled. This does not establish nonce or all DPoP deployment combinations.

Reference: published `oidc-provider` 9.12.2, Node 24.21.0, complete HTTP OP
with its development memory adapter. The dedicated
[harness](../../test/reference/full-op/registration.mjs) and
[passing output](../validation/node-registration-reference.txt) establish these
observations, not a general DCR or pairwise conformance claim.

## Measured behavior

- Registration is discovered through `registration_endpoint`. This fixture
  configures a fixed initial access token; an incorrect bearer token returns 401.
- A CIBA-only confidential poll client with `response_types: []` can omit both
  `redirect_uris` and `client_name`. Registration returns 201, generated client
  credentials, and an empty redirect URI array.
- Missing delivery mode, unsupported `push`, missing ping endpoint, an HTTP
  ping endpoint, and a string instead of a user-code boolean return 400
  `invalid_client_metadata`.
- Unknown internal-looking fields (`id`, `internal_admin`) are ignored; a
  caller-supplied `client_secret` is replaced with a generated secret.
- A ping client with an HTTPS endpoint and boolean user-code metadata registers.
  The test does not contact that endpoint or exercise user-code verification.
- A separate registered client combines ping, an RSA-signed request and required
  user code. Its real signed request is rejected with the application's wrong
  code and accepted with its approved code. This node fixture does not complete
  that request or deliver its ping; those phases have separate harnesses.
- With RAR enabled, registration accepts a supported type-name array and rejects
  a scalar, non-string elements, empty names and unknown types. A full update
  omitting the type list returns an empty list and subsequent RAR requests are
  rejected. The node fixture provides a resource indicator, as required for RAR.
- Pairwise plus client-secret-basic is rejected. Successful pairwise registration
  and subject derivation are not established by this fixture.
- The generated poll-client credentials authenticate a real backchannel request.
  After the application creates consent and completes the request, polling returns
  access and ID tokens. This test checks issuance, not cryptographic verification
  of those tokens (the lifecycle harness separately verifies signatures).
- With node's registrationManagement enabled, the issued registration bearer
  reads its client and is echoed in the response. A partial update lacking
  `client_id` is rejected; a full metadata update succeeds. A second replacement
  omitting the name removes it and retains the original client secret, followed
  by successful deletion. Default management updates rotate the bearer;
  the previous bearer is then rejected with 401.
  Presenting a bearer for a different client both returns 401 and invalidates
  that bearer: a subsequent request for its own client also returns 401.
- Deleting a client with issued tokens and a pending CIBA request returns 204.
  Subsequent poll returns 401 invalid_client and UserInfo returns 401
  invalid_token. The node memory adapter still contains the Grant, AccessToken
  and pending request records; record retention is distinct from usability.

The app callbacks for context and binding message are explicitly no-ops;
the composition fixture supplies a fixed user-code validation policy. The first attempted run reached
registration but failed request creation with the default context callback;
the corrected fixture now passes the complete registration-to-issuance path.

## Gem integration work still required

The gem now prepends `CibaSupport::Registration`, with
`ciba_dynamic_client_registration_enabled` defaulting to false. Initial opt-in
integration supports the measured public-subject poll registration and token
issuance path. Static-only behavior remains the default.

`test/ciba_registration_test.rb` covers generated credentials, real issuance,
invalid metadata without insertion, application registration authentication,
ordinary OAuth required fields, valid management updates, grant removal and
Discovery. A regression first reproduced a partial update to `subject_type`
being accepted for an existing CIBA client without resending `grant_types`.
The first repair merged stored metadata while holding the application row. The
current implementation instead uses node-style complete replacement for CIBA
management requests, retaining the row lock through validation/persistence
(SQLite uses an immediate transaction).

This is an initial integration, not a release-ready DCR claim. Additional
client-auth combinations and remaining metadata validation need coverage.
Full registration management response semantics
still need comparison with node. Package/Ruby-version coverage has not yet been
refreshed for this change.

## Registration security review and repairs

Regression tests reproduced upstream's fallback accepting arbitrary DB column
names and its management serializer exposing the registration access-token hash.
For CIBA registrations, the gem now selects explicit protocol metadata before
calling upstream validation. Unknown fields are ignored even if a matching DB
column exists; generated credentials replace caller-supplied create secrets.
This mirrors the measured node behavior for unknown fields and create secrets.
Custom metadata is not automatically admitted merely by adding a database column.

Management tests verify a wrong bearer cannot update the row and internal fields
cannot change identifiers/privilege/token hashes. The earlier compatibility
handling for ignored-fields-only partial updates has been superseded by full
replacement: a matching `client_id` is now mandatory, and server-issued token/URI
fields in the body are rejected before persistence.
CIBA management responses suppress stored credential hashes, include `client_id`,
and return scalar `token_endpoint_auth_method`. They now echo the authenticated
presented bearer and include the registration client URI, matching the measured
node GET behavior. The stored registration verifier is also suppressed on the
ordinary serializer path, so an older unprefixed client does not expose it after
removing its CIBA grant. Other ordinary response mapping remains upstream's.

## Initial management credential issuance

When CIBA DCR is enabled, `ciba_issue_registration_access_token` defaults to true.
Registration generates 32 random bytes encoded as a URL-safe bearer with a
`ciba_reg_` namespace prefix, stores only
its bcrypt verifier using upstream `password_hash`, and returns the raw bearer
and management URI inside the original registration transaction. It also stores
a unique SHA-256 lookup digest using `ciba_registration_token_digest_column`
(default `ciba_registration_token_digest`). The application table needs both
the upstream registration verifier column and this explicit additive migration:

```ruby
Rodauth::CibaSupport::Schema.add_registration_token_digest(db)
# Custom table/column supported via table: and column: keyword arguments;
# configure ciba_registration_token_digest_column to match a custom column.
```

Missing storage raises a configuration error rather than returning an unusable
management credential. Setting `ciba_issue_registration_access_token false`
omits issuance. The migration preserves existing rows with null digests. It does
not reconstruct digests from bcrypt verifiers: prefixed credentials issued by
the earlier development implementation need reissuance; unprefixed upstream
management credentials retain their previous authentication path.

The app must mount `load_registration_client_uri_routes` after `r.rodauth`, as
in the integration fixture. Mounting upstream's broad management route before
the registration POST route consumes that path and returns 404.

The gem test uses the issued credentials for GET, PUT and DELETE. Presenting a
new issued bearer to another client's URI now invalidates the presented bearer,
matching node; a subsequent request to the original client's URI returns 401.
The target client's row and the source's OAuth client secret remain unchanged.
Unknown or malformed bearers cannot revoke any client. Lookup and password-hash
verification are both required before a mismatch can invalidate credentials.

For ordinary management operations, the transaction locks the presented
credential's source row before validating the target client identifier. A mismatch clears only the source verifier/digest
and commits that deliberate invalidation before returning 401. It never locks
the unrelated target row, avoiding opposite cross-client requests locking each
other's rows. Concurrent updates of one client and opposite-client mismatches
are tested on separate connections; the latter invalidate only each presented
credential and leave OAuth secrets and an unrelated client unchanged.
Digest/verifier fields are omitted from management responses.
After invalidation, arbitrary unprefixed bearers are also rejected with 401:
the management-route-only hash matcher treats a missing verifier as a failed
match instead of passing nil to BCrypt and returning an internal error.

Deletion with existing CIBA and ordinary grants is now covered below. This work
does not establish full management parity.

## Full replacement updates

CIBA management PUT requires a matching `client_id`; mismatches or omission
return `invalid_request` without saving changes. Server-issued management token,
URI and issuance/secret-expiry fields are forbidden in the request. Omitted
protocol metadata is reset; explicit metadata is validated again. The client
identifier, client secret and app-owned internal columns are retained. The
registration credential is rotated by default as described below. Browser
response types require redirect URIs. Optional metadata's
complete default/type behavior still needs the feature-composition tests.

The `ciba_reg_` namespace selects this same management policy and safe response
serialization even after the client removes its CIBA grant. It is not an
authentication credential by itself: upstream still checks the full bearer
against the saved verifier before management validation or serialization.
Older unprefixed bearers rely on the client's current CIBA grant for selection
of the replacement policy; stored verifier redaction applies regardless.

Mounted-route coverage registers under `/identity/register` and verifies that
the same missing-client-id rejection applies there. Row-lock selection uses
the route's remaining path, matching upstream's routing rather than assuming
registration is mounted at the URL root.

## Optional-feature composition and storage

The gem test dynamically registers a client combining ping, RS256 request
signatures (separate client JWKS) and user-code validation. An unsigned request
and an incorrect code are rejected before request persistence. A correctly
signed request is completed, its ping dispatch goes through a test transport
with the registered endpoint/token, and polling returns a verified signed ID
Token for the newly generated client. This is not a real HTTPS delivery test;
the separate installed ping smoke supplies that transport evidence.

A full update then removes signing keys/algorithm and the notification endpoint,
switches to poll, and explicitly sets the user-code metadata false. The unsigned
request is now accepted under that new registration. This exposed and repaired
the upstream serializer dropping boolean false from the management response.

Another regression reproduced registration returning 201 with submitted JWKS
even though the application table lacked the JWKS column and upstream discarded
the key material. All accepted mapped CIBA-registration metadata must now have
storage before registration/update succeeds; missing columns return
`invalid_client_metadata` without inserting a client. Unknown ignored metadata
remains ignored. Column presence is not a claim that every optional feature,
key shape, algorithm or arbitrary schema type has been validated.

## RAR client metadata

With `ciba_authorization_details_enabled`, dynamic registration validates
`authorization_details_types` as an array of nonempty strings from the OP's
configured types. The array is serialized as JSON into the existing RAR client
column; create/read/update responses expose an array. Omission defaults to an
empty array, including full replacement updates. With the feature disabled,
the metadata is ignored and not persisted or echoed, even if that column exists.

The gem composition test registers a client for CIBA and refresh, requests RAR
read/delete actions for a resource, and saves approval for read only. Initial
resource token issuance and refresh carry only that approved read action. A
management update removing the registered type then prevents refresh of the
old RAR source. The fixed application callback defines action subset semantics;
this is not evidence of a generic RAR policy engine.

## Management token rotation

`ciba_rotate_registration_access_token` defaults to true, matching node's
`registrationManagement.rotateRegistrationAccessToken` default. A successful
PUT writes replacement metadata, a fresh verifier and its unique lookup digest
in one transaction, and responds with the new raw bearer. The old bearer is no
longer found; replay against either the original or another client cannot
invalidate the successor. GET does not rotate. Explicit false retains the bearer.

A response-serialization exception is injected after the new token is generated
and the update executes. The test confirms the row rolls back, the attempted
new bearer is rejected and the original bearer still authenticates. This follows
the accepted same-DB atomicity policy rather than claiming node's memory adapter
has equivalent failure behavior. Loss after a committed response is outside
that guarantee and requires application recovery/re-registration.

Two simultaneous PUTs using one bearer run on separate DB connections. Only one
can commit a new bearer. PostgreSQL/MySQL should reject the other with 401 after
acquiring the row lock. SQLite may instead time out waiting for its writer lock;
recognized BusyException (or adapter lock/serialization errors) returns 503
`temporarily_unavailable` with Retry-After. Retrying that request then returns
401. Other database errors are not mislabeled as retryable. This does not claim
crash recovery or guarantees for arbitrary application overrides.

## Deleting a client with live grants

The gem initially failed deletion when an ordinary OAuth grant referenced the
client: that grant has no CIBA-consent FK to cascade through. After authenticating
the management credential, CIBA-managed DELETE now removes OAuth grants belonging
to that client and the client itself within the existing outer transaction.
The supplied CIBA schema cascades consent, requests, refresh sources and private
ping delivery rows. Other clients and their grants remain unchanged. Legacy
unprefixed management credentials for a currently CIBA-enabled client use the
same cleanup after their own verifier check.

The test first proves opaque UserInfo and refresh work, then changes the client
to ping and creates a pending notification. It adds an ordinary grant to the
same client and an unrelated client's grant. A wrong bearer leaves all rows
unchanged. Successful deletion removes the target's credentials and dependent
records; UserInfo, refresh and pending poll are rejected. Ping data is pending,
so this test makes no outbound delivery request.

Unlike node's measured memory adapter, the SQL implementation removes dependent
rows using its established FK relationships; both measured OPs reject subsequent
use of the deleted client's opaque token and poll credentials. This does not
promise invalidation of externally validated self-contained JWTs before expiry.

A second test adds an application-owned restrictive FK. Failure to delete the
client rolls back the preceding grant cleanup, leaving its management credential
usable. The gem does not delete arbitrary application dependencies. The application
must resolve those dependencies or configure its own deletion policy. Custom
schema cascade policies remain unverified.

### Deletion lock order and refresh race

A deterministic PostgreSQL regression held a consent row while DELETE held the
client row, reproducing the reverse-order timeout. DELETE now verifies the
credential without a client lock, locks that client's existing consents in ID
order, then locks the client and revalidates the credential. A matching client
may therefore wait for a consent without blocking a refresh's parent-client FK
access. A mismatched URI still never locks the unrelated target's consents.
The controlled two-connection test passes on PostgreSQL/MySQL; SQLite's writer
serialization makes that row-lock-specific test inapplicable.

An actual concurrent DELETE/refresh test verifies eventual client deletion,
empty dependent tables and refusal of the old refresh token. Refresh may finish
before deletion or be rejected after it; recognized contention returns 503 and
deletion is retried. This exposed SQLite BusyException being reported as 500 by
the token endpoint: the same narrowly recognized condition now returns 503 there
as on management routes. Arbitrary DB errors still retain server-error handling.
These tests do not establish every interleaving with newly created consents,
ordinary OAuth issuance, external token consumers or custom transaction hooks.

Installed rodauth-oauth 1.7.0 requires `redirect_uris` and `client_name` before
calling `validate_client_registration_params`. Its registration implementation
also defaults omitted grants and responses to authorization_code/code. Therefore
removing the static rejection alone cannot implement the measured contract.

The complete integration must cover:

1. Explicit opt-in and CIBA-specific required/default metadata without changing
   unrelated OAuth registration behavior.
2. Validated delivery mode, notification endpoint, user-code boolean, request
   signing algorithm/key requirements, and supported subject/authentication
   combinations before persistence. Optional capability flags and migrations
   must constrain the accepted metadata.
3. Real register/start/complete/poll behavior with generated credentials, plus
   rejection cases that leave no newly registered client.
4. Registration management updates: changing grant types, CIBA metadata or
   authentication must not bypass the same checks. Authorization remains the
   registration feature/application's responsibility.

Pairwise remains a separate incomplete boundary; rejecting unsupported pairwise
registration initially is not full alignment with the reference.

## Reproduction

From `test/reference/full-op`, after installing the pinned dependencies:

```sh
docker run --rm --network none \
  --mount "type=bind,src=$PWD,dst=/app,readonly" --workdir /app \
  node:24-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6 \
  node registration.mjs
```

Only loopback listeners are used; no external network or production credentials.
Source inspection: `lib/helpers/client_schema.js` and
`lib/actions/registration.js` in the pinned node package, and upstream
`lib/rodauth/features/oauth_dynamic_client_registration.rb`.

### Dynamically registered private_key_jwt

The real node OP accepts a dynamically registered RSA public JWKS for CIBA
client authentication. Wrong key, wrong audience and replayed assertion are
rejected. An issuer audience is accepted at both the backchannel and CIBA token
endpoints. The gem previously accepted issuer only at the backchannel endpoint;
its CIBA grant token path now also accepts issuer, retaining endpoint audiences.
Other token grant paths and unrelated clients retain their existing policy.

The gem integration also replaces the registered JWKS using authenticated
management PUT: fresh assertions signed with the removed key are rejected and
the replacement key works. This is inline JWKS replacement; remote JWKS cache
invalidation and algorithm metadata validation are separate remaining work.

### Client authentication signing algorithm

`token_endpoint_auth_signing_alg` is optional. When supplied, CIBA registration
checks its string type, the registered JWT authentication method and the OP's
advertised algorithms. `none`, an asymmetric/HMAC method mismatch, unsupported
algorithms and use with Basic authentication are rejected before insertion.
The application must add a nullable String `token_endpoint_auth_signing_alg`
column, or configure `oauth_applications_token_endpoint_auth_signing_alg_column`
to its mapped column; requests supplying the field fail if storage is absent.
Omission preserves the previous assertion algorithm policy.

Authentication compares the assertion header with the saved algorithm before
signature verification. For private_key_jwt the selected algorithm is also
passed to the upstream decoder. A regression using keys for RS256 and RS512
proved that previously an RS512-registered client could authenticate with RS256;
it now rejects RS256 and accepts RS512. The same registered constraint applies
on CIBA-capable clients' existing protected assertion authentication paths.

The real node fixture explicitly enables RS256/RS512 through
`enabledJWA.clientAuthSigningAlgValues`; RS512 is not a node default. Gem tests
configure these through upstream `oauth_jwt_keys`, which supplies its existing
Discovery signing-algorithm list. This does not decouple client-auth algorithms
from OP signing configuration. HMAC and other algorithm-family combinations
need further comparative coverage; the RSA test is not proof of all families.

### Inline JWKS registration validation

Inline `jwks` must contain a `keys` array of objects. Recognized RSA, EC, OKP
and AKP entries have the reference provider's structural checks for required
public fields, forbidden private parameters, optional alg/kid/use strings and
x5c arrays. Symmetric oct entries are rejected. Like node, unknown key types
and unsupported curves are not required to pass recognized-key checks; neither
registration acceptance nor an empty set proves usable authentication keys.
Actual signature verification remains necessary. This validation applies to
CIBA registration and management replacement, without changing ordinary OAuth
registration's upstream policy.

The real node and Ruby fixtures cover malformed top-level/entry structure,
symmetric keys, every forbidden RSA private parameter, malformed RSA public
fields and metadata, plus acceptance of an empty set. The gem also verifies
that rejected management replacement leaves both metadata and the current
management credential intact. These fixtures do not establish operational
support for every curve or key type, or validate remote JWKS responses.

### Remote assertion keys and management URL replacement

A real loopback HTTP fixture exercises dynamic private_key_jwt registration,
JWT authentication, an upstream max-age cache hit, and authenticated management
PUT replacing jwks_uri. Registration's URI policy is explicitly relaxed only
for the two fixture URLs. With the normal outbound address policy, the first
assertion must fail without contacting loopback. After a test-only address
allowance, the old URI is fetched once and cached; changing to the new URI
rejects old-key assertions and accepts the new key, without refetching the old
URI. Malformed JSON and oversized responses fail authentication without saving
pending requests.

This exposed private_key_jwt using upstream HTTP directly, bypassing the
outbound controls already used for signed CIBA authentication requests. The
protected client-assertion lookup now uses the same bounded, address-checked
transport. Fetch/parse failures become invalid_client. Unrelated client flows
retain upstream transport behavior.

The published node OP is now exercised by `registration-remote.mjs` over real
HTTP with its memory adapter. It rejects default loopback lookup with 401
invalid_client without reaching the receiver. A test-only exception for the
two owned URLs then permits one fetch and cache reuse. Changing the served key
at the same URL while max-age=3600 is fresh rejects the new kid, still accepts
the cached old key and performs no fetch. Management PUT changing jwks_uri then
rejects the old key and accepts the new key after one new-URL fetch. The gem's
matching test confirms this sequence; no unknown-kid refresh was added.

[Node log](../validation/node-registration-remote-reference.txt),
[gem DB comparison](../validation/registration-remote-cache.txt).
This establishes the measured fresh-cache and URL-replacement behavior only.
Node's source applies a minimum 60-second freshness interval, whereas upstream
Ruby follows its own HTTP cache policy; no-cache/expiry timing, same-URL metadata
updates, shared cache ownership and cross-process invalidation still require
separate comparison. Do not infer universal cache equivalence.

## default_max_age validation and persistence

The reference OP accepts non-negative safe integer values (0 through
9007199254740991), and rejects negative/fractional numbers, strings, booleans,
arrays, objects and larger numbers. The gem previously returned 201 for -1;
valid values were echoed but dropped from insertion because upstream's generic
metadata key did not map to a symbol column. Both boundaries are now explicit.
Integral JSON numbers such as 1.0 normalize to an integer before storage.

To accept this optional metadata, add a nullable BIGINT `default_max_age` column
to the application's client table. Override
`oauth_applications_default_max_age_column` if using another column name.
Without storage, supplying this metadata is rejected. Failed management PUT
preserves the whole client row, including its management credential; authenticated
GET returns the stored value, including zero.

This is registration metadata support, not implementation of browser OIDC
reauthentication or a new CIBA parameter. The application still implements
authentication policy; no claim of automatic freshness enforcement follows.
[Reference HTTP results](../validation/node-registration-max-age.txt),
[initial failing test](../validation/registration-max-age-red.txt).

The full three-DB suite passes **265 tests** before the final 1.0 normalization;
the final targeted test passes **59 assertions** on each DB, including missing
storage, bad values, persisted valid values, management rollback and GET.
[Full DB log](../validation/registration-max-age-matrix.txt),
[final change](../validation/registration-max-age-final.txt).

## require_auth_time boolean metadata

The pinned reference accepts only JSON booleans for `require_auth_time` and
returns both true and false from registration and authenticated management GET.
The gem previously accepted the string `"true"` and echoed it in a201 response.
CIBA registration now rejects non-boolean values before persistence and maps the
metadata to an explicit column. Its management serializer also preserves false;
upstream's generic serializer omits false-valued columns.

Applications accepting this metadata must add a nullable boolean
`require_auth_time` column, or override
`oauth_applications_require_auth_time_column`. Supplying it without storage is
rejected. Invalid management replacement leaves the client row and management
credential unchanged. No new table requirement applies when it is omitted.
This registration change validates and stores metadata. The separate token-output
comparison and subsequent implementation are recorded below.

Evidence: [reference registration and GET](../validation/node-registration-auth-time.txt),
[pre-fix failure](../validation/registration-auth-time-red.txt), and
[Ruby3.4 SQLite/PostgreSQL/MySQL](../validation/registration-auth-time-matrix.txt),
2 tests /95 assertions on each backend including default_max_age regression.
The DB run uses existing test-image dependencies with current lib/test/examples
mounted read-only; it is not a new image build or a full-suite run.

### Measured auth_time output difference

The dedicated `auth-time.mjs` reference fixture checks six configurations:
require_auth_time omitted/false/true, each with completion authTime omitted/123.
All initial and refreshed ID Tokens are independently signature-verified.

| Completion time | require_auth_time | Node initial/refresh | Current gem initial/refresh |
|---|---|---|---|
| omitted | omitted, false or true | claim absent | claim absent |
| 123 | omitted or false | claim absent | auth_time=123 |
| 123 | true | auth_time=123 | auth_time=123 |

[Reference execution](../validation/node-auth-time.txt),
[gem characterization:1 test /48 assertions](../validation/auth-time-current.txt).
The gem test records current behavior, not an alignment pass. Neither implementation
invents a timestamp when the application omits it, even for require_auth_time=true.
Node's common grant helper copies source.authTime to available claims; its claim
selection, including authorization/claims.js, controls output. The existing gem
id_token_claims emits any supplied context directly. Before changing it, reconcile
explicit claims requests, scope-selected authentication claims and initial/refresh
selection together; do not merely discard the persisted authentication context.
This was an implementation gap, not an accepted adaptation. The subsequent
[authentication claim selection](../authentication-claims.md) implementation now
saves request selection and applies it on initial issuance and refresh. NULL legacy
sources retain their old output contract as a migration boundary.

### Authentication selection correction evidence

The extended reference tests cover18 scenarios each with default and explicit
scope mappings ([default](../validation/node-authentication-claims.txt),
[scope mapping](../validation/node-authentication-claims-scope.txt)); each verifies
both signed initial and refreshed ID Tokens. ACR/AMR support is explicitly configured.
The gem uses stored request selection plus an application scope mapping, without
changing stored auth_time/acr/amr values or permitting account claims to replace them.
[Ruby3.4 three-DB tests](../validation/authentication-claims-matrix.txt) pass13 tests
/951 assertions each, including saved selection across metadata changes, legacy
migration and existing pairwise/Edwards/RAR refresh cases. The earlier
auth-time-current.txt is a pre-correction characterization log.

## default_acr_values and authentication defaults

The pinned reference accepts arrays of configured ACR strings, rejects other
values and unsupported strings, and removes duplicates while preserving first
occurrence order. Empty arrays are valid. Registration and management GET retain
the normalized array ([reference](../validation/node-registration-acr-defaults.txt)).

CIBA registration now follows that contract. Applications accepting this metadata
add a nullable text `default_acr_values` column (JSON array), or override
`oauth_applications_default_acr_values_column`, and configure upstream
`oauth_acr_values_supported`. Missing storage rejects the metadata; invalid
management replacement preserves the whole client and credential. The metadata
column does not configure which ACRs the OP supports.

At request acceptance, omitted acr_values uses the client's defaults in order;
explicit acr_values takes precedence. The selected ACR is exposed to the device
callback through the ordinary request snapshot. An empty default list makes no
selection. Completion still supplies the achieved ACR, which is not inferred
from the requested values. Selection survives later client metadata changes and
refresh. Static registrations store the same JSON array representation.

The reference also selects auth_time when default_max_age is configured, including
zero; the gem now does likewise. In the reference test an old supplied authTime
still produces a token. Neither this output selection nor metadata persistence
proves freshness enforcement. The reference retains max_age in request.params;
the gem subsequently added a saved maximum-age input in its device request
snapshot. See [maximum authentication age](../max-age.md) for request precedence,
normalized zero semantics and migration. Freshness enforcement remains application-owned.

[Reference defaults fixture](../validation/node-authentication-defaults.txt)
verifies18 initial/refresh configurations, including explicit ACR precedence.
[Local tests](../validation/authentication-defaults-current.txt) pass2 tests /147
assertions, including registration rollback, preference order and metadata-change
isolation. Empty request acr_values initially remained stricter; the subsequent correction
below treats an empty string like omission.

Final related DB validation: [Ruby3.4 matrix](../validation/authentication-defaults-matrix.txt)
passes17 tests /1,193 assertions on SQLite, PostgreSQL and MySQL, with no
failures/errors/skips. This is the focused defaults/registration/authentication
selection subset; the earlier385-test full run predates these defaults changes.


### Empty ACR request correction

The gem now treats acr_values="" like omission, matching the pinned reference's
request/default assignment. Registered ordered defaults apply when present;
without defaults, empty input does not select an ACR claim. An explicit nonempty
value still overrides the defaults. No whitespace trimming or changed validation
of other parameters is implied.

Reference evidence covers24 initial/refresh cases each for
[ordinary requests without defaults](../validation/node-empty-acr-default.txt)
and [signed requests with defaults](../validation/node-empty-acr-signed.txt).
The signed fixture supplies a conflicting unsigned outer ACR; it never replaces
the signed empty/omitted value or the registered fallback. The gem regression
covers omitted/empty/explicit input with nil/empty/ordered defaults in both modes.
[Pre-fix rejection](../validation/empty-acr-red.txt),
[final related tests](../validation/empty-acr-final.txt). The intermediate
empty-acr-current.txt has local socket permission errors and is not a passing run.
