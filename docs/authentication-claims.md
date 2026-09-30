# Authentication context in CIBA ID Tokens

Approval saves the application's verified `auth_time`, `acr` and `amr`. Saving a
value does not by itself select it for disclosure in a newly accepted request.
Initial and refreshed ID Tokens use the same stored selection:

- `require_auth_time: true` or configured `default_max_age` client metadata selects
  `auth_time` at request acceptance. This is output selection, not freshness enforcement.
- A nonempty `acr_values` request selects `acr`. If omitted or empty, registered
  `default_acr_values` supplies the ordered preferences; the emitted value is the achieved
  application result, not the requested string.
- With `ciba_claims_enabled`, the `claims.id_token` keys `auth_time`, `acr` and `amr`
  select those authentication claims. These are not ordinary account attributes:
  a consent list or an account attribute callback cannot replace their values.
- Applications can additionally map authorized scopes to authentication claims:

```ruby
ciba_authentication_claims_by_scope "openid" => %w[auth_time acr amr]
```

The default mapping is empty. Only the three names above are considered. Scope
selection uses the scopes authorized for the current issuance, including refresh
narrowing. It is application configuration, not a client-supplied mapping.
Client metadata and explicit request selection are saved at acceptance; replacing
client metadata later does not reinterpret an accepted request or refresh source.
Missing authentication values remain absent even if selected. The gem does not
invent a login timestamp, echo a requested ACR as achieved, or verify the truth of
application-provided authentication context.

## Existing development databases

New `Schema.create` and `Schema.create_refresh_tokens` tables include nullable text
`authentication_claims` columns. Existing installations must migrate explicitly
before starting upgraded workers:

```ruby
Rodauth::CibaSupport::Schema.add_authentication_claims(db)
# Only if the refresh source table already exists:
Rodauth::CibaSupport::Schema.add_authentication_claims(db, table: :ciba_refresh_tokens)
```

For renamed request storage, pass `table:` and `column:` and set the matching
`ciba_request_columns` mapping. Startup checks require the request column and,
when refresh is enabled, its refresh-source column. No automatic migration runs.
Upgrade workers together: old workers do not record selection for new requests.
Existing NULL rows retain the previous output contract (all supplied context
claims). New requests store an explicit list, including an empty list. Do not
backfill NULL with an empty list unless changing pending requests' output is
intended. Refresh copies this distinction without losing authentication evidence.

## Evidence and scope

The pinned reference fixture `auth-time.mjs` exercises omitted/false/true client
metadata, omitted/provided time, explicit claims, ACR requests and a configured
scope mapping, with independently verified initial and refreshed ID Tokens.
ACR and AMR support are explicitly configured in the reference; their unconfigured
reference defaults are not inferred to be identical to every application setup.
The gem tests additionally cover metadata replacement after acceptance and legacy
request migration. Browser authorization and UserInfo claim behavior are outside
this change; their existing upstream behavior is preserved.

Validation: [full Ruby4.0.6/SQLite run](validation/authentication-claims-full.txt)
passes385 tests /10,152 assertions with two row-lock skips;
[the Ruby3.4 three-DB subset](validation/authentication-claims-matrix.txt) passes13
tests /951 assertions on each DB. The [installed artifact](validation/authentication-claims-installed.txt)
passes its smoke suite including explicit scope-selected authentication time.
These do not establish every Ruby × DB combination or arbitrary application policies.

See [registration defaults](research/registration-reference-contract.md#default_acr_values-and-authentication-defaults)
for JSON-array storage and supported ACR configuration. The [maximum-age policy input](max-age.md) is now saved independently;
empty-string ACR requests now use the same defaulting as omitted values.
