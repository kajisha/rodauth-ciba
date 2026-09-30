# CIBA maximum authentication age

The gem accepts `max_age` at the backchannel endpoint as a node-oidc-provider
extension. This does not add a CIBA Core conformance requirement.

An explicit request value overrides client `default_max_age`. Omission or an empty
string uses the registered default, if any. Signed requests use only their signed
max_age; an unsigned outer value cannot override or supply it.

The accepted maximum age is saved with the request before device dispatch. The
application receives it through `trigger_ciba_authentication_device` and can read
it later using `ciba_request`:

- `nil`: no maximum age was selected.
- `0`: require fresh authentication.
- A positive integer: maximum authentication age in seconds.

Node retains positive inputs as strings in request.params; zero becomes its
internal `prompt=login`. The Ruby API uses an integer, retaining zero explicitly,
so applications need no second prompt field to distinguish fresh authentication
from no policy. This is an internal representation adaptation, not an HTTP response
change. Client metadata changes after acceptance do not alter the saved policy.
Applications must enforce freshness during authentication; approval does not reject
an old supplied auth_time automatically. Selected max_age causes auth_time to be
selected for ID Token output, but does not invent an authentication time.
Refresh preserves the original authentication claim selection/context and does
not start a new authentication request or reapply current client defaults.

## Parsing and migration

Validation follows the measured Node numeric boundary: a finite, non-negative
safe integer (at most9007199254740991) after numeric conversion. Integral decimal
and exponent representations and unsigned hexadecimal/binary/octal representations
are accepted. Whitespace-only input and negative zero mean zero. Unsupported
syntax, fractional results, negative numbers, nonfinite numbers and arrays are
rejected before saving or dispatching. The gem bounds the input to1024 UTF-8 bytes.

New request tables include nullable BIGINT `max_age`. Existing development schemas
must add it explicitly before upgraded workers start:

```ruby
Rodauth::CibaSupport::Schema.add_request_max_age(db)
```

Pass `table:` / `column:` and configure `ciba_request_columns[:max_age]` for custom
storage. Startup requires this column. Existing requests remain NULL; migration
does not reinterpret them using today's client defaults. This migration is in
addition to the [authentication_claims migration](authentication-claims.md).
No refresh-table max_age column is needed.

## Evidence

The [pinned reference test](../test/reference/full-op/max-age.mjs) checks request
overrides, numeric forms, zero-to-login conversion, invalid values and successful
signed ID Tokens using an application-supplied old authTime. See its
[execution](validation/node-max-age.txt). Gem tests cover saved/frozen callback
policy, later metadata changes, signed input isolation, rejected values, custom
columns and forward migration. No deployment authentication policy is verified.

Validation: [Ruby3.3 / SQLite full suite](validation/max-age-ruby33.txt) passes391
tests /10,418 assertions with two row-lock skips. The [Ruby3.4 three-DB subset](validation/max-age-matrix.txt)
passes22 tests /1,317 assertions on each of SQLite/PostgreSQL/MySQL. Containers
reuse existing dependency images and mount current source read-only.
The [installed artifact smoke](validation/max-age-installed.txt) also passes;
it reuses locally installed dependencies rather than testing network resolution.
