# Optional request context

This capability implements the node reference's `request_context` application
validation/storage boundary. It is disabled by default. It does not interpret an
operation, grant business permission, or automatically add a token claim. No new
standard Discovery member or CIBA conformance claim is introduced.

Run an explicit application migration:

```ruby
Rodauth::CibaSupport::Schema.add_request_context(db)
```

It adds a nullable TEXT column to `ciba_requests`. Custom names use `table:` and
`column:`, with the latter also mapped by `ciba_request_columns`. Existing rows
remain null. Then configure:

```ruby
ciba_request_context_enabled true
validate_ciba_request_context do |context, oauth_application:|
  # Application owns syntax, semantics, requiredness and client association.
  unless context.nil? || allowed_context?(context, oauth_application)
    raise Rodauth::CibaSupport::ProtocolError, "invalid_request"
  end
end
```

The callback is required when enabled. It receives an immutable string or nil for
omission after client authentication and account resolution, before request
persistence or device dispatch. Like the reference validation callback and the
gem's binding-message validator, it rejects by raising; returning false alone does
not reject. Unexpected exceptions produce server_error rather than access_denied.
The supplied value must be a nonempty UTF-8 string of at most8192 bytes. These are
gem input bounds, not a generic authorization-details schema.

The validated original string is saved and appears in request/device and
transactional request-hook snapshots. Applications own its meaning, display
escaping, retention and any confidential content. Observation events exclude the
value. It is not copied into consent, refresh sources or token claims; poll-time
replacement cannot change it. Applications needing lasting business restrictions
must attach those to their own saved approval/consent policy.

With signed authentication requests, only the signed parameter is used; an outer
parameter cannot replace it. With the capability disabled, an ordinary form
request's unknown context parameter remains ignored. Do not infer that ignored
input was validated. Upgrade workers and migrate storage before enabling.

The node HTTP fixture tests supplied/omitted values, persistence, rejection before
device dispatch and absence from ID Token claims. Gem tests cover those boundaries,
signed input isolation, explicit migration and callback failure. Installed opaque
and JWT extension smoke includes a signed context reference.
