# Optional user codes

User-code registration, storage, comparison, rate limiting and recovery belong
to the application. The gem implements the protocol boundary and does not store
the supplied code. It is separate from customer authentication and approval.

The application must use a code distinct from the user's OP login password.
It should provide a way for the user to change that code. Code enrollment and
change UI remain application responsibilities; a callback accepting a fixture
string does not demonstrate them. The CIBA client must ask for the code for each
flow and must not store it. The gem's removal of the code from its own records
does not prove client compliance. These responsibilities follow
[CIBA Core §7.1.2](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#user_code).

Run `Rodauth::CibaSupport::Schema.add_user_code(db)` once to add nullable
`backchannel_user_code_parameter` to `oauth_applications`. Existing requests and
grants are unchanged. Custom schemas can specify `table:`/`column:` and configure
`oauth_applications_backchannel_user_code_parameter_column` to match.

Enable `ciba_user_code_enabled true` and implement:

```ruby
verify_ciba_user_code do |code, account_id:, oauth_application:|
  # Application policy decides whether this client/user requires a code.
  # Raise Rodauth::CibaSupport::ProtocolError, "missing_user_code" if required but absent.
  # Return true only after accepting the code or explicitly permitting omission.
end
```

Enabling without an implementation is a configuration error. The callback runs
after hint resolution and account eligibility, before DB insertion, transaction
hooks and device dispatch. It receives nil for omission; otherwise a nonempty
UTF-8 string of at most 1024 bytes. Invalid input shapes return invalid_request.
Only literal true accepts the request: false/nil returns invalid_user_code.
Applications may raise ProtocolError with missing_user_code or invalid_user_code;
unexpected exceptions return server_error and do not create a request.

Client metadata is available to the callback, but the gem does not decide the
application's per-user exceptions. A client declaring user-code support is
ineligible while the feature is disabled. With the feature enabled, the callback
runs for every eligible client, even when the code is omitted or client metadata
is false/nil; the application must explicitly accept that case. Discovery's
backchannel_user_code_parameter_supported reflects the feature flag.

The raw value is removed before request persistence, hooks, device snapshots
and observation events. Original HTTP bodies and application logging remain
the application's responsibility. With signed requests, only the inner code
is used; an outer code cannot fill in or override it. A successful code check
still creates pending work requiring new customer approval. Poll does not rerun
the code check or inherit approval from it.

## Reference comparison and evidence

node-oidc-provider 9.12.2 resolves the account and then calls
`features.ciba.verifyUserCode(ctx, account, code)`. Its default callback throws
until replaced; application policy determines omission/validation errors. The
complete HTTP reference now has a client-specific test policy: missing/wrong
code returns the corresponding error before device dispatch; correct code
remains pending until approval and produces a verified ID Token afterwards.
[Harness](../test/reference/full-op/lifecycle.mjs),
[reference log](validation/node-full-op-lts.txt).

The gem keeps this responsibility boundary but requires explicit true instead
of node's successful callback completion, bounds input size, and removes the
code from persisted snapshots. Those are deliberate API/storage differences.
The test/demo policy uses a fixed fixture string; it is not a production code
verifier. No production password hashing, account recovery, throttling or
brute-force defense is provided by these fixtures.

[Gem tests](validation/user-code-tests.txt) cover omission, rejection, unknown
accounts, no persistence/dispatch on failure, callback exceptions, metadata,
signed-request isolation and new approval. The installed-gem extension example
combines codes with signed requests, hints, claims, resources and RAR.
