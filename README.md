# rodauth-ciba

CIBA OpenID Provider extension for **rodauth-oauth**, with default poll and optional ping. Version0.1.0 release candidate; not yet published to RubyGems.

It adds a backchannel authentication endpoint, Discovery metadata, Ruby approval/denial APIs, transactional hooks and post-commit observation events. Your app handles customer authentication, consent UI, notification transport, business authorization and any later delegation.

## Supported scope

- Poll delivery, `login_hint`, optional [login_hint_token](docs/login-hint-token.md) and [id_token_hint](docs/id-token-hint.md), public subject identifiers, static CIBA client registration.
- Upstream confidential client authentication; basic/post and private-key/shared-secret JWT methods have integration coverage. Optional [mTLS](docs/research/mtls-reference-contract.md) adds explicit application trust callbacks, certificate binding, dynamic registration and verified TLS integration tests.
- Signed ID Token and access token; CIBA refresh tokens are disabled by default. An [experimental refresh implementation](docs/refresh-tokens.md) is in progress and is not yet release-ready.
- Optional [DPoP](docs/research/dpop-reference-contract.md) covers token binding, proof/nonce validation, replay handling, UserInfo and introspection. The documented configuration and deployment limits apply.
- Same-database request storage with Sequel, explicit migration, bounded cleanup/recovery lookup.
- Optional [explicit claim consent](docs/claims.md) and [resource indicators](docs/resources.md), each with its own migration and activation flag. Their documented limitations apply.
- Optional [authorization details](docs/authorization-details.md) with mandatory application policy and separate requested/approved/issued data.
- Optional [request context](docs/request-context.md) with application validation and request-only storage.

Optional [signed authentication requests](docs/signed-requests.md) use registered client keys and separate client authentication. Optional [user codes](docs/user-code.md) require an application validation callback. Optional [ping](docs/ping.md) sends after commit and exposes explicit retry. No push or encrypted ID Token hints. Optional [CIBA pairwise subjects](docs/pairwise.md) are under integration and are not release-ready. [CIBA dynamic registration](docs/research/registration-reference-contract.md) is under development behind an opt-in flag; its basic installed-package lifecycle is verified, while additional client-auth combinations and metadata validation remain incomplete. The extension preserves OP-wide authentication settings; CIBA requires a registered confidential client. Existing non-CIBA authorization-code behavior and registration validation are delegated to upstream; management responses suppress stored credential hashes. This project is not OpenID Certified.

## Install

Ruby>=3.3 is required. Until a registry release exists, build from this checkout:

```sh
bundle install
gem build rodauth-ciba.gemspec
gem install ./rodauth-ciba-0.1.0.gem
```

The initial dependency bounds are intentionally narrow: rodauth-oauth1.7.0, Rodauth2.28.x, Sequel5.108.x and JWT3.3.x. Your application supplies its DB adapter and existing Rodauth/OAuth schema.

## Integrate

1. Copy [the migration](examples/migration.rb) into your app's Sequel migrations after its account/application/grant migrations and run it explicitly. See [migration customization](docs/operations.md).
2. Require `rodauth/ciba`, enable `:ciba`, configure signing keys, a stable issuer/base URL, your login-hint resolver and AD initiation callback. Request lifetime and maximum default to 600 seconds; override them for your deployment.
3. Statically provision a confidential OAuth application with the CIBA grant, `backchannel_token_delivery_mode: "poll"`, public subjects and appropriate scopes.
4. Expose Discovery and Rodauth routes. Implement `trigger_ciba_authentication_device` to start customer authentication/approval, then call the Ruby completion API after your app verifies customer authentication and consent.

```ruby
require "rodauth/ciba"

plugin :rodauth do
  enable :ciba
  # Existing db, account/OAuth schema, signing keys and issuer configuration here.
  ciba_request_lifetime 300
  ciba_max_request_lifetime 600
  resolve_ciba_login_hint do |hint, oauth_application:|
    # Example only: enforce tenant/client policy for your application.
    db[:accounts].where(email: hint).get(:id)
  end
  trigger_ciba_authentication_device do |request|
    # Start your app-owned approval flow using request[:id].
    # Returning permits the success response; exceptions produce server_error.
  end
end
```

The app completes a request using its **internal integer ID**, fixed local customer ID and verified authentication context:

```ruby
# After verifying that this customer may approve this request:
grant = rodauth.create_ciba_grant(account_id: customer_id,
  oauth_application_id: client_application_id, scopes: approved_scopes)
rodauth.backchannel_result(request_id, grant,
  auth_time: actual_authentication_time.to_i, acr: "urn:example:mfa", amr: ["pwd", "otp"])
# Or report refusal after the same application-side identity/authority checks:
rodauth.backchannel_result(request_id,
  Rodauth::CibaSupport::ProtocolError.new("access_denied"))
```

Keep the saved Grant ID for retries; wrap creation and completion in an application DB transaction if both must commit together. The demo shows this pattern. The convenience `approve_ciba_request` / `deny_ciba_request` APIs remain available.

Identical completion retries return `:already_completed`; conflicting decisions are rejected. Token collection succeeds only once. Public `auth_req_id` possession is not approval authority.

[Full configuration/API](docs/api.md) · [Deployment/operating boundaries](docs/operations.md) · [Protocol-to-test mapping](docs/protocol-coverage.md)

## Try the local demo

The sample simulates a fixed customer; it does not authenticate a real user. It binds to127.0.0.1, uses disposable data and explicitly enables local HTTP. Do not deploy it as an approval service.

```sh
bundle exec ruby examples/server.rb
# In another terminal:
bundle exec ruby examples/client.rb
```

Open http://127.0.0.1:9292/ and approve or deny the request. The client polls and verifies the returned ID Token using the OP's published keys.

## Test

```sh
bundle exec ruby test/run.rb       # local SQLite
bundle exec ruby -Ilib examples/smoke.rb
bundle exec ruby -Ilib examples/extensions_smoke.rb # optional claims/resource flows
ruby bin/verify-package            # build, install outside checkout, run all smoke flows
./bin/test-databases --seed 3363    # Docker: SQLite, PostgreSQL, MySQL
./bin/test-rubies                  # Docker: Ruby 3.3 and 3.4 with SQLite
```

The Docker runner builds the Ruby image, waits for database health, runs the same suite on each DB and removes its containers/network on exit. DB ports are not published. Data is on tmpfs; each test owns a random database. Only images/build cache remain. `pg` and `mysql2` are an optional Bundler group enabled inside Docker. The macOS/mise equivalent is `mise exec ruby -- ruby test/run.rb`.

[Release validation](docs/release-validation.md) records actual tested versions and limitations. GitHub Actions contains a Ruby matrix and DB job, but a configured workflow is not evidence of a hosted CI run.

## License

MIT. Copyright2026 rodauth-ciba contributors. Dependencies retain their own licenses.
