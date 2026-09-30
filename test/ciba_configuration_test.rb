# frozen_string_literal: true
require_relative "test_helper"

class CibaIntegrationTest
  def test_custom_table_and_column_mapping
    @db.drop_table(:ciba_requests)
    mapping = {id: :request_key, account_id: :subject_ref, status: :request_state, auth_req_id_digest: :public_digest, expires_at: :deadline, nonce: :correlation_value, max_age: :maximum_age}
    Rodauth::CibaSupport::Schema.create(@db, table: :custom_requests, columns: mapping)
    @app.plugin(:rodauth) do
      ciba_requests_table :custom_requests
      ciba_request_columns mapping
    end
    response = post("/backchannel-authentication", login_hint: "customer@example.test", scope: "openid", nonce: "custom-nonce", max_age: "60")
    assert_equal 200, response.status
    id = JSON.parse(response.body)["auth_req_id"]
    request_id = @db[:custom_requests].get(:request_key)
    assert_equal @account_id, auth.ciba_request(request_id)[:account_id]
    assert_equal 60, auth.ciba_request(request_id)[:max_age]
    assert_equal 60, @db[:custom_requests].get(:maximum_age)
    auth.approve_ciba_request(request_id, account_id: @account_id)
    response = poll(id)
    assert_equal 200, response.status
    assert_equal "custom-nonce", decode_id_token(response).last.fetch("nonce")
    assert_equal "consumed", @db[:custom_requests].get(:request_state)
  end

  def test_migration_client_metadata_helper
    @db.create_table(:custom_applications) { primary_key :id }
    Rodauth::CibaSupport::Schema.add_client_metadata(@db, table: :custom_applications, column: :delivery)
    assert_includes @db[:custom_applications].columns, :delivery
  end

  def test_dcr_rejects_ciba_but_preserves_other_grant_validation
    @app.plugin(:rodauth) do
      enable :oauth_dynamic_client_registration
      before_register { throw_json_response_error(418, "existing_registration_handler") }
    end
    params = {"redirect_uris" => ["https://rp.example.test/callback"], "client_name" => "RP", "grant_types" => [GRANT]}
    response = post("/register", {}, "CONTENT_TYPE" => "application/json", input: JSON.generate(params))
    assert_error response, "invalid_client_metadata"
    params["grant_types"] = ["authorization_code"]
    response = post("/register", {}, "CONTENT_TYPE" => "application/json", input: JSON.generate(params))
    assert_equal 418, response.status, response.body
  end

  def test_invalid_utf8_and_oversized_body_are_rejected
    ["scope=openid&login_hint=%FF", "scope=openid&login_hint=%XX", "scope=openid&unknown=#{'a' * 17_000}"].each do |body|
      response = post("/backchannel-authentication", {}, "CONTENT_TYPE" => "application/x-www-form-urlencoded", input: body)
      assert_error response, "invalid_request"
    end
  end

  def test_id_token_audience_is_client_even_with_different_access_audience
    @app.plugin(:rodauth) { oauth_jwt_audience { "https://resource.example.test" } }
    id = accept_request
    approve(id)
    _, claims = decode_id_token(poll(id))
    assert_equal "support", claims["aud"]
  end

  def test_schema_rejects_duplicate_public_identifier
    accept_request
    row = @db[:ciba_requests].first.reject { |key, _| key == :id }
    assert_raises(Sequel::UniqueConstraintViolation) { @db[:ciba_requests].insert(row) }
  end

  def test_push_client_cannot_redeem_existing_ciba_request
    id = accept_request
    approve(id)
    original = @db[:ciba_requests].first
    @db[:oauth_applications].update(backchannel_token_delivery_mode: "push")
    assert_error poll(id), "unauthorized_client"
    assert_equal original, @db[:ciba_requests].first
    assert_equal 0, @db[:oauth_grants].count
  end

  def test_unavailable_or_unsupported_client_metadata_is_rejected
    [{subject_type: "pairwise"}, {backchannel_token_delivery_mode: "push"}, {backchannel_token_delivery_mode: nil}, {backchannel_token_delivery_mode: "poll ping"}, {grant_types: "authorization_code"}].each do |changes|
      original = @db[:oauth_applications].first
      @db[:oauth_applications].update(changes)
      response = post("/backchannel-authentication", login_hint: "customer@example.test", scope: "openid")
      assert_error response, "unauthorized_client"
      @db[:oauth_applications].where(id: original[:id]).update(original)
    end
    assert_equal 0, @db[:ciba_requests].count
  end
end

class CibaIntegrationTest
  def test_unsigned_id_token_client_is_rejected
    @db.alter_table(:oauth_applications) { add_column :id_token_signed_response_alg, String }
    @db[:oauth_applications].update(id_token_signed_response_alg: "none")
    response = post("/backchannel-authentication", login_hint: "customer@example.test", scope: "openid")
    assert_error response, "unauthorized_client"
    assert_equal 0, @db[:ciba_requests].count
  end

  def test_explicit_migration_up_and_down
    require "fileutils"
    Sequel.extension :migration
    @db.drop_table(:ciba_requests, :ciba_client_assertions)
    @db.alter_table(:oauth_grants) { drop_foreign_key :ciba_grant_id }
    @db.drop_table(:ciba_grants)
    @db.alter_table(:oauth_applications) { drop_column :backchannel_token_delivery_mode }
    Dir.mktmpdir("ciba-migration-") do |directory|
      FileUtils.cp(File.expand_path("../examples/migration.rb", __dir__), File.join(directory, "001_ciba.rb"))
      Sequel::Migrator.run(@db, directory)
      assert @db.table_exists?(:ciba_requests)
      assert @db.table_exists?(:ciba_client_assertions)
      assert @db.table_exists?(:ciba_grants)
      assert_includes @db[:oauth_grants].columns, :ciba_grant_id
      assert_includes @db[:oauth_applications].columns, :backchannel_token_delivery_mode
      Sequel::Migrator.run(@db, directory, target: 0)
      refute @db.table_exists?(:ciba_requests)
      refute @db.table_exists?(:ciba_client_assertions)
      refute @db.table_exists?(:ciba_grants)
      refute_includes @db[:oauth_grants].columns, :ciba_grant_id
      assert @db.table_exists?(:accounts)
    end
  end
end

class CibaIntegrationTest
  def configure_assertion_client
    @db.alter_table(:oauth_applications) { add_column :jwks, String, text: true }
    @db[:oauth_applications].update(token_endpoint_auth_method: "private_key_jwt",
      jwks: JSON.generate(keys: [JWT::JWK.new(KEY.public_key).export]))
    @app.plugin(:rodauth) { enable :oauth_jwt_bearer_grant }
  end

  def assertion_params(audience, key: KEY)
    {client_id: "support", client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: JWT.encode({iss: "support", sub: "support", aud: audience,
        exp: Time.now.to_i + 60, iat: Time.now.to_i, jti: SecureRandom.uuid}, key, "RS256",
        kid: JWT::JWK.new(key).kid)}
  end

  def test_upstream_jwt_authentication_coexists_with_ciba_and_discovery
    configure_assertion_client
    metadata = JSON.parse(Rack::MockRequest.new(@app).get("https://op.example.test/.well-known/openid-configuration").body)
    assert_includes metadata.fetch("token_endpoint_auth_methods_supported"), "private_key_jwt"
    ["https://op.example.test", "https://op.example.test/token", "https://op.example.test/backchannel-authentication"].each do |audience|
      response = post("/backchannel-authentication", assertion_params(audience).merge(
        login_hint: "customer@example.test", scope: "openid"), "HTTP_AUTHORIZATION" => nil)
      assert_equal 200, response.status, response.body
      id = JSON.parse(response.body).fetch("auth_req_id")
      approve(id)
      result = post("/token", assertion_params("https://op.example.test/token").merge(
        grant_type: GRANT, auth_req_id: id), "HTTP_AUTHORIZATION" => nil)
      assert_equal 200, result.status, result.body
      decode_id_token(result)
    end
    @db[:oauth_grants].insert(account_id: @account_id, oauth_application_id: @client_id,
      type: "authorization_code", code: "jwt-code", scopes: "openid", expires_in: Time.now + 60,
      redirect_uri: "https://rp.example.test/callback")
    result = post("/token", assertion_params("https://op.example.test/token").merge(
      grant_type: "authorization_code", code: "jwt-code", redirect_uri: "https://rp.example.test/callback"),
      "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, result.status, result.body
    @db[:oauth_applications].update(token_endpoint_auth_method: "client_secret_basic")
    id = accept_request
    approve(id)
    assert_equal 200, poll(id).status
  end

  def test_ciba_jwt_authentication_rejects_wrong_audience_signature_and_mixed_credentials
    configure_assertion_client
    [assertion_params("https://wrong.example.test"),
     assertion_params("https://op.example.test", key: OpenSSL::PKey::RSA.generate(2048))].each do |params|
      response = post("/backchannel-authentication", params.merge(login_hint: "customer@example.test", scope: "openid"),
        "HTTP_AUTHORIZATION" => nil)
      assert_equal 401, response.status, response.body
    end
    response = post("/backchannel-authentication", assertion_params("https://op.example.test").merge(
      login_hint: "customer@example.test", scope: "openid"))
    assert_error response, "invalid_request"
    assert_equal 0, @db[:ciba_requests].count
  end

  def test_upstream_client_secret_jwt_works_for_ciba
    @app.plugin(:rodauth) { enable :oauth_jwt_bearer_grant }
    secret = "s" * 32
    @db[:oauth_applications].update(token_endpoint_auth_method: "client_secret_jwt", client_secret: secret)
    make_assertion = lambda do |audience|
      {client_id: "support", client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: JWT.encode({iss: "support", sub: "support", aud: audience,
          exp: Time.now.to_i + 60, jti: SecureRandom.uuid}, secret, "HS256")}
    end
    response = post("/backchannel-authentication", make_assertion.call("https://op.example.test").merge(
      login_hint: "customer@example.test", scope: "openid"), "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body).fetch("auth_req_id")
    approve(id)
    response = post("/token", make_assertion.call("https://op.example.test/token").merge(
      grant_type: GRANT, auth_req_id: id), "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, response.status, response.body
  end

  def test_public_clients_can_exist_but_cannot_use_ciba
    @app.plugin(:rodauth) { oauth_token_endpoint_auth_methods_supported %w[client_secret_basic client_secret_post none] }
    @db[:oauth_applications].update(token_endpoint_auth_method: "none")
    response = post("/backchannel-authentication", {client_id: "support", login_hint: "customer@example.test", scope: "openid"},
      "HTTP_AUTHORIZATION" => nil)
    assert_error response, "unauthorized_client"
    assert_equal 0, @db[:ciba_requests].count
  end
end
