# frozen_string_literal: true
require_relative "test_helper"
require "minitest/mock"

# Integration contract measured against the published node provider. These tests
# deliberately exercise the real upstream registration routes and persistence.
class CibaIntegrationTest
  def configure_dynamic_registration
    @db.alter_table(:oauth_applications) do
      add_column :name, String
      add_column :redirect_uri, String, text: true
      add_column :response_types, String
      add_column :registration_access_token, String
    end
    Rodauth::CibaSupport::Schema.add_registration_token_digest(@db)
    @app.plugin(:rodauth) do
      enable :oauth_dynamic_client_registration
      ciba_dynamic_client_registration_enabled true
      before_register do
        authorization_required unless request.env["HTTP_AUTHORIZATION"] == "Bearer registration-test-only"
      end
    end
    @app.route do |r|
      rodauth.load_openid_configuration_route
      rodauth.load_oauth_server_metadata_route
      r.rodauth
      rodauth.load_registration_client_uri_routes
    end
  end

  def registration_params
    {"grant_types" => [GRANT], "response_types" => [], "scope" => "openid",
     "token_endpoint_auth_method" => "client_secret_basic", "backchannel_token_delivery_mode" => "poll"}
  end

  def register(params = registration_params, bearer: "registration-test-only")
    post("/register", {}, "HTTP_AUTHORIZATION" => "Bearer #{bearer}",
      "CONTENT_TYPE" => "application/json", input: JSON.generate(params))
  end

  def test_registration_default_acr_values_validates_and_preserves_order
    configure_dynamic_registration
    @app.plugin(:rodauth) { oauth_acr_values_supported { %w[first second] } }
    assert_error register(registration_params.merge("default_acr_values" => ["first"])), "invalid_client_metadata"
    @db.alter_table(:oauth_applications) { add_column :default_acr_values, String, text: true }
    ["first", true, {}, [1], ["unknown"]].each do |value|
      count = @db[:oauth_applications].count
      assert_error register(registration_params.merge("default_acr_values" => value)), "invalid_client_metadata"
      assert_equal count, @db[:oauth_applications].count
    end
    [[], %w[second first second]].each do |value|
      response = register(registration_params.merge("default_acr_values" => value))
      assert_equal 201, response.status, response.body
      client = JSON.parse(response.body)
      assert_equal value.uniq, client.fetch("default_acr_values")
      saved = @db[:oauth_applications].where(client_id: client.fetch("client_id")).first
      assert_equal value.uniq, JSON.parse(saved.fetch(:default_acr_values))
      rejected = Rack::MockRequest.new(@app).put(client.fetch("registration_client_uri"),
        "HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}",
        "CONTENT_TYPE" => "application/json", input: JSON.generate(registration_params.merge(
          "client_id" => client.fetch("client_id"), "default_acr_values" => ["unknown"])))
      assert_error rejected, "invalid_client_metadata"
      assert_equal saved, @db[:oauth_applications].where(id: saved.fetch(:id)).first
      read = Rack::MockRequest.new(@app).get(client.fetch("registration_client_uri"),
        "HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}")
      assert_equal 200, read.status, read.body
      assert_equal value.uniq, JSON.parse(read.body).fetch("default_acr_values")
    end
  end

  def test_registration_require_auth_time_validates_boolean_and_preserves_storage
    configure_dynamic_registration
    assert_error register(registration_params.merge("require_auth_time" => true)), "invalid_client_metadata"
    @db.alter_table(:oauth_applications) { add_column :require_auth_time, TrueClass }
    ["true", "false", 0, 1, [], {}].each do |value|
      count = @db[:oauth_applications].count
      assert_error register(registration_params.merge("require_auth_time" => value)), "invalid_client_metadata"
      assert_equal count, @db[:oauth_applications].count
    end
    [true, false].each do |value|
      response = register(registration_params.merge("require_auth_time" => value))
      assert_equal 201, response.status, response.body
      client = JSON.parse(response.body)
      assert_equal value, client.fetch("require_auth_time")
      saved = @db[:oauth_applications].where(client_id: client.fetch("client_id")).first
      assert_equal value, saved.fetch(:require_auth_time)
      rejected = Rack::MockRequest.new(@app).put(client.fetch("registration_client_uri"),
        "HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}",
        "CONTENT_TYPE" => "application/json", input: JSON.generate(registration_params.merge(
          "client_id" => client.fetch("client_id"), "require_auth_time" => "false")))
      assert_error rejected, "invalid_client_metadata"
      assert_equal saved, @db[:oauth_applications].where(id: saved.fetch(:id)).first
      read = Rack::MockRequest.new(@app).get(client.fetch("registration_client_uri"),
        "HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}")
      assert_equal 200, read.status, read.body
      assert_equal value, JSON.parse(read.body).fetch("require_auth_time")
    end
  end

  def test_registration_default_max_age_requires_nonnegative_safe_integer
    configure_dynamic_registration
    assert_error register(registration_params.merge("default_max_age" => 60)), "invalid_client_metadata"
    @db.alter_table(:oauth_applications) { add_column :default_max_age, :bigint }
    [-1, 1.5, "60", true, [], {}, 9_007_199_254_740_992].each do |value|
      count = @db[:oauth_applications].count
      assert_error register(registration_params.merge("default_max_age" => value)), "invalid_client_metadata"
      assert_equal count, @db[:oauth_applications].count
    end
    [0, 1.0, 60, 9_007_199_254_740_991].each do |value|
      response = register(registration_params.merge("default_max_age" => value))
      assert_equal 201, response.status, response.body
      client = JSON.parse(response.body)
      assert_equal value, client.fetch("default_max_age")
      saved = @db[:oauth_applications].where(client_id: client.fetch("client_id")).first
      assert_equal value, saved.fetch(:default_max_age)
      assert_instance_of Integer, saved.fetch(:default_max_age)
      rejected = Rack::MockRequest.new(@app).put(client.fetch("registration_client_uri"),
        "HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}",
        "CONTENT_TYPE" => "application/json", input: JSON.generate(registration_params.merge(
          "client_id" => client.fetch("client_id"), "default_max_age" => -1)))
      assert_error rejected, "invalid_client_metadata"
      assert_equal saved, @db[:oauth_applications].where(id: saved.fetch(:id)).first
      read = Rack::MockRequest.new(@app).get(client.fetch("registration_client_uri"),
        "HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}")
      assert_equal 200, read.status, read.body
      assert_equal value, JSON.parse(read.body).fetch("default_max_age")
    end
  end

  def test_dynamic_poll_registration_without_browser_metadata_and_complete_flow
    configure_dynamic_registration
    response = register
    assert_equal 201, response.status, response.body
    client = JSON.parse(response.body)
    assert_equal [], client.fetch("redirect_uris")
    assert_equal [], client.fetch("response_types")
    assert_equal "poll", client.fetch("backchannel_token_delivery_mode")
    assert client.fetch("client_secret").is_a?(String)
    credentials = {"HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64("#{client.fetch('client_id')}:#{client.fetch('client_secret')}")}"
    }
    started = post("/backchannel-authentication", {scope: "openid", login_hint: "customer@example.test"}, credentials)
    assert_equal 200, started.status, started.body
    id = JSON.parse(started.body).fetch("auth_req_id")
    approve(id)
    issued = poll(id, credentials)
    assert_equal 200, issued.status, issued.body
    claims, = JWT.decode(JSON.parse(issued.body).fetch("id_token"), KEY.public_key, true,
      algorithms: ["RS256"], verify_iss: true, iss: "https://op.example.test",
      verify_aud: true, aud: client.fetch("client_id"))
    assert_equal client.fetch("client_id"), claims.fetch("aud")
  end

  def test_ciba_registration_rejects_assertion_type_as_authentication_method
    configure_dynamic_registration
    @app.plugin(:rodauth) { enable :oauth_jwt_bearer_grant }
    assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    discovery = JSON.parse(Rack::MockRequest.new(@app).get("https://op.example.test/.well-known/openid-configuration").body)
    oauth = JSON.parse(Rack::MockRequest.new(@app).get("https://op.example.test/.well-known/oauth-authorization-server").body)
    advertised = discovery.fetch("token_endpoint_auth_methods_supported")
    refute_includes advertised, assertion_type
    assert_equal advertised, oauth.fetch("token_endpoint_auth_methods_supported")
    # Metadata normalization does not replace upstream authentication dispatch.
    underlying = auth.send(:oauth_token_endpoint_auth_methods_supported)
    assert_includes underlying, assertion_type
    assert_equal underlying - [assertion_type], advertised
    before = @db[:oauth_applications].count
    assert_error register(registration_params.merge("token_endpoint_auth_method" => assertion_type)), "invalid_client_metadata"
    assert_equal before, @db[:oauth_applications].count
    assert_equal 201, register.status
  end

  def test_invalid_registration_metadata_does_not_persist
    configure_dynamic_registration
    [
      {"backchannel_token_delivery_mode" => nil},
      {"backchannel_token_delivery_mode" => "push"},
      {"backchannel_token_delivery_mode" => "ping"},
      {"backchannel_user_code_parameter" => "true"},
      {"backchannel_user_code_parameter" => true},
      {"backchannel_authentication_request_signing_alg" => "RS256"},
      {"subject_type" => "pairwise"},
      {"token_endpoint_auth_method" => "none"}
    ].each do |changes|
      before = @db[:oauth_applications].count
      assert_error register(registration_params.merge(changes)), "invalid_client_metadata"
      assert_equal before, @db[:oauth_applications].count
    end
  end

  def test_dynamic_private_key_client_authentication_and_management_key_replacement
    configure_dynamic_registration
    @db.alter_table(:oauth_applications) { add_column :jwks, String, text: true }
    @app.plugin(:rodauth) { enable :oauth_jwt_bearer_grant }
    key = OpenSSL::PKey::RSA.generate(2048)
    replacement = OpenSSL::PKey::RSA.generate(2048)
    params = registration_params.merge("token_endpoint_auth_method" => "private_key_jwt",
      "jwks" => {"keys" => [JWT::JWK.new(key.public_key).export]})
    response = register(params)
    assert_equal 201, response.status, response.body
    client = JSON.parse(response.body)
    assertion = lambda do |signing_key, audience = "https://op.example.test"|
      {client_id: client.fetch("client_id"),
       client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
       client_assertion: JWT.encode({iss: client.fetch("client_id"), sub: client.fetch("client_id"),
         aud: audience, exp: Time.now.to_i + 60, iat: Time.now.to_i, jti: SecureRandom.uuid},
         signing_key, "RS256", kid: JWT::JWK.new(signing_key).kid)}
    end
    start = lambda do |auth_params|
      post("/backchannel-authentication", auth_params.merge(scope: "openid", login_hint: "customer@example.test"),
        "HTTP_AUTHORIZATION" => nil)
    end
    [assertion.call(replacement), assertion.call(key, "https://wrong.example.test")].each do |invalid|
      assert_equal "invalid_client", JSON.parse(start.call(invalid).body).fetch("error")
    end
    assert_equal 0, @db[:ciba_requests].count
    auth_params = assertion.call(key)
    response = start.call(auth_params)
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body).fetch("auth_req_id")
    assert_equal "invalid_client", JSON.parse(start.call(auth_params).body).fetch("error")
    approve(id)
    response = post("/token", assertion.call(key, "https://wrong.example.test").merge(
      grant_type: GRANT, auth_req_id: id), "HTTP_AUTHORIZATION" => nil)
    assert_equal 401, response.status, response.body
    assert_equal "invalid_client", JSON.parse(response.body).fetch("error")
    response = post("/token", assertion.call(key).merge(grant_type: GRANT, auth_req_id: id), "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, response.status, response.body
    JWT.decode(JSON.parse(response.body).fetch("id_token"), KEY.public_key, true,
      algorithms: ["RS256"], verify_aud: true, aud: client.fetch("client_id"))
    response = Rack::MockRequest.new(@app).put(client.fetch("registration_client_uri"),
      "HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}",
      "CONTENT_TYPE" => "application/json", input: JSON.generate(params.merge(
        "client_id" => client.fetch("client_id"), "jwks" => {"keys" => [JWT::JWK.new(replacement.public_key).export]})))
    assert_equal 200, response.status, response.body
    assert_equal "invalid_client", JSON.parse(start.call(assertion.call(key)).body).fetch("error")
    response = start.call(assertion.call(replacement))
    assert_equal 200, response.status, response.body
  end

  def test_dynamic_client_auth_signing_algorithm_is_validated_and_enforced
    configure_dynamic_registration
    @db.alter_table(:oauth_applications) do
      add_column :jwks, String, text: true
      add_column :token_endpoint_auth_signing_alg, String
    end
    @app.plugin(:rodauth) do
      enable :oauth_jwt_bearer_grant
      oauth_jwt_keys("RS256" => KEY, "RS512" => KEY)
      oauth_jwt_public_keys("RS256" => KEY.public_key, "RS512" => KEY.public_key)
    end
    keys = %w[RS256 RS512].map do |algorithm|
      JWT::JWK.new(KEY.public_key).export.merge(alg: algorithm, use: "sig", kid: algorithm)
    end
    params = registration_params.merge("token_endpoint_auth_method" => "private_key_jwt",
      "token_endpoint_auth_signing_alg" => "RS512", "jwks" => {"keys" => keys})
    ["none", "HS256", "RS384", "unknown", 1, ["RS256"]].each do |algorithm|
      count = @db[:oauth_applications].count
      assert_error register(params.merge("token_endpoint_auth_signing_alg" => algorithm)), "invalid_client_metadata"
      assert_equal count, @db[:oauth_applications].count
    end
    assert_error register(params.merge("token_endpoint_auth_method" => "client_secret_basic")), "invalid_client_metadata"
    response = register(params)
    assert_equal 201, response.status, response.body
    client = JSON.parse(response.body)
    assert_equal "RS512", client.fetch("token_endpoint_auth_signing_alg")
    %w[RS256 RS512].each do |algorithm|
      assertion = JWT.encode({iss: client.fetch("client_id"), sub: client.fetch("client_id"),
        aud: "https://op.example.test", exp: Time.now.to_i + 60, jti: SecureRandom.uuid}, KEY, algorithm, kid: algorithm)
      response = post("/backchannel-authentication", {scope: "openid", login_hint: "customer@example.test",
        client_id: client.fetch("client_id"), client_assertion: assertion,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "HTTP_AUTHORIZATION" => nil)
      assert_equal(algorithm == "RS512" ? 200 : 401, response.status, response.body)
    end
    assert_equal 1, @db[:ciba_requests].count
  end

  def test_registration_authentication_still_required
    configure_dynamic_registration
    before = @db[:oauth_applications].count
    response = register(bearer: "wrong")
    assert_equal 401, response.status, response.body
    assert_equal before, @db[:oauth_applications].count
  end

  def test_dynamic_registration_rejects_malformed_or_private_jwks_without_persistence
    configure_dynamic_registration
    @db.alter_table(:oauth_applications) { add_column :jwks, String, text: true }
    @app.plugin(:rodauth) { enable :oauth_jwt_bearer_grant }
    public_key = JWT::JWK.new(KEY.public_key).export.transform_keys(&:to_s)
    invalid = [{}, {"keys" => nil}, {"keys" => {}}, {"keys" => [nil]},
      {"keys" => [{"kty" => "oct", "k" => "c2VjcmV0"}]},
      {"keys" => [public_key.merge("n" => "")]},
      {"keys" => [public_key.merge("kid" => 1)]},
      {"keys" => [public_key.merge("x5c" => [1])]}]
    %w[d p q dp dq qi oth].each { |field| invalid << {"keys" => [public_key.merge(field => "private-fixture")]} }
    invalid.each do |jwks|
      count = @db[:oauth_applications].count
      assert_error register(registration_params.merge("token_endpoint_auth_method" => "private_key_jwt", "jwks" => jwks)), "invalid_client_metadata"
      assert_equal count, @db[:oauth_applications].count
    end
    # Node accepts an empty set at registration; it cannot authenticate a client.
    response = register(registration_params.merge("token_endpoint_auth_method" => "private_key_jwt", "jwks" => {"keys" => []}))
    assert_equal 201, response.status, response.body
    client = JSON.parse(response.body)
    before = @db[:oauth_applications].where(client_id: client.fetch("client_id")).first
    response = Rack::MockRequest.new(@app).put(client.fetch("registration_client_uri"),
      "HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}",
      "CONTENT_TYPE" => "application/json", input: JSON.generate(registration_params.merge(
        "client_id" => client.fetch("client_id"), "token_endpoint_auth_method" => "private_key_jwt",
        "jwks" => {"keys" => [public_key.merge("d" => "private-fixture")]})))
    assert_error response, "invalid_client_metadata"
    assert_equal before, @db[:oauth_applications].where(client_id: client.fetch("client_id")).first
    assert_equal 200, Rack::MockRequest.new(@app).get(client.fetch("registration_client_uri"),
      "HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}").status
  end

  def test_update_cannot_change_existing_ciba_subject_type_without_repeating_grant_type
    configure_dynamic_registration
    @db[:oauth_applications].where(id: @client_id).update(
      registration_access_token: BCrypt::Password.create("management-test-only", cost: 4).to_s)
    before = @db[:oauth_applications].where(id: @client_id).first
    response = Rack::MockRequest.new(@app).put("https://op.example.test/register/support",
      "HTTP_AUTHORIZATION" => "Bearer management-test-only", "CONTENT_TYPE" => "application/json",
      input: JSON.generate(subject_type: "pairwise"))
    assert_error response, "invalid_request"
    assert_equal before, @db[:oauth_applications].where(id: @client_id).first
  end

  def test_non_ciba_registration_keeps_upstream_required_fields
    configure_dynamic_registration
    response = register({"grant_types" => ["authorization_code"]})
    assert_error response, "invalid_client_metadata"
    response = register({"grant_types" => ["authorization_code"], "response_types" => ["code"],
      "client_name" => "Browser client", "redirect_uris" => ["https://rp.example.test/callback"]})
    assert_equal 201, response.status, response.body
    client = JSON.parse(response.body)
    assert_equal "Browser client", client.fetch("client_name")
    assert_equal ["code"], client.fetch("response_types")
  end

  def test_valid_existing_client_update_and_discovery
    configure_dynamic_registration
    @db[:oauth_applications].where(id: @client_id).update(
      registration_access_token: BCrypt::Password.create("management-test-only", cost: 4).to_s)
    response = Rack::MockRequest.new(@app).put("https://op.example.test/register/support",
      "HTTP_AUTHORIZATION" => "Bearer management-test-only", "CONTENT_TYPE" => "application/json",
      input: JSON.generate(registration_params.merge("client_id" => "support", "client_name" => "Updated support client")))
    assert_equal 200, response.status, response.body
    assert_equal "Updated support client", @db[:oauth_applications].where(id: @client_id).get(:name)
    discovery = Rack::MockRequest.new(@app).get("https://op.example.test/.well-known/openid-configuration")
    assert_equal "https://op.example.test/register", JSON.parse(discovery.body).fetch("registration_endpoint")
  end

  def test_management_can_remove_ciba_grant_and_subsequent_request_is_denied
    configure_dynamic_registration
    @app.plugin(:rodauth) { ciba_rotate_registration_access_token false }
    @db[:oauth_applications].where(id: @client_id).update(
      registration_access_token: BCrypt::Password.create("management-test-only", cost: 4).to_s)
    response = Rack::MockRequest.new(@app).put("https://op.example.test/register/support",
      "HTTP_AUTHORIZATION" => "Bearer management-test-only", "CONTENT_TYPE" => "application/json",
      input: JSON.generate(client_id: "support", grant_types: ["authorization_code"], response_types: ["code"], redirect_uris: ["https://rp.example.test/callback"]))
    assert_equal 200, response.status, response.body
    assert_equal "authorization_code", @db[:oauth_applications].where(id: @client_id).get(:grant_types)
    read = Rack::MockRequest.new(@app).get("https://op.example.test/register/support",
      "HTTP_AUTHORIZATION" => "Bearer management-test-only")
    assert_equal 200, read.status, read.body
    refute JSON.parse(read.body).key?("registration_access_token")
    response = post("/backchannel-authentication", login_hint: "customer@example.test", scope: "openid")
    refute_equal 200, response.status, response.body
    assert_equal 0, @db[:ciba_requests].count
  end

  def test_ciba_registration_ignores_internal_columns_and_generates_own_secret
    configure_dynamic_registration
    @db.alter_table(:oauth_applications) { add_column :internal_admin, TrueClass, default: false }
    response = register(registration_params.merge("internal_admin" => true, "id" => 999,
      "registration_access_token" => "attacker-chosen", "client_secret" => "attacker-chosen"))
    assert_equal 201, response.status, response.body
    payload = JSON.parse(response.body)
    refute_equal "attacker-chosen", payload.fetch("client_secret")
    %w[internal_admin id].each { |key| refute payload.key?(key), key }
    refute_equal "attacker-chosen", payload.fetch("registration_access_token")
    saved = @db[:oauth_applications].where(client_id: payload.fetch("client_id")).first
    refute_equal 999, saved.fetch(:id)
    refute saved.fetch(:internal_admin)
    assert BCrypt::Password.new(saved.fetch(:registration_access_token)) == payload.fetch("registration_access_token")
    assert_equal payload.fetch("client_secret"), saved.fetch(:client_secret)
  end

  def test_ciba_management_response_never_exposes_registration_token_hash
    configure_dynamic_registration
    @db[:oauth_applications].where(id: @client_id).update(
      registration_access_token: BCrypt::Password.create("management-test-only", cost: 4).to_s)
    response = Rack::MockRequest.new(@app).get("https://op.example.test/register/support",
      "HTTP_AUTHORIZATION" => "Bearer management-test-only")
    assert_equal 200, response.status, response.body
    payload = JSON.parse(response.body)
    assert_equal "management-test-only", payload.fetch("registration_access_token")
    refute payload.key?("client_secret")
    assert_equal "support", payload.fetch("client_id")
    assert_equal "client_secret_basic", payload.fetch("token_endpoint_auth_method")
  end

  def test_ciba_management_rejects_wrong_bearer_and_ignores_internal_update
    configure_dynamic_registration
    @db.alter_table(:oauth_applications) { add_column :internal_admin, TrueClass, default: false }
    @db[:oauth_applications].where(id: @client_id).update(
      registration_access_token: BCrypt::Password.create("management-test-only", cost: 4).to_s)
    before = @db[:oauth_applications].where(id: @client_id).first
    response = Rack::MockRequest.new(@app).put("https://op.example.test/register/support",
      "HTTP_AUTHORIZATION" => "Bearer wrong", "CONTENT_TYPE" => "application/json",
      input: JSON.generate(client_name: "Unauthorized"))
    assert_equal 401, response.status, response.body
    assert_equal before, @db[:oauth_applications].where(id: @client_id).first
    response = Rack::MockRequest.new(@app).put("https://op.example.test/register/support",
      "HTTP_AUTHORIZATION" => "Bearer management-test-only", "CONTENT_TYPE" => "application/json",
      input: JSON.generate(registration_params.merge("client_id" => "support", "id" => 999, "internal_admin" => true, "registration_access_token" => "attacker-chosen")))
    assert_error response, "invalid_request"
    assert_equal before, @db[:oauth_applications].where(id: @client_id).first
  end

  def test_generated_registration_bearer_manages_only_its_client
    configure_dynamic_registration
    response = register
    assert_equal 201, response.status, response.body
    client = JSON.parse(response.body)
    bearer = client.fetch("registration_access_token")
    uri = client.fetch("registration_client_uri")
    assert_equal "https://op.example.test/register/#{client.fetch('client_id')}", uri
    saved = @db[:oauth_applications].where(client_id: client.fetch("client_id")).first
    refute_equal bearer, saved.fetch(:registration_access_token)
    assert BCrypt::Password.new(saved.fetch(:registration_access_token)) == bearer
    headers = {"HTTP_AUTHORIZATION" => "Bearer #{bearer}"}
    read = Rack::MockRequest.new(@app).get(uri, headers)
    assert_equal 200, read.status, read.body
    # The submitted bearer may be echoed; the persisted verifier must never be.
    refute_includes read.body, saved.fetch(:registration_access_token)
    assert_equal client.fetch("client_id"), JSON.parse(read.body).fetch("client_id")
    other = JSON.parse(register.body)
    foreign_headers = {"HTTP_AUTHORIZATION" => "Bearer #{other.fetch('registration_access_token')}"}
    denied = Rack::MockRequest.new(@app).get(uri, foreign_headers)
    assert_equal 401, denied.status, denied.body
    invalidated = Rack::MockRequest.new(@app).get(other.fetch("registration_client_uri"), foreign_headers)
    assert_equal 401, invalidated.status, invalidated.body
    assert_equal saved, @db[:oauth_applications].where(id: saved.fetch(:id)).first
    revoked = @db[:oauth_applications].where(client_id: other.fetch("client_id")).first
    assert_nil revoked.fetch(:registration_access_token)
    assert_nil revoked.fetch(:ciba_registration_token_digest)
    assert_equal other.fetch("client_secret"), revoked.fetch(:client_secret)
    unknown = Rack::MockRequest.new(@app).get(other.fetch("registration_client_uri"),
      "HTTP_AUTHORIZATION" => "Bearer arbitrary-unprefixed-token")
    assert_equal 401, unknown.status, unknown.body
    updated = Rack::MockRequest.new(@app).put(uri, headers.merge("CONTENT_TYPE" => "application/json",
      input: JSON.generate(registration_params.merge("client_id" => client.fetch("client_id"), "client_name" => "Managed client"))))
    assert_equal 200, updated.status, updated.body
    assert_equal "Managed client", @db[:oauth_applications].where(id: saved.fetch(:id)).get(:name)
    headers = {"HTTP_AUTHORIZATION" => "Bearer #{JSON.parse(updated.body).fetch('registration_access_token')}"}
    removed = Rack::MockRequest.new(@app).delete(uri, headers)
    assert_equal 204, removed.status, removed.body
    assert_nil @db[:oauth_applications].where(id: saved.fetch(:id)).first
    assert @db[:oauth_applications].where(client_id: other.fetch("client_id")).first
  end

  def test_ciba_management_replacement_clears_omitted_metadata_and_checks_client_id
    configure_dynamic_registration
    client = JSON.parse(register(registration_params.merge("client_name" => "Original name")).body)
    uri = client.fetch("registration_client_uri")
    headers = {"HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}", "CONTENT_TYPE" => "application/json"}
    saved = @db[:oauth_applications].where(client_id: client.fetch("client_id")).first
    [nil, "another-client"].each do |identifier|
      params = registration_params.merge("client_id" => identifier)
      response = Rack::MockRequest.new(@app).put(uri, headers.merge(input: JSON.generate(params)))
      assert_error response, "invalid_request"
      assert_equal saved, @db[:oauth_applications].where(id: saved.fetch(:id)).first
    end
    response = Rack::MockRequest.new(@app).put(uri, headers.merge(input: JSON.generate(
      registration_params.merge("client_id" => client.fetch("client_id")))))
    assert_equal 200, response.status, response.body
    current = @db[:oauth_applications].where(id: saved.fetch(:id)).first
    assert_nil current.fetch(:name)
    assert_equal saved.fetch(:client_secret), current.fetch(:client_secret)
    refute_equal saved.fetch(:registration_access_token), current.fetch(:registration_access_token)
    refute JSON.parse(response.body).key?("client_name")
  end

  def test_removed_ciba_capability_retains_safe_management_responses
    configure_dynamic_registration
    client = JSON.parse(register.body)
    uri = client.fetch("registration_client_uri")
    headers = {"HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}", "CONTENT_TYPE" => "application/json"}
    response = Rack::MockRequest.new(@app).put(uri, headers.merge(input: JSON.generate(
      client_id: client.fetch("client_id"), grant_types: ["authorization_code"], response_types: ["code"],
      redirect_uris: ["https://rp.example.test/callback"])))
    assert_equal 200, response.status, response.body
    saved = @db[:oauth_applications].where(client_id: client.fetch("client_id")).first
    assert_nil saved.fetch(:backchannel_token_delivery_mode)
    next_token = JSON.parse(response.body).fetch("registration_access_token")
    headers["HTTP_AUTHORIZATION"] = "Bearer #{next_token}"
    read = Rack::MockRequest.new(@app).get(uri, headers)
    assert_equal 200, read.status, read.body
    refute_includes read.body, saved.fetch(:registration_access_token)
    assert_equal next_token, JSON.parse(read.body).fetch("registration_access_token")
    partial = Rack::MockRequest.new(@app).put(uri, headers.merge(input: JSON.generate(client_name: "partial")))
    assert_error partial, "invalid_request"
  end

  def test_ciba_management_replacement_under_a_mounted_route
    configure_dynamic_registration
    @app.plugin(:rodauth) { prefix "/identity" }
    @app.route do |r|
      r.on("identity") do
        r.rodauth
        rodauth.load_registration_client_uri_routes
      end
    end
    response = post("/identity/register", {}, "HTTP_AUTHORIZATION" => "Bearer registration-test-only",
      "CONTENT_TYPE" => "application/json", input: JSON.generate(registration_params))
    assert_equal 201, response.status, response.body
    client = JSON.parse(response.body)
    assert_includes client.fetch("registration_client_uri"), "/identity/register/"
    response = Rack::MockRequest.new(@app).put(client.fetch("registration_client_uri"),
      "HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}", "CONTENT_TYPE" => "application/json",
      input: JSON.generate(client_name: "partial"))
    assert_error response, "invalid_request"
  end

  def test_unknown_management_bearer_cannot_revoke_another_client
    configure_dynamic_registration
    client = JSON.parse(register.body)
    before = @db[:oauth_applications].order(:id).all
    ["ciba_reg_#{SecureRandom.urlsafe_base64(32)}", "#{client.fetch('registration_access_token')}extra"].each do |token|
      response = Rack::MockRequest.new(@app).get(client.fetch("registration_client_uri"),
        "HTTP_AUTHORIZATION" => "Bearer #{token}")
      assert_equal 401, response.status, response.body
      assert_equal before, @db[:oauth_applications].order(:id).all
    end
    saved = before.find { |row| row[:client_id] == client.fetch("client_id") }
    assert_equal Digest::SHA256.hexdigest(client.fetch("registration_access_token")), saved.fetch(:ciba_registration_token_digest)
    response = Rack::MockRequest.new(@app).get(client.fetch("registration_client_uri"),
      "HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}")
    assert_equal 200, response.status, response.body
    refute_includes response.body, saved.fetch(:ciba_registration_token_digest)
  end

  def test_registration_digest_migration_preserves_rows_and_enforces_uniqueness
    existing = @db[:oauth_applications].first
    Rodauth::CibaSupport::Schema.add_registration_token_digest(@db, column: :management_lookup)
    assert_equal existing, @db[:oauth_applications].first.reject { |key, _| key == :management_lookup }
    assert_nil @db[:oauth_applications].get(:management_lookup)
    digest = Digest::SHA256.hexdigest("test-management-credential")
    @db[:oauth_applications].where(id: @client_id).update(management_lookup: digest)
    duplicate = existing.reject { |key, _| key == :id }.merge(client_id: "duplicate", management_lookup: digest)
    assert_raises(Sequel::UniqueConstraintViolation) { @db[:oauth_applications].insert(duplicate) }
  end

  def test_registration_update_rotates_bearer_and_old_replay_cannot_revoke_successor
    configure_dynamic_registration
    client = JSON.parse(register.body)
    uri = client.fetch("registration_client_uri")
    old_token = client.fetch("registration_access_token")
    old_headers = {"HTTP_AUTHORIZATION" => "Bearer #{old_token}"}
    response = Rack::MockRequest.new(@app).put(uri, old_headers.merge("CONTENT_TYPE" => "application/json",
      input: JSON.generate(registration_params.merge("client_id" => client.fetch("client_id")))))
    assert_equal 200, response.status, response.body
    token = JSON.parse(response.body).fetch("registration_access_token")
    refute_equal old_token, token
    current = @db[:oauth_applications].where(client_id: client.fetch("client_id")).first
    assert_equal Digest::SHA256.hexdigest(token), current.fetch(:ciba_registration_token_digest)
    assert BCrypt::Password.new(current.fetch(:registration_access_token)) == token
    assert_equal 401, Rack::MockRequest.new(@app).get(uri, old_headers).status
    other = JSON.parse(register.body)
    assert_equal 401, Rack::MockRequest.new(@app).get(other.fetch("registration_client_uri"), old_headers).status
    assert_equal current, @db[:oauth_applications].where(id: current.fetch(:id)).first
    assert_equal 200, Rack::MockRequest.new(@app).get(uri, "HTTP_AUTHORIZATION" => "Bearer #{token}").status
  end

  def test_registration_rotation_rolls_back_when_response_serialization_fails
    configure_dynamic_registration
    client = JSON.parse(register.body)
    saved = @db[:oauth_applications].where(client_id: client.fetch("client_id")).first
    @app.plugin(:rodauth) do
      auth_class_eval do
        def _json_response_body(body)
          if scope.env["test.fail_registration_response"]
            scope.env.fetch("test.capture_registration_response").call(body)
            raise "injected management serialization failure"
          end
          super
        end
      end
    end
    headers = {"HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}"}
    attempted = nil
    assert_raises(RuntimeError) do
      Rack::MockRequest.new(@app).put(client.fetch("registration_client_uri"), headers.merge(
        "test.fail_registration_response" => true, "CONTENT_TYPE" => "application/json",
        "test.capture_registration_response" => ->(body) { attempted = body.fetch("registration_access_token") },
        input: JSON.generate(registration_params.merge("client_id" => client.fetch("client_id"), "client_name" => "Not committed"))))
    end
    assert_equal saved, @db[:oauth_applications].where(id: saved.fetch(:id)).first
    refute_nil attempted
    refute_equal client.fetch("registration_access_token"), attempted
    assert_equal 401, Rack::MockRequest.new(@app).get(client.fetch("registration_client_uri"),
      "HTTP_AUTHORIZATION" => "Bearer #{attempted}").status
    assert_equal 200, Rack::MockRequest.new(@app).get(client.fetch("registration_client_uri"), headers).status
  end

  def test_registration_rotation_can_be_disabled_for_issued_credentials
    configure_dynamic_registration
    @app.plugin(:rodauth) { ciba_rotate_registration_access_token false }
    client = JSON.parse(register.body)
    saved = @db[:oauth_applications].where(client_id: client.fetch("client_id")).first
    headers = {"HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}"}
    response = Rack::MockRequest.new(@app).put(client.fetch("registration_client_uri"), headers.merge(
      "CONTENT_TYPE" => "application/json", input: JSON.generate(registration_params.merge(
        "client_id" => client.fetch("client_id"), "client_name" => "Without rotation"))))
    assert_equal 200, response.status, response.body
    assert_equal client.fetch("registration_access_token"), JSON.parse(response.body).fetch("registration_access_token")
    current = @db[:oauth_applications].where(id: saved.fetch(:id)).first
    assert_equal saved.fetch(:registration_access_token), current.fetch(:registration_access_token)
    assert_equal saved.fetch(:ciba_registration_token_digest), current.fetch(:ciba_registration_token_digest)
    assert_equal 200, Rack::MockRequest.new(@app).get(client.fetch("registration_client_uri"), headers).status
  end

  def test_concurrent_management_updates_rotate_only_once
    configure_dynamic_registration
    client = JSON.parse(register.body)
    uri = client.fetch("registration_client_uri")
    headers = {"HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}", "CONTENT_TYPE" => "application/json"}
    responses = parallel_decisions do |index|
      Rack::MockRequest.new(@app).put(uri, headers.merge(input: JSON.generate(
        registration_params.merge("client_id" => client.fetch("client_id"), "client_name" => "Update #{index}"))))
    end
    statuses = responses.map(&:status).sort
    if @db.database_type == :sqlite && statuses == [200, 503]
      busy = responses.find { |response| response.status == 503 }
      assert_equal "temporarily_unavailable", JSON.parse(busy.body).fetch("error")
      assert_equal "5", busy["Retry-After"]
      retry_response = Rack::MockRequest.new(@app).put(uri, headers.merge(input: JSON.generate(
        registration_params.merge("client_id" => client.fetch("client_id")))))
      assert_equal 401, retry_response.status, retry_response.body
    else
      assert_equal [200, 401], statuses, responses.map(&:body).inspect
    end
    winner = JSON.parse(responses.find { |response| response.status == 200 }.body)
    saved = @db[:oauth_applications].where(client_id: client.fetch("client_id")).first
    assert_equal winner.fetch("client_name"), saved.fetch(:name)
    assert_equal Digest::SHA256.hexdigest(winner.fetch("registration_access_token")), saved.fetch(:ciba_registration_token_digest)
    assert_equal 200, Rack::MockRequest.new(@app).get(uri,
      "HTTP_AUTHORIZATION" => "Bearer #{winner.fetch('registration_access_token')}").status
  end

  def test_dynamic_registration_composes_ping_signed_requests_and_user_codes
    configure_dynamic_registration
    Rodauth::CibaSupport::Schema.add_ping(@db)
    Rodauth::CibaSupport::Schema.add_signed_requests(@db)
    Rodauth::CibaSupport::Schema.add_user_code(@db)
    @db.alter_table(:oauth_applications) { add_column :jwks, String, text: true }
    @app.plugin(:rodauth) do
      ciba_ping_enabled true
      ciba_request_signing_algorithms ["RS256"]
      ciba_user_code_enabled true
      verify_ciba_user_code do |code, account_id:, oauth_application:|
        oauth_application[:backchannel_user_code_parameter] ? code == "approved-code" : code.nil?
      end
    end
    key = OpenSSL::PKey::RSA.generate(2048)
    jwk = JWT::JWK.new(key.public_key).export.merge(alg: "RS256", use: "sig")
    params = registration_params.merge("backchannel_token_delivery_mode" => "ping",
      "backchannel_client_notification_endpoint" => "https://rp.example.test/notify",
      "backchannel_authentication_request_signing_alg" => "RS256", "jwks" => {"keys" => [jwk]},
      "backchannel_user_code_parameter" => true)
    response = register(params)
    assert_equal 201, response.status, response.body
    client = JSON.parse(response.body)
    headers = {"HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64("#{client.fetch('client_id')}:#{client.fetch('client_secret')}")}"}
    signed = lambda do |code|
      now = Time.now.to_i
      JWT.encode({iss: client.fetch("client_id"), aud: "https://op.example.test", iat: now, nbf: now - 1,
        exp: now + 120, jti: SecureRandom.hex(12), scope: "openid", login_hint: "customer@example.test",
        user_code: code, client_notification_token: "dynamic-notification-secret-12345"}, key, "RS256", kid: jwk.fetch(:kid))
    end
    assert_error post("/backchannel-authentication", {scope: "openid", login_hint: "customer@example.test"}, headers), "invalid_request"
    assert_error post("/backchannel-authentication", {request: signed.call("wrong")}, headers), "invalid_user_code"
    assert_equal 0, @db[:ciba_requests].count
    started = post("/backchannel-authentication", {request: signed.call("approved-code")}, headers)
    assert_equal 200, started.status, started.body
    id = JSON.parse(started.body).fetch("auth_req_id")
    calls = []
    sender = lambda do |uri, request, **_options|
      refute @db.in_transaction?
      calls << [uri.to_s, request["authorization"], JSON.parse(request.body)]
      Struct.new(:code).new("204")
    end
    Rodauth::CibaSupport::HTTP.stub(:request, sender) { approve(id) }
    assert_equal [["https://rp.example.test/notify", "Bearer dynamic-notification-secret-12345", {"auth_req_id" => id}]], calls
    issued = poll(id, headers)
    assert_equal 200, issued.status, issued.body
    claims, = JWT.decode(JSON.parse(issued.body).fetch("id_token"), KEY.public_key, true,
      algorithms: ["RS256"], verify_aud: true, aud: client.fetch("client_id"))
    assert_equal @account_id.to_s, claims.fetch("sub")

    update = Rack::MockRequest.new(@app).put(client.fetch("registration_client_uri"),
      "HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}", "CONTENT_TYPE" => "application/json",
      input: JSON.generate(registration_params.merge("client_id" => client.fetch("client_id"), "backchannel_user_code_parameter" => false)))
    assert_equal 200, update.status, update.body
    assert_equal false, JSON.parse(update.body).fetch("backchannel_user_code_parameter")
    saved = @db[:oauth_applications].where(client_id: client.fetch("client_id")).first
    assert_nil saved.fetch(:jwks)
    assert_nil saved.fetch(:backchannel_authentication_request_signing_alg)
    assert_nil saved.fetch(:backchannel_client_notification_endpoint)
    unsigned = post("/backchannel-authentication", {scope: "openid", login_hint: "customer@example.test"}, headers)
    assert_equal 200, unsigned.status, unsigned.body
  end

  def test_registration_rejects_metadata_without_required_storage
    configure_dynamic_registration
    Rodauth::CibaSupport::Schema.add_signed_requests(@db)
    @app.plugin(:rodauth) { ciba_request_signing_algorithms ["RS256"] }
    before = @db[:oauth_applications].count
    response = register(registration_params.merge("backchannel_authentication_request_signing_alg" => "RS256",
      "jwks" => {"keys" => [JWT::JWK.new(KEY.public_key).export]}))
    assert_error response, "invalid_client_metadata"
    assert_equal before, @db[:oauth_applications].count
  end

  def test_managed_client_deletion_with_ciba_and_ordinary_grants
    configure_dynamic_registration
    Rodauth::CibaSupport::Schema.create_refresh_tokens(@db)
    Rodauth::CibaSupport::Schema.add_ping(@db)
    @app.plugin(:rodauth) do
      ciba_refresh_tokens_enabled true
      ciba_ping_enabled true
      oauth_application_scopes %w[openid offline_access]
      get_additional_param { |_account, _claim| nil }
    end
    metadata = registration_params.merge("grant_types" => [GRANT, "authorization_code", "refresh_token"],
      "scope" => "openid offline_access", "response_types" => ["code"], "redirect_uris" => ["https://rp.example.test/callback"])
    client = JSON.parse(register(metadata).body)
    application = @db[:oauth_applications].where(client_id: client.fetch("client_id")).first
    headers = {"HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64("#{client.fetch('client_id')}:#{client.fetch('client_secret')}")}"}
    start = post("/backchannel-authentication", {scope: "openid offline_access", login_hint: "customer@example.test"}, headers)
    assert_equal 200, start.status, start.body
    id = JSON.parse(start.body).fetch("auth_req_id")
    approve(id)
    issued = poll(id, headers)
    assert_equal 200, issued.status, issued.body
    token = JSON.parse(issued.body).fetch("access_token")
    refresh = JSON.parse(issued.body).fetch("refresh_token")
    assert_equal 1, @db[:ciba_refresh_tokens].where(oauth_application_id: application.fetch(:id)).count
    before_userinfo = Rack::MockRequest.new(@app).get("https://op.example.test/userinfo", "HTTP_AUTHORIZATION" => "Bearer #{token}")
    assert_equal 200, before_userinfo.status, before_userinfo.body
    refreshed = post("/token", {grant_type: "refresh_token", refresh_token: refresh}, headers)
    assert_equal 200, refreshed.status, refreshed.body
    update = Rack::MockRequest.new(@app).put(client.fetch("registration_client_uri"),
      "HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}", "CONTENT_TYPE" => "application/json",
      input: JSON.generate(metadata.merge("client_id" => client.fetch("client_id"), "backchannel_token_delivery_mode" => "ping",
        "backchannel_client_notification_endpoint" => "https://rp.example.test/notify")))
    assert_equal 200, update.status, update.body
    management_token = JSON.parse(update.body).fetch("registration_access_token")
    pending = post("/backchannel-authentication", {scope: "openid", login_hint: "customer@example.test",
      client_notification_token: "pending-deletion-notification-token"}, headers)
    assert_equal 200, pending.status, pending.body
    assert_equal 1, @db[:ciba_ping_deliveries].count
    # Existing upstream authorization-code grants do not have a CIBA consent FK.
    @db[:oauth_grants].insert(oauth_application_id: application.fetch(:id), account_id: @account_id,
      type: "authorization_code", token: "ordinary-owned-token", scopes: "openid", expires_in: Time.now + 3600)
    unrelated = @db[:oauth_grants].insert(oauth_application_id: @client_id, account_id: @account_id,
      type: "authorization_code", token: "unrelated-token", scopes: "openid", expires_in: Time.now + 3600)
    before = %i[oauth_applications oauth_grants ciba_grants ciba_requests ciba_refresh_tokens ciba_ping_deliveries].to_h { |table| [table, @db[table].all] }
    denied = Rack::MockRequest.new(@app).delete(client.fetch("registration_client_uri"), "HTTP_AUTHORIZATION" => "Bearer wrong")
    assert_equal 401, denied.status, denied.body
    before.each { |table, rows| assert_equal rows, @db[table].all }
    response = Rack::MockRequest.new(@app).delete(client.fetch("registration_client_uri"),
      "HTTP_AUTHORIZATION" => "Bearer #{management_token}")
    assert_equal 204, response.status, response.body
    assert_nil @db[:oauth_applications].where(id: application.fetch(:id)).first
    assert_equal 0, @db[:oauth_grants].where(oauth_application_id: application.fetch(:id)).count
    assert_equal 0, @db[:ciba_grants].where(oauth_application_id: application.fetch(:id)).count
    assert_equal 0, @db[:ciba_requests].where(oauth_application_id: application.fetch(:id)).count
    assert_equal 0, @db[:ciba_refresh_tokens].where(oauth_application_id: application.fetch(:id)).count
    assert_equal 0, @db[:ciba_ping_deliveries].count
    assert @db[:oauth_grants].where(id: unrelated).first
    assert_equal 401, poll(JSON.parse(pending.body).fetch("auth_req_id"), headers).status
    userinfo = Rack::MockRequest.new(@app).get("https://op.example.test/userinfo", "HTTP_AUTHORIZATION" => "Bearer #{token}")
    assert_equal 401, userinfo.status, userinfo.body
    assert_equal 401, post("/token", {grant_type: "refresh_token", refresh_token: refresh}, headers).status
  end

  def test_client_deletion_rolls_back_grant_cleanup_when_application_dependency_blocks_it
    configure_dynamic_registration
    client = JSON.parse(register.body)
    row = @db[:oauth_applications].where(client_id: client.fetch("client_id")).first
    @db.create_table(:application_dependencies) do
      primary_key :id
      foreign_key :application_id, :oauth_applications
    end
    @db[:application_dependencies].insert(application_id: row.fetch(:id))
    grant_id = @db[:oauth_grants].insert(oauth_application_id: row.fetch(:id), account_id: @account_id,
      type: "authorization_code", token: "preserved-on-failure", scopes: "openid", expires_in: Time.now + 3600)
    grant = @db[:oauth_grants].where(id: grant_id).first
    headers = {"HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}"}
    assert_raises(Sequel::ForeignKeyConstraintViolation) do
      Rack::MockRequest.new(@app).delete(client.fetch("registration_client_uri"), headers)
    end
    assert_equal row, @db[:oauth_applications].where(id: row.fetch(:id)).first
    assert_equal grant, @db[:oauth_grants].where(id: grant_id).first
    assert_equal 200, Rack::MockRequest.new(@app).get(client.fetch("registration_client_uri"), headers).status
  end

  def test_delete_waiting_for_grant_does_not_hold_client_lock
    skip "SQLite serializes writers instead of using row locks" if @db.database_type == :sqlite
    configure_dynamic_registration
    client = JSON.parse(register.body)
    application_id = @db[:oauth_applications].where(client_id: client.fetch("client_id")).get(:id)
    grant = auth.create_ciba_grant(account_id: @account_id, oauth_application_id: application_id, scopes: "openid")
    @app.plugin(:rodauth) do
      auth_class_eval do
        def password_hash_match?(hash, password)
          result = super
          scope.env.delete("test.registration_verified_probe")&.call if result
          result
        end
      end
    end
    reached, release = Queue.new, Queue.new
    worker = nil
    begin
      @db.transaction do
        @db.run(@db.database_type == :postgres ? "SET LOCAL lock_timeout = '1s'" : "SET innodb_lock_wait_timeout = 1")
        @db[:ciba_grants].where(id: grant.fetch(:id)).for_update.first
        worker = Thread.new do
          Rack::MockRequest.new(@app).delete(client.fetch("registration_client_uri"),
            "HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}",
            "test.registration_verified_probe" => -> { reached << true; release.pop })
        end
        Timeout.timeout(10) { reached.pop }
        # A refresh holding the consent may still acquire the parent client FK
        # lock. DELETE must not hold that client while waiting for our consent.
        row = @db[:oauth_applications].where(id: application_id).for_update.first
        assert_equal application_id, row.fetch(:id)
        release << true
      end
      response = Timeout.timeout(10) { worker.value }
      assert_equal 204, response.status, response.body
    ensure
      release << true
      worker&.kill if worker&.alive?
      worker&.join
    end
  end

  def test_opposite_client_management_requests_invalidate_only_their_own_credentials
    configure_dynamic_registration
    clients = 2.times.map { JSON.parse(register.body) }
    unrelated = @db[:oauth_applications].where(id: @client_id).first
    send_request = lambda do |index|
      Rack::MockRequest.new(@app).get(clients[1 - index].fetch("registration_client_uri"),
        "HTTP_AUTHORIZATION" => "Bearer #{clients[index].fetch('registration_access_token')}")
    end
    responses = parallel_decisions { |index| send_request.call(index) }
    responses.each_with_index do |response, index|
      if @db.database_type == :sqlite && response.status == 503
        assert_equal "temporarily_unavailable", JSON.parse(response.body).fetch("error")
        response = send_request.call(index)
      end
      assert_equal 401, response.status, response.body
    end
    clients.each do |client|
      row = @db[:oauth_applications].where(client_id: client.fetch("client_id")).first
      assert_nil row.fetch(:registration_access_token)
      assert_nil row.fetch(:ciba_registration_token_digest)
      assert_equal client.fetch("client_secret"), row.fetch(:client_secret)
    end
    assert_equal unrelated, @db[:oauth_applications].where(id: @client_id).first
  end

  def test_concurrent_client_delete_and_refresh_leave_no_live_client_tokens
    configure_dynamic_registration
    Rodauth::CibaSupport::Schema.create_refresh_tokens(@db)
    @app.plugin(:rodauth) do
      ciba_refresh_tokens_enabled true
      oauth_application_scopes %w[openid offline_access]
    end
    client = JSON.parse(register(registration_params.merge("scope" => "openid offline_access",
      "grant_types" => [GRANT, "refresh_token"])).body)
    id = @db[:oauth_applications].where(client_id: client.fetch("client_id")).get(:id)
    credentials = {"HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64("#{client.fetch('client_id')}:#{client.fetch('client_secret')}")}"}
    start = post("/backchannel-authentication", {scope: "openid offline_access", login_hint: "customer@example.test"}, credentials)
    assert_equal 200, start.status, start.body
    request_id = JSON.parse(start.body).fetch("auth_req_id")
    approve(request_id)
    token = JSON.parse(poll(request_id, credentials).body).fetch("refresh_token")
    delete_client = -> { Rack::MockRequest.new(@app).delete(client.fetch("registration_client_uri"),
      "HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}") }
    errors = []
    responses = parallel_decisions do |index|
      index == 0 ? delete_client.call : post("/token", {grant_type: "refresh_token", refresh_token: token}, credentials.merge(
        "test.processing_error" => ->(error) { errors << [error.class.name, error.respond_to?(:wrapped_exception) && error.wrapped_exception.class.name] }))
    end
    deleted, refreshed = responses
    if deleted.status == 503
      assert_equal "temporarily_unavailable", JSON.parse(deleted.body).fetch("error")
      deleted = delete_client.call
    end
    assert_equal 204, deleted.status, deleted.body
    assert_includes [200, 400, 401, 503], refreshed.status, "#{refreshed.body} #{errors.inspect}"
    if refreshed.status == 400
      assert_equal "invalid_grant", JSON.parse(refreshed.body).fetch("error")
    elsif refreshed.status == 503
      assert_equal "temporarily_unavailable", JSON.parse(refreshed.body).fetch("error")
    end
    assert_nil @db[:oauth_applications].where(id: id).first
    %i[ciba_grants ciba_requests ciba_refresh_tokens oauth_grants].each do |table|
      assert_equal 0, @db[table].where(oauth_application_id: id).count
    end
    assert_equal 401, post("/token", {grant_type: "refresh_token", refresh_token: token}, credentials).status
  end

  def configure_registration_rar
    configure_dynamic_registration
    Rodauth::CibaSupport::Schema.add_resources(@db)
    Rodauth::CibaSupport::Schema.add_authorization_details(@db)
    Rodauth::CibaSupport::Schema.create_refresh_tokens(@db)
    @app.plugin(:rodauth) do
      ciba_resources_enabled true
      ciba_resource_servers("https://api.example.test" => {scopes: ["read"], audience: "https://api.example.test"})
      ciba_refresh_tokens_enabled true
      oauth_application_scopes %w[openid offline_access read]
      ciba_authorization_details_enabled true
      ciba_authorization_details_types ["support_data"]
      ciba_validate_authorization_details do |details, oauth_application:|
        details.all? { |detail| detail["actions"].is_a?(Array) && (detail["actions"] - %w[read delete]).empty? }
      end
      ciba_authorization_details_for_token do |requested:, approved:, narrowing:, resource:, oauth_application:|
        allowed = approved.flat_map { |detail| detail["actions"] }
        if narrowing && narrowing.any? { |detail| (detail["actions"] - allowed).any? }
          raise Rodauth::CibaSupport::ProtocolError, "invalid_authorization_details"
        end
        approved.map do |detail|
          actions = detail["actions"] & requested.flat_map { |item| item["actions"] }
          actions &= narrowing.flat_map { |item| item["actions"] } if narrowing
          detail.merge("actions" => actions)
        end
      end
    end
  end

  def test_dynamic_rar_registration_resource_tokens_refresh_and_type_removal
    configure_registration_rar
    metadata = registration_params.merge("grant_types" => [GRANT, "refresh_token"], "scope" => "openid offline_access read",
      "authorization_details_types" => ["support_data"])
    response = register(metadata)
    assert_equal 201, response.status, response.body
    client = JSON.parse(response.body)
    assert_equal ["support_data"], client.fetch("authorization_details_types")
    app_id = @db[:oauth_applications].where(client_id: client.fetch("client_id")).get(:id)
    headers = {"HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64("#{client.fetch('client_id')}:#{client.fetch('client_secret')}")}"}
    requested = [{"type" => "support_data", "actions" => %w[read delete]}]
    approved = [{"type" => "support_data", "actions" => ["read"]}]
    start = post("/backchannel-authentication", {scope: "openid offline_access read", login_hint: "customer@example.test",
      resource: "https://api.example.test", authorization_details: JSON.generate(requested)}, headers)
    assert_equal 200, start.status, start.body
    id = JSON.parse(start.body).fetch("auth_req_id")
    grant = auth.create_ciba_grant(account_id: @account_id, oauth_application_id: app_id, scopes: "openid offline_access",
      resources: {"https://api.example.test" => "read"}, authorization_details: approved)
    auth.backchannel_result(@db[:ciba_requests].get(:id), grant)
    issued = post("/token", {grant_type: GRANT, auth_req_id: id, resource: "https://api.example.test"}, headers)
    assert_equal 200, issued.status, issued.body
    body = JSON.parse(issued.body)
    assert_equal approved, body.fetch("authorization_details")
    refresh = body.fetch("refresh_token")
    refreshed = post("/token", {grant_type: "refresh_token", refresh_token: refresh, resource: "https://api.example.test"}, headers)
    assert_equal 200, refreshed.status, refreshed.body
    assert_equal approved, JSON.parse(refreshed.body).fetch("authorization_details")
    update = Rack::MockRequest.new(@app).put(client.fetch("registration_client_uri"),
      "HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}", "CONTENT_TYPE" => "application/json",
      input: JSON.generate(metadata.reject { |key, _| key == "authorization_details_types" }.merge("client_id" => client.fetch("client_id"))))
    assert_equal 200, update.status, update.body
    assert_equal [], JSON.parse(update.body).fetch("authorization_details_types")
    assert_error post("/token", {grant_type: "refresh_token", refresh_token: refresh, resource: "https://api.example.test"}, headers),
      "invalid_authorization_details"
  end

  def test_dynamic_rar_registration_rejects_invalid_type_metadata
    configure_registration_rar
    ["support_data", [1], [""], ["unregistered"], {}].each do |types|
      before = @db[:oauth_applications].count
      assert_error register(registration_params.merge("authorization_details_types" => types)), "invalid_client_metadata"
      assert_equal before, @db[:oauth_applications].count
    end
  end

  def test_rar_registration_metadata_is_ignored_when_feature_is_disabled
    configure_dynamic_registration
    @db.alter_table(:oauth_applications) { add_column :authorization_details_types, String, text: true }
    response = register(registration_params.merge("authorization_details_types" => ["support_data"]))
    assert_equal 201, response.status, response.body
    client = JSON.parse(response.body)
    refute client.key?("authorization_details_types")
    assert_nil @db[:oauth_applications].where(client_id: client.fetch("client_id")).get(:authorization_details_types)
  end
end
