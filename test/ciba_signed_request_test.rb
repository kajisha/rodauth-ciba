# frozen_string_literal: true
require_relative "test_helper"

class CibaIntegrationTest
  REQUEST_KEY = OpenSSL::PKey::RSA.generate(2048)

  def enable_signed_requests
    Rodauth::CibaSupport::Schema.add_signed_requests(@db)
    @db.alter_table(:oauth_applications) { add_column :jwks, String, text: true }
    @db[:oauth_applications].update(backchannel_authentication_request_signing_alg: "RS256",
      jwks: JSON.generate(keys: [JWT::JWK.new(REQUEST_KEY.public_key).export.merge(alg: "RS256", use: "sig")]))
    @app.plugin(:rodauth) { ciba_request_signing_algorithms ["RS256"] }
  end

  def signed_ciba_request(changes = {}, key: REQUEST_KEY, header: {}, omit: [])
    now = Time.now.to_i
    payload = {iss: "support", aud: "https://op.example.test", exp: now + 300, iat: now, nbf: now - 1,
      jti: "signed-request", scope: "openid", login_hint: "customer@example.test", requested_expiry: 123}
    payload.merge!(changes)
    omit.each { |name| payload.delete(name) }
    parts = [{alg: "RS256", kid: JWT::JWK.new(key).kid}.merge(header), payload].map do |value|
      Base64.urlsafe_encode64(JSON.generate(value), padding: false)
    end
    input = parts.join(".")
    input + "." + Base64.urlsafe_encode64(key.sign("SHA256", input), padding: false)
  end

  def test_signed_request_isolated_parameters_new_approval_and_repeated_submission
    enable_signed_requests
    token = signed_ciba_request
    snapshots = []
    start = post("/backchannel-authentication", {request: token, scope: "untrusted", login_hint: "other"},
      "test.device" => ->(row, _) { snapshots << row })
    assert_equal 200, start.status, start.body
    assert_equal 123, JSON.parse(start.body)["expires_in"]
    refute_includes JSON.generate(snapshots + @db[:ciba_requests].all), token
    id = JSON.parse(start.body).fetch("auth_req_id")
    assert_error poll(id), "authorization_pending"
    approve(id)
    result = poll(id, "test.now" => -> { Time.now.to_i + 10 })
    assert_equal 200, result.status, result.body
    assert_equal @account_id.to_s, decode_id_token(result).last["sub"]
    again = post("/backchannel-authentication", request: token)
    assert_equal 200, again.status, again.body
    refute_equal id, JSON.parse(again.body)["auth_req_id"]
    assert_equal 0, @db[:ciba_client_assertions].count
  end

  def test_signed_request_empty_jti_matches_reference_without_reusing_approval
    enable_signed_requests
    token = signed_ciba_request({jti: ""})
    accepted = post("/backchannel-authentication", request: token)
    assert_equal 200, accepted.status, accepted.body
    id = JSON.parse(accepted.body).fetch("auth_req_id")
    approve(id)
    assert_equal 200, poll(id).status
    repeated = post("/backchannel-authentication", request: token)
    assert_equal 200, repeated.status, repeated.body
    new_id = JSON.parse(repeated.body).fetch("auth_req_id")
    refute_equal id, new_id
    assert_error poll(new_id), "authorization_pending"
    assert_equal 1, @db[:oauth_grants].count
    assert_equal 0, @db[:ciba_client_assertions].count
  end

  def test_signed_request_registration_discovery_and_client_authentication
    enable_signed_requests
    discovery = Rack::MockRequest.new(@app).get("https://op.example.test/.well-known/openid-configuration")
    assert_equal ["RS256"], JSON.parse(discovery.body)["backchannel_authentication_request_signing_alg_values_supported"]
    assert_error post("/backchannel-authentication", scope: "openid", login_hint: "customer@example.test"), "invalid_request"
    unauthenticated = post("/backchannel-authentication", {request: signed_ciba_request, client_id: "support"}, "HTTP_AUTHORIZATION" => nil)
    assert_equal 401, unauthenticated.status
    @db[:oauth_applications].update(backchannel_authentication_request_signing_alg: nil)
    assert_error post("/backchannel-authentication", request: signed_ciba_request), "invalid_request"
    assert_equal 200, post("/backchannel-authentication", scope: "openid", login_hint: "customer@example.test").status
  end

  def test_signed_request_configured_asymmetric_algorithms_and_encrypted_shape
    enable_signed_requests
    algorithms = %w[RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES384 ES512]
    @app.plugin(:rodauth) { ciba_request_signing_algorithms algorithms }
    algorithms.each do |algorithm|
      curve = {"ES256" => "prime256v1", "ES384" => "secp384r1", "ES512" => "secp521r1"}[algorithm]
      key = curve ? OpenSSL::PKey::EC.generate(curve) : REQUEST_KEY
      wrong_key = curve ? OpenSSL::PKey::EC.generate(curve) : KEY
      jwk = JWT::JWK.new(key).export
      @db[:oauth_applications].update(backchannel_authentication_request_signing_alg: algorithm,
        jwks: JSON.generate(keys: [jwk.merge(alg: algorithm, use: "sig")]))
      claims = JSON.parse(Base64.urlsafe_decode64(signed_ciba_request.split(".")[1]))
      token = JWT.encode(claims, key, algorithm, kid: jwk.fetch(:kid))
      response = post("/backchannel-authentication", request: token)
      assert_equal 200, response.status, "#{algorithm}: #{response.body}"
      count = @db[:ciba_requests].count
      forged = JWT.encode(claims, wrong_key, algorithm, kid: jwk.fetch(:kid))
      assert_error post("/backchannel-authentication", request: forged), "invalid_request"
      assert_equal count, @db[:ciba_requests].count
    end
    # Five-part encrypted request objects are outside the accepted format.
    assert_error post("/backchannel-authentication", request: "e30.e30.e30.e30.e30"), "invalid_request"
  end

  def test_signed_request_numeric_dates_match_reference_without_inheriting_approval
    enable_signed_requests
    now = Time.now.to_i
    [{iat: now + 3600}, {iat: now + 0.5, nbf: now - 0.5, exp: now + 300.5}].each do |claims|
      response = post("/backchannel-authentication", request: signed_ciba_request(claims))
      assert_equal 200, response.status, response.body
      id = JSON.parse(response.body).fetch("auth_req_id")
      assert_error poll(id), "authorization_pending"
      approve(id)
      assert_equal 200, poll(id, "test.now" => -> { Time.now.to_i + 10 }).status
    end
    count = @db[:ciba_requests].count
    [{nbf: now + 3600.5}, {exp: now - 3600.5}].each do |claims|
      assert_error post("/backchannel-authentication", request: signed_ciba_request(claims)), "invalid_request"
    end
    assert_equal count, @db[:ciba_requests].count
  end

  def test_signed_request_rejects_bad_claims_and_keys_before_persistence
    enable_signed_requests
    changes = %i[iss aud exp iat nbf jti scope login_hint].map { |name| {name => nil} }
    %i[exp iat nbf].each do |name|
      value = Time.now.to_i + (name == :exp ? 300 : -1)
      changes.concat([{name => value.to_s}, {name => true}, {name => []}])
    end
    changes += [{iss: "other"}, {aud: "https://other.example"}, {exp: Time.now.to_i - 3600},
      {nbf: Time.now.to_i + 3600.5}, {jti: 123}, {jti: []},
      {request: "nested"}, {request_uri: "https://example.test/jar"}, {client_id: "other"}, {scope: ["openid"]}]
    changes.each do |change|
      assert_error post("/backchannel-authentication", request: signed_ciba_request(change), scope: "openid", login_hint: "customer@example.test"), "invalid_request"
    end
    [signed_ciba_request(key: KEY), signed_ciba_request(header: {kid: "unknown"}), "invalid"].each do |token|
      assert_error post("/backchannel-authentication", request: token), "invalid_request"
    end
    assert_equal 0, @db[:ciba_requests].count
  end

  def test_signed_request_missing_required_fields_cannot_use_outer_values
    enable_signed_requests
    dispatched = []
    outer = {iss: "support", aud: "https://op.example.test", exp: Time.now.to_i + 300,
      iat: Time.now.to_i, nbf: Time.now.to_i - 1, jti: "outer",
      scope: "openid", login_hint: "customer@example.test"}
    outer.each_key do |name|
      response = post("/backchannel-authentication",
        outer.merge(request: signed_ciba_request(omit: [name])),
        "test.device" => ->(row, _) { dispatched << row })
      assert_error response, "invalid_request"
      assert_equal 0, @db[:ciba_requests].count, name.to_s
      assert_equal 0, @db[:oauth_grants].count, name.to_s
      assert_empty dispatched, name.to_s
    end
    control = post("/backchannel-authentication", {request: signed_ciba_request},
      "test.device" => ->(row, _) { dispatched << row })
    assert_equal 200, control.status, control.body
    assert_equal 1, dispatched.size
    assert_equal "pending", @db[:ciba_requests].get(:status)
  end

  def test_signed_request_key_selection_duplicate_json_and_migration_preservation
    existing = accept_request
    enable_signed_requests
    assert_equal "pending", @db[:ciba_requests].get(:status)
    key = JWT::JWK.new(REQUEST_KEY.public_key).export
    [{use: "enc"}, {alg: "RS512"}, {key_ops: ["sign"]}].each do |changes|
      @db[:oauth_applications].update(jwks: JSON.generate(keys: [key.merge(changes)]))
      assert_error post("/backchannel-authentication", request: signed_ciba_request), "invalid_request"
    end
    @db[:oauth_applications].update(jwks: JSON.generate(keys: [JWT::JWK.new(KEY.public_key).export, key]))
    assert_equal 200, post("/backchannel-authentication", request: signed_ciba_request).status
    token = signed_ciba_request
    header, payload, = token.split(".")
    json = Base64.urlsafe_decode64(payload).sub('"scope":"openid"', '"scope":"openid","scope":"openid"')
    input = header + "." + Base64.urlsafe_encode64(json, padding: false)
    duplicate = input + "." + Base64.urlsafe_encode64(REQUEST_KEY.sign("SHA256", input), padding: false)
    assert_error post("/backchannel-authentication", request: duplicate), "invalid_request"
    assert_error poll(existing), "authorization_pending"
  end

  def test_signed_request_claims_resources_and_rar_use_only_inner_values
    enable_signed_requests
    Rodauth::CibaSupport::Schema.add_claims(@db)
    Rodauth::CibaSupport::Schema.add_resources(@db)
    Rodauth::CibaSupport::Schema.add_authorization_details(@db)
    @db[:oauth_applications].update(authorization_details_types: JSON.generate(["support_data"]))
    @app.plugin(:rodauth) do
      ciba_claims_enabled true
      ciba_resources_enabled true
      ciba_resource_servers("https://api.example.test" => {scopes: ["read"], audience: "api"})
      ciba_authorization_details_enabled true
      ciba_authorization_details_types ["support_data"]
      ciba_validate_authorization_details { |details, oauth_application:| details.all? { |d| d["type"] == "support_data" } }
      ciba_authorization_details_for_token { |requested:, approved:, narrowing:, resource:, oauth_application:| [] }
    end
    response = post("/backchannel-authentication", request: signed_ciba_request({
      requested_expiry: "123", resource: ["https://api.example.test"], claims: {id_token: {email: nil}},
      authorization_details: [{type: "support_data", actions: ["read"]}]}), resource: "https://untrusted.example")
    assert_equal 200, response.status, response.body
    row = @db[:ciba_requests].first
    assert_equal ["https://api.example.test"], JSON.parse(row[:requested_resources])
    assert_equal({"id_token" => {"email" => nil}}, JSON.parse(row[:requested_claims]))
    assert_equal [{"type" => "support_data", "actions" => ["read"]}], JSON.parse(row[:requested_authorization_details])
  end
end
