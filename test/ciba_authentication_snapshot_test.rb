# frozen_string_literal: true
require_relative "ciba_pairwise_test"

class CibaIntegrationTest
  def test_authenticated_pairwise_snapshot_survives_management_before_opaque_issuance
    assert_authenticated_pairwise_snapshot(false)
  end

  def test_authenticated_pairwise_snapshot_survives_management_before_jwt_issuance
    assert_authenticated_pairwise_snapshot(true)
  end

  def assert_authenticated_pairwise_snapshot(jwt)
    configure_dynamic_registration
    configure_pairwise
    new_key = OpenSSL::PKey::RSA.generate(2048)
    @app.plugin(:rodauth) do
      oauth_jwt_access_tokens jwt
      auth_class_eval do
        define_method(:oauth_application_jwks) do |application|
          key = application[:jwks_uri] == "https://keys.example.test/jwks" ? CibaIntegrationTest::KEY : new_key
          {keys: [JWT::JWK.new(key.public_key).export]}
        end
      end
    end
    response = post("/backchannel-authentication", pairwise_assertion.merge(scope: "openid",
      login_hint: "customer@example.test"), "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body).fetch("auth_req_id")
    approve(id)
    management_token, credentials = auth.send(:ciba_new_registration_credentials)
    @db[:oauth_applications].where(id: @client_id).update(credentials)
    replacement = registration_params.merge("client_id" => "support", "subject_type" => "pairwise",
      "token_endpoint_auth_method" => "private_key_jwt", "jwks_uri" => "https://other-sector.example.test/jwks")
    updated = nil
    # This hook runs after real client authentication and before the token
    # transaction starts, so DCR can commit on every supported database.
    change = lambda do
      updated = Rack::MockRequest.new(@app).put("https://op.example.test/register/support",
        "HTTP_AUTHORIZATION" => "Bearer #{management_token}", "CONTENT_TYPE" => "application/json",
        input: JSON.generate(replacement))
    end
    response = post("/token", pairwise_assertion.merge(grant_type: GRANT, auth_req_id: id),
      "HTTP_AUTHORIZATION" => nil, "test.token_gate" => change)
    assert_equal 200, updated.status, updated.body
    assert_equal 200, response.status, response.body
    tokens, claims = decode_id_token(response)
    old_subject = OpenSSL::HMAC.hexdigest("SHA256", "pairwise-test-secret", JSON.generate(["keys.example.test", @account_id]))
    assert_equal old_subject, claims.fetch("sub")
    assert_equal old_subject, @db[:oauth_grants].get(:ciba_subject)
    if jwt
      access, = JWT.decode(tokens.fetch("access_token"), KEY.public_key, true, algorithms: ["RS256"])
      assert_equal old_subject, access.fetch("sub")
    end
    info = Rack::MockRequest.new(@app).get("https://op.example.test/userinfo",
      "HTTP_AUTHORIZATION" => "Bearer #{tokens.fetch('access_token')}")
    assert_equal 200, info.status, info.body
    assert_equal old_subject, JSON.parse(info.body).fetch("sub")
    rejected = post("/token", pairwise_assertion.merge(grant_type: GRANT, auth_req_id: id), "HTTP_AUTHORIZATION" => nil)
    assert_equal 401, rejected.status, rejected.body
    assertion = JWT.encode({iss: "support", sub: "support", aud: "https://op.example.test",
      exp: Time.now.to_i + 60, jti: SecureRandom.uuid}, new_key, "RS256", kid: JWT::JWK.new(new_key).kid)
    response = post("/backchannel-authentication", pairwise_assertion.merge(client_assertion: assertion,
      scope: "openid", login_hint: "customer@example.test"), "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body).fetch("auth_req_id")
    approve(id)
    assertion = JWT.encode({iss: "support", sub: "support", aud: "https://op.example.test",
      exp: Time.now.to_i + 60, jti: SecureRandom.uuid}, new_key, "RS256", kid: JWT::JWK.new(new_key).kid)
    response = post("/token", pairwise_assertion.merge(client_assertion: assertion,
      grant_type: GRANT, auth_req_id: id), "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, response.status, response.body
    _, current = decode_id_token(response)
    new_subject = OpenSSL::HMAC.hexdigest("SHA256", "pairwise-test-secret", JSON.generate(["other-sector.example.test", @account_id]))
    assert_equal new_subject, current.fetch("sub")
  end

  def test_issued_pairwise_subject_survives_public_management_with_opaque_token
    assert_issued_pairwise_subject_after_public_management(false)
  end

  def test_issued_pairwise_subject_survives_public_management_with_jwt_token
    assert_issued_pairwise_subject_after_public_management(true)
  end

  def assert_issued_pairwise_subject_after_public_management(jwt)
    configure_dynamic_registration
    configure_pairwise
    @app.plugin(:rodauth) { oauth_jwt_access_tokens jwt }
    response = post("/backchannel-authentication", pairwise_assertion.merge(scope: "openid",
      login_hint: "customer@example.test"), "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body).fetch("auth_req_id")
    approve(id)
    response = post("/token", pairwise_assertion.merge(grant_type: GRANT, auth_req_id: id), "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, response.status, response.body
    tokens, claims = decode_id_token(response)
    management_token, credentials = auth.send(:ciba_new_registration_credentials)
    @db[:oauth_applications].where(id: @client_id).update(credentials)
    replacement = registration_params.merge("client_id" => "support", "subject_type" => "public")
    updated = Rack::MockRequest.new(@app).put("https://op.example.test/register/support",
      "HTTP_AUTHORIZATION" => "Bearer #{management_token}", "CONTENT_TYPE" => "application/json",
      input: JSON.generate(replacement))
    assert_equal 200, updated.status, updated.body
    info = Rack::MockRequest.new(@app).get("https://op.example.test/userinfo",
      "HTTP_AUTHORIZATION" => "Bearer #{tokens.fetch('access_token')}")
    assert_equal 200, info.status, info.body
    assert_equal claims.fetch("sub"), JSON.parse(info.body).fetch("sub")
    # New authentications still use the newly registered public subject.
    id = accept_request
    approve(id)
    _, current = decode_id_token(poll(id))
    assert_equal @account_id.to_s, current.fetch("sub")
  end
end
