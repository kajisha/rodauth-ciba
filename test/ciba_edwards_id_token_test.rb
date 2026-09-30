# frozen_string_literal: true
require_relative "ciba_id_token_hint_test"
require_relative "ciba_registration_test"
require_relative "ciba_refresh_test"
require_relative "ciba_pairwise_test"

class CibaIntegrationTest
  def test_edwards_id_token_refresh_public_subject
    assert_edwards_refresh_subject(false)
  end

  def test_edwards_id_token_refresh_pairwise_subject
    assert_edwards_refresh_subject(true)
  end

  def assert_edwards_refresh_subject(pairwise)
    @app.plugin(:rodauth) { ciba_authentication_claims_by_scope("openid" => %w[auth_time acr amr]) }
    configure_pairwise if pairwise
    enable_refresh
    @db.alter_table(:oauth_applications) { add_column :id_token_signed_response_alg, String }
    %w[Ed25519 EdDSA].product([false, true]).each do |algorithm, jwt|
      key = OpenSSL::PKey.generate_key("ED25519")
      @app.plugin(:rodauth) do
        ciba_id_token_signing_keys(algorithm => key)
        oauth_jwt_access_tokens jwt
      end
      @db[:oauth_applications].update(id_token_signed_response_alg: algorithm)
      request = lambda do |path, parameters, extra_env = {}|
        if pairwise
          post(path, pairwise_assertion.merge(parameters), {"HTTP_AUTHORIZATION" => nil}.merge(extra_env))
        else
          post(path, parameters, extra_env)
        end
      end
      response = request.call("/backchannel-authentication", scope: "openid offline_access", login_hint: "customer@example.test")
      assert_equal 200, response.status, response.body
      id = JSON.parse(response.body).fetch("auth_req_id")
      approve(id, auth_time: 123, acr: "customer", amr: ["pwd"])
      response = request.call("/token", grant_type: GRANT, auth_req_id: id)
      assert_equal 200, response.status, response.body
      initial = JSON.parse(response.body)
      expected_subject = pairwise ? OpenSSL::HMAC.hexdigest("SHA256", "pairwise-test-secret",
        JSON.generate(["keys.example.test", @account_id])) : @account_id.to_s
      verify = lambda do |tokens, signing_key|
        parts = tokens.fetch("id_token").split(".")
        assert signing_key.verify(nil, Base64.urlsafe_decode64(parts.last), parts.first(2).join("."))
        claims, header = JWT.decode(tokens.fetch("id_token"), nil, false)
        assert_equal algorithm, header.fetch("alg")
        assert_equal expected_subject, claims.fetch("sub")
        assert_equal "support", claims.fetch("aud")
        assert_equal 123, claims.fetch("auth_time")
        assert_equal ["pwd"], claims.fetch("amr")
        assert_equal Base64.urlsafe_encode64(Digest::SHA512.digest(tokens.fetch("access_token"))[0, 32], padding: false), claims.fetch("at_hash")
        header.fetch("kid")
      end
      old_kid = verify.call(initial, key)
      refresh = initial.fetch("refresh_token")
      source = @db[:ciba_refresh_tokens].where(token_digest: Digest::SHA256.hexdigest(refresh))
      source.update(issued_at: Time.now.to_i - 800, expires_at: Time.now.to_i + 200)
      before_count = @db[:oauth_grants].count
      failed = request.call("/token", {grant_type: "refresh_token", refresh_token: refresh},
        "test.fail_signing" => true, "test.processing_error" => ->(_) {})
      assert_equal 500, failed.status, failed.body
      assert_nil source.get(:consumed_at)
      assert_equal before_count, @db[:oauth_grants].count
      replacement = OpenSSL::PKey.generate_key("ED25519")
      @app.plugin(:rodauth) { ciba_id_token_signing_keys(algorithm => [replacement, OpenSSL::PKey.read(key.public_to_der)]) }
      response = request.call("/token", grant_type: "refresh_token", refresh_token: refresh)
      assert_equal 200, response.status, response.body
      renewed = JSON.parse(response.body)
      refute_equal old_kid, verify.call(renewed, replacement)
      refute_equal refresh, renewed.fetch("refresh_token")
      refute_nil source.get(:consumed_at)
      userinfo = Rack::MockRequest.new(@app).get("https://op.example.test/userinfo",
        "HTTP_AUTHORIZATION" => "Bearer #{renewed.fetch('access_token')}")
      assert_equal 200, userinfo.status, userinfo.body
      assert_equal expected_subject, JSON.parse(userinfo.body).fetch("sub")
      assert_error request.call("/token", grant_type: "refresh_token", refresh_token: refresh), "invalid_grant"
      assert_error request.call("/token", grant_type: "refresh_token", refresh_token: renewed.fetch("refresh_token")), "invalid_grant"
    end
  end

  def test_edwards_id_token_issuance_public_keys_and_hints
    enable_id_hint
    @db.alter_table(:oauth_applications) { add_column :id_token_signed_response_alg, String }
    key = OpenSSL::PKey.generate_key("ED25519")
    configured = {"Ed25519" => key, "EdDSA" => key}
    @app.plugin(:rodauth) { ciba_id_token_signing_keys configured }
    metadata = JSON.parse(Rack::MockRequest.new(@app).get("https://op.example.test/.well-known/openid-configuration").body)
    %w[Ed25519 EdDSA].each do |algorithm|
      assert_includes metadata.fetch("id_token_signing_alg_values_supported"), algorithm
      @db[:oauth_applications].update(id_token_signed_response_alg: algorithm)
      id = accept_request
      approve(id)
      response = poll(id)
      assert_equal 200, response.status, response.body
      tokens = JSON.parse(response.body)
      token = tokens.fetch("id_token")
      parts = token.split(".")
      claims, header = JWT.decode(token, nil, false)
      assert_equal algorithm, header.fetch("alg")
      assert key.verify(nil, Base64.urlsafe_decode64(parts.last), parts.first(2).join("."))
      assert_equal @account_id.to_s, claims.fetch("sub")
      assert_equal "support", claims.fetch("aud")
      assert_equal Base64.urlsafe_encode64(Digest::SHA512.digest(tokens.fetch("access_token"))[0, 32], padding: false), claims.fetch("at_hash")
      jwks = JSON.parse(Rack::MockRequest.new(@app).get(metadata.fetch("jwks_uri")).body).fetch("keys")
      public_key = jwks.find { |item| item["kid"] == header["kid"] && item["alg"] == algorithm }
      assert_equal "OKP", public_key.fetch("kty")
      assert_equal "Ed25519", public_key.fetch("crv")
      refute public_key.key?("d")
      assert_equal OpenSSL::ASN1.decode(key.public_to_der).value.last.value, Base64.urlsafe_decode64(public_key.fetch("x"))
      assert jwks.any? { |item| item["kty"] == "RSA" }
      result = request_id_hint(token)
      assert_equal 200, result.status, result.body
      assert_error poll(JSON.parse(result.body).fetch("auth_req_id")), "authorization_pending"
      profile_header = header.merge("typ" => "at+jwt", "b64" => true, "crit" => ["b64"])
      profile_claims = claims.reject { |name, _| %w[iat exp].include?(name) }.merge("azp" => "other")
      profile_input = [profile_header, profile_claims].map { |part| Base64.urlsafe_encode64(JSON.generate(part), padding: false) }.join(".")
      profile_token = profile_input + "." + Base64.urlsafe_encode64(key.sign(nil, profile_input), padding: false)
      profile = request_id_hint(profile_token)
      assert_equal 200, profile.status, profile.body
      assert_error poll(JSON.parse(profile.body).fetch("auth_req_id")), "authorization_pending"
      count = @db[:ciba_requests].count
      wrong = OpenSSL::PKey.generate_key("ED25519")
      forged = (parts.first(2) + [Base64.urlsafe_encode64(wrong.sign(nil, parts.first(2).join(".")), padding: false)]).join(".")
      assert_error request_id_hint(forged), "invalid_request"
      assert_equal count, @db[:ciba_requests].count
      [{"iss" => "https://foreign.example"}, {"aud" => "other"}, {"sub" => nil},
       {"nbf" => Time.now.to_i + 3600}].each do |changed|
        modified = [parts.first, Base64.urlsafe_encode64(JSON.generate(claims.merge(changed)), padding: false)]
        invalid = (modified + [Base64.urlsafe_encode64(key.sign(nil, modified.join(".")), padding: false)]).join(".")
        assert_error request_id_hint(invalid), "invalid_request"
      end
      expired_parts = [parts.first, Base64.urlsafe_encode64(JSON.generate(claims.merge("iat" => Time.now.to_i - 7200, "exp" => Time.now.to_i - 3600)), padding: false)]
      expired = (expired_parts + [Base64.urlsafe_encode64(key.sign(nil, expired_parts.join(".")), padding: false)]).join(".")
      assert_equal 200, request_id_hint(expired).status
      replacement = OpenSSL::PKey.generate_key("ED25519")
      retained = configured.merge(algorithm => [replacement, OpenSSL::PKey.read(key.public_to_der)])
      @app.plugin(:rodauth) { ciba_id_token_signing_keys retained }
      assert_equal 200, request_id_hint(token).status
      removed = configured.merge(algorithm => replacement)
      @app.plugin(:rodauth) { ciba_id_token_signing_keys removed }
      assert_error request_id_hint(token), "invalid_request"
      @app.plugin(:rodauth) { ciba_id_token_signing_keys configured }
    end
  end
  def test_edwards_id_token_registration_requires_configured_keys
    configure_dynamic_registration
    @db.alter_table(:oauth_applications) { add_column :id_token_signed_response_alg, String }
    %w[Ed25519 EdDSA].each do |algorithm|
      params = registration_params.merge("id_token_signed_response_alg" => algorithm)
      @app.plugin(:rodauth) { ciba_id_token_signing_keys({}) }
      assert_error register(params), "invalid_client_metadata"
      keys = {algorithm => OpenSSL::PKey.generate_key("ED25519")}
      @app.plugin(:rodauth) { ciba_id_token_signing_keys keys }
      result = register(params)
      assert_equal 201, result.status, result.body
      assert_equal algorithm, JSON.parse(result.body).fetch("id_token_signed_response_alg")
    end
  end

  def test_edwards_id_token_encryption_does_not_silently_fall_back_to_plaintext
    @db.alter_table(:oauth_applications) do
      add_column :id_token_signed_response_alg, String
      add_column :id_token_encrypted_response_alg, String
      add_column :id_token_encrypted_response_enc, String
    end
    key = OpenSSL::PKey.generate_key("ED25519")
    @app.plugin(:rodauth) { ciba_id_token_signing_keys("Ed25519" => key) }
    @db[:oauth_applications].update(id_token_signed_response_alg: "Ed25519",
      id_token_encrypted_response_alg: "RSA-OAEP-256", id_token_encrypted_response_enc: "A256GCM")
    id = accept_request
    approve(id)
    errors = []
    response = poll(id, "test.processing_error" => ->(error) { errors << error })
    assert_equal 500, response.status
    assert_equal "server_error", JSON.parse(response.body).fetch("error")
    assert_equal [Rodauth::CibaSupport::ConfigurationError], errors.map(&:class)
    assert_equal "approved", @db[:ciba_requests].get(:status)
    assert_equal 0, @db[:oauth_grants].count
    @db[:oauth_applications].update(id_token_encrypted_response_alg: nil, id_token_encrypted_response_enc: nil)
    assert_equal 200, poll(id).status
  end

end
