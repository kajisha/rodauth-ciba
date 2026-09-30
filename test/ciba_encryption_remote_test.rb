# frozen_string_literal: true
require_relative "ciba_remote_jwks_test"
require_relative "ciba_refresh_test"
require_relative "ciba_pairwise_test"

class CibaIntegrationTest
  def test_symmetric_encryption_does_not_fetch_unrelated_jwks
    with_client_jwks_server do |state, uri, _server|
      enable_refresh
      @db.alter_table(:oauth_applications) do
        add_column :id_token_encrypted_response_alg, String
        add_column :id_token_encrypted_response_enc, String
      end
      @db[:oauth_applications].update(backchannel_authentication_request_signing_alg: nil,
        id_token_encrypted_response_alg: "dir", id_token_encrypted_response_enc: "A256GCM")
      @app.plugin(:rodauth) { ciba_id_token_encryption_enabled true }
      state[:status] = 503
      started = post("/backchannel-authentication", scope: "openid offline_access", login_hint: "customer@example.test")
      assert_equal 200, started.status, started.body
      id = JSON.parse(started.body).fetch("auth_req_id")
      approve(id)
      issued = poll(id, "test.processing_error" => ->(_) {})
      assert_equal 200, issued.status, issued.body
      renewed = refresh_with(JSON.parse(issued.body).fetch("refresh_token"), {}, "test.processing_error" => ->(_) {})
      assert_equal 200, renewed.status, renewed.body
      assert_equal 0, state[:requests]
    end
  end

  def test_symmetric_encryption_retains_remote_client_authentication
    with_client_jwks_server do |state, uri, _server|
      @db.alter_table(:oauth_applications) do
        add_column :id_token_encrypted_response_alg, String
        add_column :id_token_encrypted_response_enc, String
      end
      @db[:oauth_applications].update(backchannel_authentication_request_signing_alg: nil,
        token_endpoint_auth_method: "private_key_jwt", id_token_encrypted_response_alg: "dir",
        id_token_encrypted_response_enc: "A256GCM")
      @app.plugin(:rodauth) do
        enable :oauth_jwt_bearer_grant
        ciba_id_token_encryption_enabled true
        ciba_id_token_encryption_secret { |oauth_application:| "application-secret" }
      end
      state[:keys] = [JWT::JWK.new(KEY.public_key).export]
      send_request = lambda do |path, params|
        post(path, pairwise_assertion.merge(params), "HTTP_AUTHORIZATION" => nil,
          "test.processing_error" => ->(_) {})
      end
      started = send_request.call("/backchannel-authentication", scope: "openid", login_hint: "customer@example.test")
      assert_equal 200, started.status, started.body
      assert_equal 1, state[:requests]
      id = JSON.parse(started.body).fetch("auth_req_id")
      approve(id)
      auth.send(:http_request_cache).uncache(URI(uri))
      state[:keys] = [JWT::JWK.new(REQUEST_KEY.public_key).export]
      denied = send_request.call("/token", grant_type: GRANT, auth_req_id: id)
      assert_equal 401, denied.status, denied.body
      assert_equal 2, state[:requests]
      assert_equal 0, @db[:oauth_grants].count
      assert_equal "approved", @db[:ciba_requests].get(:status)
      auth.send(:http_request_cache).uncache(URI(uri))
      state[:keys] = [JWT::JWK.new(KEY.public_key).export]
      issued = send_request.call("/token", grant_type: GRANT, auth_req_id: id)
      assert_equal 200, issued.status, issued.body
      assert_equal 3, state[:requests] # Authentication only; no recipient fetch.
      claims, = JWT.decode(JWE.decrypt(JSON.parse(issued.body).fetch("id_token"),
        OpenSSL::Digest.digest("SHA256", "application-secret")), KEY.public_key, true, algorithms: ["RS256"])
      assert_equal @account_id.to_s, claims.fetch("sub")
    end
  end

  def test_encryption_recipient_remote_failures_opaque
    assert_encryption_remote_failures(false)
  end

  def test_encryption_recipient_remote_failures_jwt
    assert_encryption_remote_failures(true)
  end

  def assert_encryption_remote_failures(jwt)
    with_client_jwks_server do |state, uri, _server|
      enable_refresh
      @db.alter_table(:oauth_applications) do
        add_column :id_token_encrypted_response_alg, String
        add_column :id_token_encrypted_response_enc, String
      end
      @db[:oauth_applications].update(backchannel_authentication_request_signing_alg: nil,
        id_token_encrypted_response_alg: "RSA-OAEP-256", id_token_encrypted_response_enc: "A256GCM")
      @app.plugin(:rodauth) do
        ciba_id_token_encryption_enabled true
        oauth_jwt_access_tokens jwt
      end
      state[:keys] = [JWT::JWK.new(KEY.public_key).export.merge(use: "enc", alg: "RSA-OAEP-256")]
      started = post("/backchannel-authentication", scope: "openid offline_access", login_hint: "customer@example.test")
      assert_equal 200, started.status, started.body
      id = JSON.parse(started.body).fetch("auth_req_id")
      approve(id)
      failures = [[503, nil], [200, "not json"], [200, " " * 65_537], [302, nil]]
      failures.each do |status, body|
        auth.send(:http_request_cache).uncache(URI(uri))
        state[:status], state[:body] = status, body
        response = poll(id, "test.processing_error" => ->(_) {})
        assert_equal 500, response.status, response.body
        assert_equal 0, @db[:oauth_grants].count
        assert_equal "approved", @db[:ciba_requests].get(:status)
      end
      state[:status], state[:body] = 200, nil
      issued = poll(id)
      assert_equal 200, issued.status, issued.body
      tokens = JSON.parse(issued.body)
      signed = JWE.decrypt(tokens.fetch("id_token"), KEY)
      claims, = JWT.decode(signed, KEY.public_key, true, algorithms: ["RS256"])
      assert_equal @account_id.to_s, claims.fetch("sub")
      refresh = tokens.fetch("refresh_token")
      @db[:ciba_refresh_tokens].update(issued_at: Time.now.to_i - 800, expires_at: Time.now.to_i + 200)
      failures.each do |status, body|
        auth.send(:http_request_cache).uncache(URI(uri))
        state[:status], state[:body] = status, body
        response = refresh_with(refresh, {}, "test.processing_error" => ->(_) {})
        assert_equal 500, response.status, response.body
        assert_equal 1, @db[:oauth_grants].count
        assert_equal 1, @db[:ciba_refresh_tokens].count
        assert_nil @db[:ciba_refresh_tokens].get(:consumed_at)
      end
      state[:status], state[:body] = 200, nil
      renewed = refresh_with(refresh)
      assert_equal 200, renewed.status, renewed.body
      refute_equal refresh, JSON.parse(renewed.body).fetch("refresh_token")
    end
  end
end
