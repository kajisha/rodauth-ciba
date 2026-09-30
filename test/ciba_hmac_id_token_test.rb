# frozen_string_literal: true
require_relative "ciba_id_token_hint_test"
require_relative "ciba_refresh_test"
require_relative "ciba_pairwise_test"

class CibaIntegrationTest
  def test_ciba_hmac_registration_generates_sufficient_client_secret
    configure_dynamic_registration
    @db.alter_table(:oauth_applications) { add_column :id_token_signed_response_alg, String }
    @app.plugin(:rodauth) do
      oauth_applications_client_secret_hash_column :client_secret
      oauth_jwt_keys("RS256" => KEY, "HS256" => "o" * 64, "HS384" => "o" * 64, "HS512" => "o" * 64)
    end
    %w[HS256 HS384 HS512].each do |algorithm|
      registered = register(registration_params.merge("id_token_signed_response_alg" => algorithm))
      assert_equal 201, registered.status, registered.body
      client = JSON.parse(registered.body)
      secret = client.fetch("client_secret")
      assert_operator secret.bytesize, :>=, algorithm.delete_prefix("HS").to_i / 8
      saved = @db[:oauth_applications].where(client_id: client.fetch("client_id")).first
      refute_equal secret, saved.fetch(:client_secret)
      headers = {"HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64("#{client.fetch('client_id')}:#{secret}")}"}
      started = post("/backchannel-authentication", {scope: "openid", login_hint: "customer@example.test"}, headers)
      assert_equal 200, started.status, started.body
      id = JSON.parse(started.body).fetch("auth_req_id")
      approve(id)
      issued = post("/token", {grant_type: GRANT, auth_req_id: id}, headers)
      assert_equal 200, issued.status, issued.body
      claims, = JWT.decode(JSON.parse(issued.body).fetch("id_token"), secret, true, algorithms: [algorithm],
        verify_iss: true, iss: "https://op.example.test", verify_aud: true, aud: client.fetch("client_id"))
      assert_equal @account_id.to_s, claims.fetch("sub")
    end
  end

  def test_ciba_hmac_secret_callback_and_missing_secret_rollback
    enable_id_hint
    configure_pairwise
    @db.alter_table(:oauth_applications) { add_column :id_token_signed_response_alg, String }
    secret = "c" * 64
    op_secret = "o" * 64
    @app.plugin(:rodauth) do
      oauth_applications_client_secret_hash_column :client_secret
      oauth_jwt_keys("RS256" => KEY, "HS256" => op_secret)
    end
    @db[:oauth_applications].update(subject_type: "public", client_secret: auth.send(:secret_hash, secret), id_token_signed_response_alg: "HS256")
    send_request = lambda do |path, params|
      post(path, pairwise_assertion.merge(params), "HTTP_AUTHORIZATION" => nil, "test.processing_error" => ->(_) {})
    end
    started = send_request.call("/backchannel-authentication", scope: "openid", login_hint: "customer@example.test")
    assert_equal 200, started.status, started.body
    id = JSON.parse(started.body).fetch("auth_req_id")
    approve(id)
    [nil, "short"].each do |unusable|
      @app.plugin(:rodauth) { ciba_id_token_hmac_secret { |oauth_application:| unusable } }
      failed = send_request.call("/token", grant_type: GRANT, auth_req_id: id)
      assert_equal 500, failed.status, failed.body
      assert_equal "approved", @db[:ciba_requests].get(:status)
      assert_equal 0, @db[:oauth_grants].count
    end
    client_ids = []
    @app.plugin(:rodauth) do
      ciba_id_token_hmac_secret do |oauth_application:|
        client_ids << oauth_application.fetch(:client_id)
        secret
      end
    end
    issued = send_request.call("/token", grant_type: GRANT, auth_req_id: id)
    assert_equal 200, issued.status, issued.body
    token = JSON.parse(issued.body).fetch("id_token")
    claims, = JWT.decode(token, secret, true, algorithms: ["HS256"])
    assert_equal @account_id.to_s, claims.fetch("sub")
    hint = send_request.call("/backchannel-authentication", scope: "openid", id_token_hint: token)
    assert_equal 200, hint.status, hint.body
    assert_equal ["support", "support"], client_ids
    ordinary = auth.send(:jwt_encode, {sub: "ordinary", iat: Time.now.to_i}, signing_algorithm: "HS256", headers: {typ: "id_token+jwt"})
    assert_equal "ordinary", JWT.decode(ordinary, op_secret, true, algorithms: ["HS256"]).first.fetch("sub")
  end

  def test_ciba_hmac_id_tokens_use_authenticated_client_secret
    enable_id_hint
    enable_refresh
    @db.alter_table(:oauth_applications) { add_column :id_token_signed_response_alg, String }
    secret = "c" * 64
    op_secret = "o" * 64
    vectors = []
    [false, true].product(%w[client_secret_basic client_secret_post], %w[HS256 HS384 HS512]).each do |hashed, method, algorithm|
      @app.plugin(:rodauth) do
        oauth_applications_client_secret_hash_column(hashed ? :client_secret : nil)
        oauth_jwt_keys("RS256" => KEY, algorithm => op_secret)
      end
      @db[:oauth_applications].update(client_secret: hashed ? auth.send(:secret_hash, secret) : secret,
        token_endpoint_auth_method: method, id_token_signed_response_alg: algorithm)
      send_request = lambda do |path, params|
        if method == "client_secret_basic"
          post(path, params, "HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64("support:#{secret}")}")
        else
          post(path, params.merge(client_id: "support", client_secret: secret), "HTTP_AUTHORIZATION" => nil)
        end
      end
      started = send_request.call("/backchannel-authentication", scope: "openid offline_access", login_hint: "customer@example.test")
      assert_equal 200, started.status, started.body
      id = JSON.parse(started.body).fetch("auth_req_id")
      approve(id)
      issued = send_request.call("/token", grant_type: GRANT, auth_req_id: id)
      assert_equal 200, issued.status, issued.body
      tokens = JSON.parse(issued.body)
      renewed = send_request.call("/token", grant_type: "refresh_token", refresh_token: tokens.fetch("refresh_token"))
      assert_equal 200, renewed.status, renewed.body
      [tokens, JSON.parse(renewed.body)].each do |response|
        token = response.fetch("id_token")
        claims, = JWT.decode(token, secret, true, algorithms: [algorithm], verify_iss: true,
          iss: "https://op.example.test", verify_aud: true, aud: "support")
        assert_equal @account_id.to_s, claims.fetch("sub")
        vectors << {algorithm: algorithm, method: method, hashed: hashed, token: token,
          access_token: response.fetch("access_token"), checked_at: Time.now.to_i}
        assert_raises(JWT::VerificationError) { JWT.decode(token, op_secret, true, algorithms: [algorithm]) }
        hint = send_request.call("/backchannel-authentication", scope: "openid", id_token_hint: token)
        assert_equal 200, hint.status, hint.body
        forged = JWT.encode(claims, op_secret, algorithm)
        count = @db[:ciba_requests].count
        assert_error send_request.call("/backchannel-authentication", scope: "openid", id_token_hint: forged), "invalid_request"
        assert_equal count, @db[:ciba_requests].count
      end
    end
    File.write(ENV.fetch("CIBA_HMAC_ID_TOKEN_EXPORT"), JSON.pretty_generate(vectors) + "\n") if ENV["CIBA_HMAC_ID_TOKEN_EXPORT"]
  end
end
