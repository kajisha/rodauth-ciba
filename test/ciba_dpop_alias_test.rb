# frozen_string_literal: true
require_relative "ciba_dpop_test"
require_relative "ciba_refresh_test"

class CibaIntegrationTest
  def test_dpop_alias_opaque_target_binding
    assert_dpop_alias_target_binding(false)
  end

  def test_dpop_alias_jwt_target_binding
    assert_dpop_alias_target_binding(true)
  end

  def assert_dpop_alias_target_binding(jwt)
    configure_ciba_dpop
    enable_refresh
    @app.plugin(:rodauth) do
      base_url "https://op.example.test"
      authorization_server_url "https://op.example.test"
      oauth_jwt_access_tokens jwt
    end
    alias_origin = "https://alias.example.test:8443"
    token_uri = "#{alias_origin}/token"
    userinfo_uri = "#{alias_origin}/userinfo"
    started = post("/backchannel-authentication", scope: "openid offline_access", login_hint: "customer@example.test")
    assert_equal 200, started.status, started.body
    id = JSON.parse(started.body).fetch("auth_req_id")
    approve(id)
    send_token = lambda do |params, uri|
      Rack::MockRequest.new(@app).post(token_uri, params: params,
        "HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64('support:test-secret')}",
        "HTTP_DPOP" => ciba_dpop_proof({htu: uri}))
    end
    params = {grant_type: GRANT, auth_req_id: id}
    assert_error send_token.call(params, "https://op.example.test/token"), "invalid_dpop_proof"
    [{"HTTP_FORWARDED" => 'host="op.example.test";proto=https'},
     {"HTTP_X_FORWARDED_HOST" => "op.example.test", "HTTP_X_FORWARDED_PROTO" => "https"}].each do |headers|
      spoofed = Rack::MockRequest.new(@app).post(token_uri, headers.merge(params: params,
        "HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64('support:test-secret')}",
        "HTTP_DPOP" => ciba_dpop_proof({htu: "https://op.example.test/token"})))
      assert_error spoofed, "invalid_dpop_proof"
    end
    assert_equal "approved", @db[:ciba_requests].get(:status)
    assert_equal 0, @db[:oauth_grants].count
    issued = send_token.call(params, token_uri)
    assert_equal 200, issued.status, issued.body
    payload, identity = decode_id_token(issued)
    refute identity.key?("cnf"), "ID Token must not inherit access-token sender binding"
    assert_equal "https://op.example.test", identity.fetch("iss")
    token = payload.fetch("access_token")
    ath = Base64.urlsafe_encode64(Digest::SHA256.digest(token), padding: false)
    ["https://op.example.test/userinfo", "#{alias_origin}/wrong", userinfo_uri].each do |target|
      response = Rack::MockRequest.new(@app).get(userinfo_uri,
        "HTTP_AUTHORIZATION" => "DPoP #{token}",
        "HTTP_DPOP" => ciba_dpop_proof({htu: target, htm: "GET", ath: ath}))
      assert_equal target == userinfo_uri ? 200 : 401, response.status, response.body
      assert_equal @account_id.to_s, JSON.parse(response.body).fetch("sub") if response.status == 200
    end
    refresh = {grant_type: "refresh_token", refresh_token: payload.fetch("refresh_token")}
    assert_error send_token.call(refresh, "https://op.example.test/token"), "invalid_dpop_proof"
    refreshed = send_token.call(refresh, token_uri)
    assert_equal 200, refreshed.status, refreshed.body
    refute decode_id_token(refreshed).last.key?("cnf")
    # The alias proof does not work at the canonical endpoint either.
    assert_error post("/token", refresh, "HTTP_DPOP" => ciba_dpop_proof({htu: token_uri})), "invalid_dpop_proof"
    @app.plugin(:rodauth) do
      ciba_dpop_endpoint_uri { request.env.fetch("test.trusted_external_url") }
    end
    trusted = post("/token", refresh, "HTTP_DPOP" => ciba_dpop_proof({htu: token_uri}),
      "test.trusted_external_url" => token_uri)
    assert_equal 200, trusted.status, trusted.body
  end
end
