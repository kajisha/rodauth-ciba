# frozen_string_literal: true
require_relative "test_helper"

class CibaIntegrationTest
  def security_jwt_client
    @db.alter_table(:oauth_applications) { add_column :jwks, String, text: true }
    @db[:oauth_applications].update(token_endpoint_auth_method: "private_key_jwt",
      jwks: JSON.generate(keys: [JWT::JWK.new(KEY.public_key).export]))
    @app.plugin(:rodauth) { enable :oauth_jwt_bearer_grant }
  end

  def security_assertion(changes = {}, omit: [], audience: "https://op.example.test")
    claims = {"iss" => "support", "sub" => "support", "aud" => audience,
      "exp" => Time.now.to_i + 60, "jti" => SecureRandom.uuid}.merge(changes)
    omit.each { |key| claims.delete(key) }
    # Sign raw JSON to exercise malformed claim types rejected by JWT.encode itself.
    parts = [{alg: "RS256", kid: JWT::JWK.new(KEY).kid}, claims].map do |part|
      Base64.urlsafe_encode64(JSON.generate(part), padding: false)
    end
    signing_input = parts.join(".")
    signing_input + "." + Base64.urlsafe_encode64(KEY.sign("SHA256", signing_input), padding: false)
  end

  def security_auth_params(assertion)
    {client_id: "support", client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: assertion}
  end

  def security_start(assertion, extra = {})
    post("/backchannel-authentication", security_auth_params(assertion).merge(
      {login_hint: "customer@example.test", scope: "openid"}).merge(extra), "HTTP_AUTHORIZATION" => nil)
  end

  def assert_invalid_client(response)
    assert_equal 401, response.status, response.body
    assert_equal "invalid_client", JSON.parse(response.body)["error"]
  end

  def test_jwt_client_assertion_requires_issuer_expiry_and_jti
    security_jwt_client
    [security_assertion({"iss" => "someone-else"}), security_assertion(omit: ["iss"]),
     security_assertion(omit: ["sub"]), security_assertion({"sub" => "someone-else"}),
     security_assertion(omit: ["exp"]), security_assertion(omit: ["jti"]),
     security_assertion({"exp" => Time.now.to_i - 1}), security_assertion({"jti" => ""})].each do |assertion|
      assert_invalid_client security_start(assertion)
    end
    assert_equal 0, @db[:ciba_requests].count
  end

  def test_jwt_client_assertion_is_single_use
    security_jwt_client
    assertion = security_assertion
    assert_equal 200, security_start(assertion).status
    assert_invalid_client security_start(assertion)
    assert_equal 1, @db[:ciba_requests].count
  end

  def test_malformed_assertions_are_authentication_errors_at_both_ciba_endpoints
    security_jwt_client
    response = security_start(security_assertion)
    id = JSON.parse(response.body).fetch("auth_req_id")
    ["not-a-jwt", JWT.encode([], KEY, "RS256")].each do |assertion|
      assert_invalid_client security_start(assertion)
      response = post("/token", security_auth_params(assertion).merge(grant_type: GRANT, auth_req_id: id),
        "HTTP_AUTHORIZATION" => nil)
      assert_invalid_client response
    end
  end

  def test_backchannel_ignores_other_grant_parameters_without_bypassing_client_authentication
    security_jwt_client
    params = {grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: security_assertion,
      login_hint: "customer@example.test", scope: "openid"}
    response = post("/backchannel-authentication", params, "HTTP_AUTHORIZATION" => nil)
    assert_invalid_client response
    assert_match(/\ABasic/, response["www-authenticate"])
    assert_equal 0, @db[:ciba_requests].count
    # Extra grant fields do not prevent a correctly authenticated CIBA request.
    assert_equal 200, security_start(security_assertion, params).status
  end
  def test_private_key_jwt_requires_client_keys_instead_of_falling_back_to_op_keys
    security_jwt_client
    @db[:oauth_applications].update(jwks: nil)
    assert_invalid_client security_start(security_assertion)
    assert_equal 0, @db[:ciba_requests].count
  end

  def test_jwt_assertion_audience_can_be_an_array_and_invalid_claim_shapes_fail
    security_jwt_client
    assert_equal 200, security_start(security_assertion({"aud" => ["https://other.example", "https://op.example.test"]})).status
    [{"aud" => []}, {"aud" => 1}, {"aud" => ["https://op.example.test", 1]},
     {"iat" => "yesterday"}, {"iat" => 1e100}, {"exp" => "tomorrow"}, {"jti" => []}].each do |claims|
      assert_invalid_client security_start(security_assertion(claims))
    end
  end

  def test_jwt_assertion_replay_is_blocked_between_start_and_poll
    security_jwt_client
    assertion = security_assertion(audience: "https://op.example.test/token")
    response = security_start(assertion)
    id = JSON.parse(response.body).fetch("auth_req_id")
    approve(id)
    response = post("/token", security_auth_params(assertion).merge(grant_type: GRANT, auth_req_id: id), "HTTP_AUTHORIZATION" => nil)
    assert_invalid_client response
    fresh = security_assertion(audience: "https://op.example.test/token")
    response = post("/token", security_auth_params(fresh).merge(grant_type: GRANT, auth_req_id: id), "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, response.status, response.body
  end

  def test_jwt_assertion_replay_is_blocked_across_other_flows_for_the_same_client
    security_jwt_client
    assertion = security_assertion(audience: "https://op.example.test/token")
    assert_equal 200, security_start(assertion).status
    @db[:oauth_grants].insert(account_id: @account_id, oauth_application_id: @client_id,
      type: "authorization_code", code: "replay-code", scopes: "openid", expires_in: Time.now + 60,
      redirect_uri: "https://rp.example.test/callback")
    response = post("/token", security_auth_params(assertion).merge(grant_type: "authorization_code",
      code: "replay-code", redirect_uri: "https://rp.example.test/callback"), "HTTP_AUTHORIZATION" => nil)
    assert_invalid_client response
    assert_equal "replay-code", @db[:oauth_grants].get(:code)
  end

  def test_client_assertion_unique_constraint_rejects_concurrent_replay
    security_jwt_client
    assertion = security_assertion
    ready, go = Queue.new, Queue.new
    workers = 2.times.map do
      Thread.new do
        @db.synchronize do
          ready << true
          Timeout.timeout(10) { go.pop }
          security_start(assertion)
        end
      end
    end
    Timeout.timeout(10) { 2.times { ready.pop } }
    2.times { go << true }
    responses = workers.map { |worker| Timeout.timeout(10) { worker.value } }
    assert_equal [200, 401], responses.map(&:status).sort
    assert_equal 1, @db[:ciba_requests].count
    assert_equal 1, @db[:ciba_client_assertions].count
  ensure
    workers&.each { |worker| worker.kill if worker.alive? }
    workers&.each(&:join)
  end

  def test_assertion_ledger_cleanup_preserves_unexpired_entries_and_is_bounded
    @db[:ciba_client_assertions].insert(digest: "a" * 64, expires_at: Time.now.to_i - 2)
    @db[:ciba_client_assertions].insert(digest: "b" * 64, expires_at: Time.now.to_i - 1)
    @db[:ciba_client_assertions].insert(digest: "c" * 64, expires_at: Time.now.to_i + 100)
    assert_equal 1, auth.cleanup_ciba_client_assertions(limit: 1)
    assert_equal 2, @db[:ciba_client_assertions].count
    assert_equal 1, auth.cleanup_ciba_client_assertions
    assert_equal "c" * 64, @db[:ciba_client_assertions].get(:digest)
  end

  def test_slow_down_does_not_saturate_at_the_initial_interval_limit
    @app.plugin(:rodauth) { ciba_poll_interval 2_147_483_647 }
    id = accept_request
    assert_error poll(id), "authorization_pending"
    assert_error poll(id), "slow_down"
    assert_equal 2_147_483_652, @db[:ciba_requests].get(:interval)
  end

  def test_client_secret_jwt_rejects_short_mac_keys
    @app.plugin(:rodauth) { enable :oauth_jwt_bearer_grant }
    @db[:oauth_applications].update(token_endpoint_auth_method: "client_secret_jwt")
    assertion = JWT.encode({iss: "support", sub: "support", aud: "https://op.example.test",
      exp: Time.now.to_i + 60, jti: SecureRandom.uuid}, "test-secret", "HS256")
    assert_invalid_client security_start(assertion)
  end

  def test_conflicting_form_parameter_shapes_return_invalid_request
    ["/backchannel-authentication", "/token"].each do |path|
      body = URI.encode_www_form(grant_type: GRANT, login_hint: "customer@example.test", scope: "openid") +
        "&auth_req_id=x&extra=scalar&extra[nested]=value"
      response = post(path, {}, input: body, "CONTENT_TYPE" => "application/x-www-form-urlencoded")
      assert_error response, "invalid_request"
    end
  end

  def test_assertion_subject_cannot_override_explicit_client_id
    security_jwt_client
    assert_invalid_client security_start(security_assertion, client_id: "other-client")
    assert_equal 0, @db[:ciba_requests].count
  end

  def test_ciba_token_required_parameters_and_error_response_contract
    id = accept_request
    [{auth_req_id: id}, {grant_type: GRANT}, {grant_type: GRANT, auth_req_id: ""}].each do |params|
      assert_error post("/token", params), "invalid_request"
    end
    response = poll("unissued-identifier")
    assert_error response, "invalid_grant"
    assert_match(/application\/json/, response["content-type"])
    assert_equal "no-store", response["cache-control"]
    assert_equal "no-cache", response["pragma"]
    refute JSON.parse(response.body).key?("error_uri")
    assert_equal 0, @db[:oauth_grants].count
  end

  def test_discovery_preserves_upstream_authentication_algorithms_for_both_endpoints
    security_jwt_client
    http = Rack::MockRequest.new(@app)
    oidc = JSON.parse(http.get("https://op.example.test/.well-known/openid-configuration").body)
    oauth = JSON.parse(http.get("https://op.example.test/.well-known/oauth-authorization-server").body)
    %w[token_endpoint_auth_methods_supported token_endpoint_auth_signing_alg_values_supported].each do |name|
      assert_equal oauth.fetch(name), oidc.fetch(name)
    end
    assert_includes oidc.fetch("token_endpoint_auth_signing_alg_values_supported"), "RS256"
    # The advertised RS256 private-key method really authenticates on both endpoints.
    response = security_start(security_assertion)
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body).fetch("auth_req_id")
    approve(id)
    response = post("/token", security_auth_params(security_assertion(audience: "https://op.example.test/token")).merge(
      grant_type: GRANT, auth_req_id: id), "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, response.status, response.body
  end

  def test_assertion_replay_rejection_preserves_outer_transaction
    security_jwt_client
    assertion = security_assertion
    assert_equal 200, security_start(assertion).status
    @db.transaction do
      assert_invalid_client security_start(assertion)
      @db[:accounts].insert(email: "outer-transaction@example.test")
    end
    assert @db[:accounts].where(email: "outer-transaction@example.test").any?
    assert_equal 1, @db[:ciba_client_assertions].count
  end

  def test_additional_authorized_scopes_survive_acceptance_and_token_issuance
    @app.plugin(:rodauth) { oauth_application_scopes %w[openid read] }
    @db[:oauth_applications].update(scopes: "openid read")
    response = post("/backchannel-authentication", login_hint: "customer@example.test", scope: "openid read")
    assert_equal 200, response.status, response.body
    payload = JSON.parse(response.body)
    assert_kind_of Integer, payload["interval"]
    assert_operator payload["interval"], :>, 0
    assert_equal "openid read", @db[:ciba_requests].get(:scopes)
    approve(payload.fetch("auth_req_id"))
    response = poll(payload.fetch("auth_req_id"))
    assert_equal 200, response.status, response.body
    # RFC 6749 section 5.1 permits omitting scope when it equals the requested scope.
    assert_equal "openid read", @db[:oauth_grants].get(:scopes)
    assert_equal "openid read", JSON.parse(response.body).fetch("scope", "openid read")
  end

  def test_reduced_scope_is_reported_when_offline_access_is_not_granted
    response = post("/backchannel-authentication", login_hint: "customer@example.test", scope: "openid offline_access")
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body).fetch("auth_req_id")
    approve(id)
    response = poll(id)
    assert_equal 200, response.status, response.body
    payload = JSON.parse(response.body)
    assert_equal "openid", payload["scope"]
    refute payload.key?("refresh_token")
  end

  def test_lock_timeout_returns_503_with_retry_after_and_rolls_back
    response = post("/backchannel-authentication", {login_hint: "customer@example.test", scope: "openid"},
      "test.before_request" => ->(_row) { raise Sequel::DatabaseLockTimeout, "test timeout" })
    assert_equal 503, response.status, response.body
    assert_equal "temporarily_unavailable", JSON.parse(response.body)["error"]
    assert_equal "5", response["retry-after"]
    assert_equal 0, @db[:ciba_requests].count

    id = accept_request
    approve(id)
    response = poll(id, "test.before_issue" => -> { raise Sequel::DatabaseLockTimeout, "test timeout" })
    assert_equal 503, response.status, response.body
    assert_equal "temporarily_unavailable", JSON.parse(response.body)["error"]
    assert_equal "5", response["retry-after"]
    assert_equal "approved", @db[:ciba_requests].get(:status)
    assert_equal 0, @db[:oauth_grants].count
  end

  def test_push_client_cannot_redeem_ciba_at_token_endpoint
    id = accept_request
    approve(id)
    @db[:oauth_applications].update(backchannel_token_delivery_mode: "push")
    assert_error poll(id), "unauthorized_client"
    assert_equal 0, @db[:oauth_grants].count
    assert_equal "approved", @db[:ciba_requests].get(:status)
  end

end
