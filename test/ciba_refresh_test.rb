# frozen_string_literal: true
require_relative "test_helper"
require_relative "ciba_lifecycle_test"

class CibaIntegrationTest
  def enable_refresh
    Rodauth::CibaSupport::Schema.create_refresh_tokens(@db)
    @db[:oauth_applications].update(scopes: "openid offline_access", grant_types: "#{GRANT} refresh_token")
    @app.plugin(:rodauth) do
      ciba_refresh_tokens_enabled true
      oauth_application_scopes %w[openid offline_access]
    end
  end

  def issue_refresh
    response = post("/backchannel-authentication", scope: "openid offline_access", login_hint: "customer@example.test", nonce: "initial")
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body).fetch("auth_req_id")
    approve(id, auth_time: 123, acr: "customer", amr: ["pwd"])
    issued = poll(id)
    assert_equal 200, issued.status, issued.body
    JSON.parse(issued.body).fetch("refresh_token")
  end

  def refresh_with(token, extra = {}, env = {})
    post("/token", {grant_type: "refresh_token", refresh_token: token}.merge(extra), env)
  end

  def test_ciba_refresh_preserves_source_scope_and_authentication
    @app.plugin(:rodauth) { ciba_authentication_claims_by_scope("openid" => %w[auth_time acr amr]) }
    enable_refresh
    token = issue_refresh
    row = @db[:ciba_refresh_tokens].first
    assert_equal Digest::SHA256.hexdigest(token), row[:token_digest]
    refute_includes JSON.generate(@db[:oauth_grants].all), token
    @db[:ciba_requests].delete
    assert_error refresh_with(token, scope: "openid email"), "invalid_scope"
    response = refresh_with(token, scope: "openid")
    assert_equal 200, response.status, response.body
    payload, claims = decode_id_token(response)
    assert_equal "openid", payload["scope"]
    assert_equal token, payload["refresh_token"]
    assert_equal 123, claims["auth_time"]
    assert_equal "initial", claims["nonce"]
    assert_equal ["pwd"], claims["amr"]
    again = refresh_with(token)
    assert_equal 200, again.status, again.body
    assert_equal "openid offline_access", JSON.parse(again.body)["scope"]
    assert_equal 3, @db[:oauth_grants].count
  end

  def test_ciba_auth_time_metadata_does_not_invent_authentication_time
    enable_refresh
    @db.alter_table(:oauth_applications) { add_column :require_auth_time, TrueClass }
    [nil, false, true].each do |required|
      @db[:oauth_applications].update(require_auth_time: required)
      [nil, 123].each do |time|
        response = post("/backchannel-authentication", scope: "openid offline_access", login_hint: "customer@example.test")
        assert_equal 200, response.status, response.body
        id = JSON.parse(response.body).fetch("auth_req_id")
        approve(id, **(time.nil? ? {} : {auth_time: time}))
        issued = poll(id)
        assert_equal 200, issued.status, issued.body
        refreshed = refresh_with(JSON.parse(issued.body).fetch("refresh_token"))
        assert_equal 200, refreshed.status, refreshed.body
        [issued, refreshed].each do |result|
          _, claims = decode_id_token(result)
          assert_equal required == true && !time.nil?, claims.key?("auth_time")
          assert_equal time, claims.fetch("auth_time") if required == true && !time.nil?
          assert_equal @account_id.to_s, claims.fetch("sub")
        end
      end
    end
  end

  def test_ciba_refresh_rotation_replay_and_failure_rollback
    enable_refresh
    token = issue_refresh
    now = Time.now.to_i
    @db[:ciba_refresh_tokens].update(issued_at: now - 800, expires_at: now + 200)
    failed = refresh_with(token, {}, "test.fail_signing" => true, "test.processing_error" => ->(_) {})
    assert_equal 500, failed.status, failed.body
    assert_equal 1, @db[:ciba_refresh_tokens].count
    assert_nil @db[:ciba_refresh_tokens].get(:consumed_at)
    assert_equal 1, @db[:oauth_grants].count
    issued = refresh_with(token)
    assert_equal 200, issued.status, issued.body
    successor = JSON.parse(issued.body).fetch("refresh_token")
    refute_equal token, successor
    assert_equal 2, @db[:ciba_refresh_tokens].count
    assert_error refresh_with(token), "invalid_grant"
    refute_nil @db[:ciba_grants].get(:revoked_at)
    assert_equal 0, @db[:oauth_grants].where(revoked_at: nil).count
    assert_error refresh_with(successor), "invalid_grant"
  end

  def test_ciba_refresh_deactivation_and_revoked_consent
    enable_refresh
    token = issue_refresh
    @app.plugin(:rodauth) { ciba_refresh_tokens_enabled false }
    assert_error refresh_with(token), "invalid_grant"
    @app.plugin(:rodauth) { ciba_refresh_tokens_enabled true }
    auth.revoke_ciba_grant(@db[:ciba_grants].get(:id))
    assert_error refresh_with(token), "invalid_grant"
  end

  def test_ciba_refresh_checks_current_client_registration
    enable_refresh
    token = issue_refresh
    @db[:oauth_applications].update(grant_types: GRANT)
    assert_error refresh_with(token), "unauthorized_client"
    assert_nil @db[:ciba_grants].get(:revoked_at)
    assert_equal 1, @db[:oauth_grants].count
  end

  def test_ciba_refresh_cleanup_preserves_live_replay_records_and_consent
    enable_refresh
    token = issue_refresh
    now = Time.now.to_i
    @db[:ciba_refresh_tokens].update(issued_at: now - 800, expires_at: now + 200)
    response = refresh_with(token)
    assert_equal 200, response.status, response.body
    successor = JSON.parse(response.body).fetch("refresh_token")
    assert_equal 0, auth.cleanup_ciba_refresh_tokens
    assert_equal 2, @db[:ciba_refresh_tokens].count
    assert_raises(ArgumentError) { auth.cleanup_ciba_refresh_tokens(limit: 0) }
    @db[:ciba_refresh_tokens].where(token_digest: Digest::SHA256.hexdigest(token)).update(expires_at: now)
    cleaner = auth("test.now" => -> { now })
    @db.transaction(rollback: :always) { assert_equal 1, cleaner.cleanup_ciba_refresh_tokens(limit: 1) }
    assert_equal 2, @db[:ciba_refresh_tokens].count
    assert_equal 1, cleaner.cleanup_ciba_refresh_tokens(limit: 1)
    assert_error refresh_with(token), "invalid_grant"
    assert_nil @db[:ciba_grants].get(:revoked_at)
    assert_equal 200, refresh_with(successor).status
    assert_equal 1, @db[:ciba_refresh_tokens].count
    @db[:ciba_refresh_tokens].update(expires_at: now)
    assert_equal 1, cleaner.cleanup_ciba_refresh_tokens
    assert_equal 1, @db[:ciba_grants].count
    assert_operator @db[:oauth_grants].count, :>, 0
  end

  def test_ciba_refresh_revocation_endpoint_hints_isolation_and_disabled_feature
    enable_refresh
    @app.plugin(:rodauth) { enable :oauth_token_revocation }
    discovery = Rack::MockRequest.new(@app).get("https://op.example.test/.well-known/openid-configuration")
    assert_equal "https://op.example.test/revoke", JSON.parse(discovery.body)["revocation_endpoint"]
    application = @db[:oauth_applications].first.reject { |key, _| key == :id }
    @db[:oauth_applications].insert(application.merge(client_id: "other"))
    [nil, "refresh_token", "access_token", "unknown"].each do |hint|
      token = issue_refresh
      params = {token: token}
      params[:token_type_hint] = hint if hint
      wrong = post("/revoke", params, "HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64('other:test-secret')}")
      assert_error wrong, "invalid_request"
      assert_equal 200, refresh_with(token).status
      @app.plugin(:rodauth) { ciba_refresh_tokens_enabled false }
      result = post("/revoke", params)
      assert_equal 200, result.status, result.body
      assert_equal "", result.body
      @app.plugin(:rodauth) { ciba_refresh_tokens_enabled true }
      assert_error refresh_with(token), "invalid_grant"
      assert_equal 200, post("/revoke", params).status
      assert_equal 200, post("/revoke", params, "HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64('other:test-secret')}").status
    end
    assert_equal 0, @db[:oauth_grants].where(revoked_at: nil).count
    missing = post("/revoke", token: "ciba_rt_unknown")
    assert_equal 200, missing.status
    assert_equal "", missing.body
  end

  def test_ciba_refresh_revocation_hook_failure_rolls_back
    enable_refresh
    @app.plugin(:rodauth) do
      enable :oauth_token_revocation
      after_revoke { raise "injected revocation failure" if scope.env["test.fail_revoke"] }
    end
    token = issue_refresh
    unauthenticated = post("/revoke", {token: token}, "HTTP_AUTHORIZATION" => nil,
      "rack.session" => {account_id: @account_id})
    assert_equal 401, unauthenticated.status, unauthenticated.body
    assert_nil @db[:ciba_grants].get(:revoked_at)
    response = post("/revoke", {token: token}, "test.fail_revoke" => true, "test.processing_error" => ->(_) {})
    assert_equal 500, response.status, response.body
    assert_nil @db[:ciba_grants].get(:revoked_at)
    assert_equal 200, refresh_with(token).status
  end

  def test_ciba_refresh_wrong_client_and_expiry_do_not_revoke_consent
    enable_refresh
    token = issue_refresh
    application = @db[:oauth_applications].first.reject { |key, _| key == :id }
    @db[:oauth_applications].insert(application.merge(client_id: "other"))
    wrong = refresh_with(token, {}, "HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64('other:test-secret')}")
    assert_error wrong, "invalid_grant"
    assert_nil @db[:ciba_grants].get(:revoked_at)
    assert_equal 200, refresh_with(token).status
    @db[:ciba_refresh_tokens].update(expires_at: Time.now.to_i - 1)
    assert_error refresh_with(token), "invalid_grant"
    assert_nil @db[:ciba_grants].get(:revoked_at)
  end

  def test_ciba_refresh_requires_both_offline_access_and_registration
    enable_refresh
    id = accept_request
    approve(id)
    refute JSON.parse(poll(id).body).key?("refresh_token")
    @db[:oauth_applications].update(grant_types: GRANT)
    response = post("/backchannel-authentication", scope: "openid offline_access", login_hint: "customer@example.test")
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body).fetch("auth_req_id")
    approve(id)
    refute JSON.parse(poll(id).body).key?("refresh_token")
    assert_equal 0, @db[:ciba_refresh_tokens].count
  end

  def test_ciba_refresh_concurrent_rotation_revokes_successor_on_replay
    enable_refresh
    token = issue_refresh
    now = Time.now.to_i
    @db[:ciba_refresh_tokens].update(issued_at: now - 800, expires_at: now + 200)
    responses = parallel_decisions { |_| refresh_with(token) }
    assert_equal [200, 400], responses.map(&:status).sort
    assert_equal "invalid_grant", JSON.parse(responses.find { |r| r.status == 400 }.body)["error"]
    refute_nil @db[:ciba_grants].get(:revoked_at)
    assert_equal 0, @db[:oauth_grants].where(revoked_at: nil).count
  end

  def test_ciba_refresh_does_not_replace_ordinary_oauth_refresh
    enable_refresh
    ordinary = "ordinary-refresh-token"
    @db[:oauth_grants].insert(account_id: @account_id, oauth_application_id: @client_id,
      type: "authorization_code", scopes: "openid offline_access", expires_in: Time.now + 3600,
      refresh_token: auth.send(:generate_token_hash, ordinary))
    response = refresh_with(ordinary)
    assert_equal 200, response.status, response.body
    refute_equal ordinary, JSON.parse(response.body).fetch("refresh_token")
    assert_equal 0, @db[:ciba_refresh_tokens].count
  end

  def test_ciba_refresh_resource_selection_uses_original_source
    enable_refresh
    Rodauth::CibaSupport::Schema.add_resources(@db)
    @db[:oauth_applications].update(scopes: "openid offline_access read write")
    @app.plugin(:rodauth) do
      oauth_application_scopes %w[openid offline_access read write]
      ciba_resources_enabled true
      ciba_resource_servers("https://api.example.test/a" => {scopes: %w[read write], audience: "api-a"},
        "https://api.example.test/b" => {scopes: %w[read write], audience: "api-b"})
    end
    pairs = [["scope", "openid offline_access read write"], ["login_hint", "customer@example.test"],
      ["resource", "https://api.example.test/a"], ["resource", "https://api.example.test/b"]]
    response = post("/backchannel-authentication", {}, input: URI.encode_www_form(pairs), "CONTENT_TYPE" => "application/x-www-form-urlencoded")
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body).fetch("auth_req_id")
    consent = auth.create_ciba_grant(account_id: @account_id, oauth_application_id: @client_id,
      scopes: "openid offline_access", resources: {"https://api.example.test/a" => "read", "https://api.example.test/b" => "write"})
    auth.backchannel_result(@db[:ciba_requests].get(:id), consent)
    first = post("/token", grant_type: GRANT, auth_req_id: id, resource: "https://api.example.test/a")
    assert_equal 200, first.status, first.body
    payload = JSON.parse(first.body)
    assert_equal "read", payload["scope"]
    token = payload.fetch("refresh_token")
    second = refresh_with(token, resource: "https://api.example.test/b")
    assert_equal 200, second.status, second.body
    assert_equal "write", JSON.parse(second.body)["scope"]
    assert_equal "api-b", @db[:oauth_grants].order(:id).last[:ciba_resource_audience]
    oidc = refresh_with(token)
    assert_equal 200, oidc.status, oidc.body
    assert_equal "openid offline_access", JSON.parse(oidc.body)["scope"]
    assert_error refresh_with(token, resource: "https://unrequested.example.test/"), "invalid_target"
  end
end
