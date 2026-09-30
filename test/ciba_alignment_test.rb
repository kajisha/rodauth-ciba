# frozen_string_literal: true
require_relative "test_helper"

class CibaIntegrationTest
  def test_generic_completion_errors_are_returned_once_without_issuing_tokens
    %w[transaction_failed authorization_pending slow_down expired_token invalid_grant server_error application_failure].each do |code|
      id = accept_request
      request_id = @db[:ciba_requests].order(:id).last[:id]
      error = Rodauth::CibaSupport::ProtocolError.new(code)
      assert_equal :denied, auth.backchannel_result(request_id, error)
      assert_equal code, auth.ciba_request(request_id)[:completion_error]
      assert_equal :already_completed, auth.backchannel_result(request_id, error)
      assert_raises(Rodauth::CibaSupport::Conflict) { auth.deny_ciba_request(request_id, account_id: @account_id) }
      assert_raises(Rodauth::CibaSupport::Conflict) { auth.approve_ciba_request(request_id, account_id: @account_id) }
      response = poll(id)
      assert_equal 400, response.status, response.body
      assert_error response, code
      assert_equal "consumed", auth.ciba_request(request_id)[:status]
      assert_error poll(id), "invalid_grant"
      assert_equal :already_completed, auth.backchannel_result(request_id, error)
      assert_equal 0, @db[:ciba_grants].count
      assert_equal 0, @db[:oauth_grants].count
    end
  end

  def test_invalid_completion_error_codes_do_not_mutate_requests
    id = accept_request
    request_id = @db[:ciba_requests].get(:id)
    before = auth.ciba_request(request_id)
    [nil, 123, "", "x" * 1025, "bad\ncode", 'bad"code', "日本語"].each do |code|
      assert_raises(ArgumentError) do
        auth.backchannel_result(request_id, Rodauth::CibaSupport::ProtocolError.new(code))
      end
      assert_equal before, auth.ciba_request(request_id)
    end
    approve(id)
    assert_equal 200, poll(id).status
  end

  def test_generic_completion_error_uses_transactional_hooks_and_ping
    enable_ping
    id = ping_request
    request_id = @db[:ciba_requests].get(:id)
    error = Rodauth::CibaSupport::ProtocolError.new("transaction_failed")
    before = auth.ciba_request(request_id)
    assert_raises(RuntimeError) do
      auth("test.after_deny" => ->(_) { raise "hook failed" }).backchannel_result(request_id, error)
    end
    assert_equal before, auth.ciba_request(request_id)
    events = []
    with_ping_sender do |calls|
      assert_equal :denied, auth("test.observe" => ->(event) { events << event }).backchannel_result(request_id, error)
      assert_equal 1, calls.size
      assert_equal({"auth_req_id" => id}, calls.first.last)
    end
    assert_equal ["failed"], events.map { |event| event[:type] }
    assert_equal "transaction_failed", events.first[:error]
    assert events.first.frozen?
    assert_error poll(id), "transaction_failed"
    assert_error poll(id), "invalid_grant"
  end

  def test_completion_error_migration_preserves_previous_denial
    id = accept_request
    request_id = @db[:ciba_requests].get(:id)
    auth.deny_ciba_request(request_id, account_id: @account_id)
    @db.alter_table(:ciba_requests) { drop_column :completion_error }
    Rodauth::CibaSupport::Schema.add_completion_error(@db)
    assert_nil @db[:ciba_requests].get(:completion_error)
    assert_error poll(id), "access_denied"
    assert_error poll(id), "invalid_grant"
  end

  def test_generic_completion_error_http_status
    {"invalid_token" => 401, "insufficient_scope" => 403}.each do |code, status|
      id = accept_request
      auth.backchannel_result(@db[:ciba_requests].order(:id).last[:id], Rodauth::CibaSupport::ProtocolError.new(code))
      response = poll(id)
      assert_equal status, response.status
      assert_equal code, JSON.parse(response.body)["error"]
      assert_error poll(id), "invalid_grant"
    end
  end

  def test_another_client_cannot_revoke_consent_by_replaying_a_request_id
    id = accept_request
    approve(id)
    assert_equal 200, poll(id).status
    grant_id = @db[:ciba_requests].get(:grant_id)
    other = @db[:oauth_applications].first.reject { |key, _| key == :id }
    @db[:oauth_applications].insert(other.merge(client_id: "other-client"))
    response = poll(id, "HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64('other-client:test-secret')}")
    assert_error response, "invalid_grant"
    assert_nil auth.ciba_grant(grant_id)[:revoked_at]
    assert_nil @db[:oauth_grants].get(:revoked_at)
  end

  def test_replayed_result_revokes_its_saved_consent_and_tokens
    id = accept_request
    approve(id)
    assert_equal 200, poll(id).status
    grant_id = @db[:ciba_requests].get(:grant_id)
    assert_nil auth.ciba_grant(grant_id)[:revoked_at]
    assert_nil @db[:oauth_grants].get(:revoked_at)
    assert_error poll(id), "invalid_grant"
    assert auth.ciba_grant(grant_id)[:revoked_at]
    assert @db[:oauth_grants].get(:revoked_at)
  end

  def test_denied_result_is_consumed_on_first_collection
    id = accept_request
    request_id = @db[:ciba_requests].get(:id)
    auth.deny_ciba_request(request_id, account_id: @account_id)
    assert_error poll(id), "access_denied"
    assert_equal "consumed", auth.ciba_request(request_id)[:status]
    assert_equal :already_completed, auth.deny_ciba_request(request_id, account_id: @account_id)
    assert_raises(Rodauth::CibaSupport::Conflict) { auth.approve_ciba_request(request_id, account_id: @account_id) }
    assert_error poll(id), "invalid_grant"
  end

  def test_expiry_precedes_consumed_result_check
    id = accept_request
    approve(id)
    assert_equal 200, poll(id).status
    expiry = @db[:ciba_requests].get(:expires_at)
    assert_error poll(id, "test.now" => -> { expiry }), "expired_token"
  end

  def test_default_request_lifetime_matches_node_policy
    @app.plugin(:rodauth) do
      ciba_request_lifetime { super() }
      ciba_max_request_lifetime { super() }
    end
    [[nil, 600], ["30", 30], ["900", 600]].each do |requested, expected|
      params = {login_hint: "customer@example.test", scope: "openid"}
      params[:requested_expiry] = requested if requested
      response = post("/backchannel-authentication", params)
      assert_equal 200, response.status, response.body
      assert_equal expected, JSON.parse(response.body).fetch("expires_in")
      row = @db[:ciba_requests].order(:id).last
      assert_equal expected, row[:expires_at] - row[:created_at]
    end
  end

  def test_common_oidc_claim_provider_only_receives_approved_scopes
    @app.plugin(:rodauth) { ciba_authentication_claims_by_scope("openid" => %w[auth_time acr amr]) }
    loaded = []
    @app.plugin(:rodauth) do
      oauth_application_scopes %w[openid email]
      get_oidc_param do |account, claim|
        loaded << claim
        account[:email] if claim == :email
      end
      # A backchannel authentication must not need a browser-session timestamp.
      get_oidc_account_last_login_at { |_id| raise "browser session lookup" }
    end
    @db[:oauth_applications].update(scopes: "openid email")
    ["openid", "openid email"].each do |approved|
      loaded.clear
      response = post("/backchannel-authentication", login_hint: "customer@example.test", scope: "openid email")
      assert_equal 200, response.status, response.body
      public_id = JSON.parse(response.body).fetch("auth_req_id")
      request_id = @db[:ciba_requests].order(:id).last.fetch(:id)
      grant = auth.create_ciba_grant(account_id: @account_id, oauth_application_id: @client_id, scopes: approved)
      auth.backchannel_result(request_id, grant, auth_time: 42)
      result = poll(public_id)
      assert_equal 200, result.status, result.body
      payload, claims = decode_id_token(result)
      assert_equal approved, payload.fetch("scope")
      assert_equal 42, claims.fetch("auth_time")
      if approved == "openid"
        assert_empty loaded
        refute claims.key?("email")
      else
        assert_includes loaded, :email
        assert_equal "customer@example.test", claims.fetch("email")
      end
    end
  end

  def test_device_trigger_receives_saved_request_before_success_response
    delivered = []
    response = post("/backchannel-authentication", {login_hint: "customer@example.test", scope: "openid"}, "test.device" => lambda { |row, rodauth|
      refute @db.in_transaction?
      assert_equal row, rodauth.ciba_request(row[:id])
      assert row.frozen?
      refute row.key?(:auth_req_id_digest)
      delivered << row[:id]
      rodauth.approve_ciba_request(row[:id], account_id: row[:account_id])
    })
    assert_equal 200, response.status, response.body
    assert_equal [@db[:ciba_requests].get(:id)], delivered
    assert_equal 200, poll(JSON.parse(response.body).fetch("auth_req_id")).status
  end

  def test_device_failure_is_not_an_observer_failure_or_success_response
    errors, observer_errors = [], []
    response = post("/backchannel-authentication", {login_hint: "customer@example.test", scope: "openid"},
      "test.device" => ->(_row, _auth) { raise "private delivery credentials" },
      "test.processing_error" => ->(error) { errors << error },
      "test.report" => ->(error) { observer_errors << error })
    assert_equal 500, response.status
    assert_equal "server_error", JSON.parse(response.body).fetch("error")
    refute_includes response.body, "private delivery credentials"
    assert_equal 1, errors.size
    assert_empty observer_errors
    # Delivery could have happened before raising; don't undo a saved request.
    assert_equal "pending", @db[:ciba_requests].get(:status)
    assert_empty @db[:oauth_grants].all
  end

  def test_device_trigger_requires_application_implementation
    errors = []
    response = post("/backchannel-authentication", {login_hint: "customer@example.test", scope: "openid"},
      "test.unconfigured_device" => true, "test.processing_error" => ->(error) { errors << error })
    assert_equal 500, response.status
    assert_equal "server_error", JSON.parse(response.body).fetch("error")
    assert_instance_of Rodauth::CibaSupport::ConfigurationError, errors.fetch(0)
  end

  def test_rejected_request_does_not_trigger_device
    delivered = []
    response = post("/backchannel-authentication", {login_hint: "customer@example.test", scope: "unregistered"}, "test.device" => ->(row, _) { delivered << row })
    assert_error response, "invalid_scope"
    assert_empty delivered
  end

  def test_binding_message_default_matches_node_oidc_provider_policy
    [nil, "W4SCT", "a" * 20, "AZaz09-._+/!?#"].each do |binding|
      params = {login_hint: "customer@example.test", scope: "openid"}
      params[:binding_message] = binding unless binding.nil?
      response = post("/backchannel-authentication", params)
      assert_equal 200, response.status, response.body
    end
    ["", "a" * 21, "hello world", "日本語", "line\nbreak"].each do |binding|
      assert_error post("/backchannel-authentication", login_hint: "customer@example.test",
        scope: "openid", binding_message: binding), "invalid_binding_message"
    end
  end

  def test_application_can_replace_binding_message_policy
    @app.plugin(:rodauth) do
      validate_ciba_binding_message do |message|
        ciba_error("invalid_binding_message") unless message == "顧客へのサポート依頼"
      end
    end
    response = post("/backchannel-authentication", login_hint: "customer@example.test",
      scope: "openid", binding_message: "顧客へのサポート依頼")
    assert_equal 200, response.status, response.body
    assert_equal "顧客へのサポート依頼", @db[:ciba_requests].get(:binding_message)
    assert_error post("/backchannel-authentication", login_hint: "customer@example.test",
      scope: "openid"), "invalid_binding_message"
  end
end
