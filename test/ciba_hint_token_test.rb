# frozen_string_literal: true
require_relative "test_helper"

class CibaIntegrationTest
  def enable_hint_token
    @hint_calls = []
    calls = @hint_calls
    account_id = @account_id
    @app.plugin(:rodauth) do
      ciba_login_hint_token_enabled true
      resolve_ciba_login_hint_token do |value, oauth_application:|
        calls << [value, oauth_application[:client_id]]
        account_id if value == "opaque-customer-reference" && oauth_application[:client_id] == "support"
      end
    end
  end

  def test_hint_token_resolver_receives_authenticated_client_and_does_not_persist_raw_token
    enable_hint_token
    observations = []
    snapshots = []
    response = post("/backchannel-authentication", {scope: "openid", login_hint_token: "opaque-customer-reference"},
      "test.observe" => ->(event) { observations << event }, "test.device" => ->(row, _) { snapshots << row })
    assert_equal 200, response.status, response.body
    assert_equal [["opaque-customer-reference", "support"]], @hint_calls
    assert_equal @account_id, @db[:ciba_requests].get(:account_id)
    [observations, snapshots, @db[:ciba_requests].all].each do |data|
      refute_includes JSON.generate(data), "opaque-customer-reference"
      refute_includes JSON.generate(data), "login_hint_token"
    end
    id = JSON.parse(response.body).fetch("auth_req_id")
    @app.plugin(:rodauth) { ciba_login_hint_token_enabled false }
    approve(id)
    result = post("/token", grant_type: GRANT, auth_req_id: id, login_hint_token: "different-customer")
    assert_equal 200, result.status, result.body
    assert_equal @account_id.to_s, decode_id_token(result).last.fetch("sub")
    assert_equal 1, @hint_calls.size
    @app.plugin(:rodauth) { ciba_login_hint_token_enabled true }
    client = @db[:oauth_applications].first.reject { |key, _| key == :id }
    @db[:oauth_applications].insert(client.merge(client_id: "other"))
    assert_error post("/backchannel-authentication", {scope: "openid", login_hint_token: "opaque-customer-reference"},
      "HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64('other:test-secret')}"), "unknown_user_id"
  end

  def test_hint_token_requires_opt_in_and_resolver
    assert_error post("/backchannel-authentication", scope: "openid", login_hint_token: "opaque-customer-reference"), "invalid_request"
    assert_raises(Rodauth::CibaSupport::ConfigurationError) do
      @app.plugin(:rodauth) { ciba_login_hint_token_enabled true }
    end
  end

  def test_hint_token_expiry_and_resolver_failure_precede_persistence
    enable_hint_token
    @app.plugin(:rodauth) do
      resolve_ciba_login_hint_token do |token, oauth_application:|
        raise Rodauth::CibaSupport::ProtocolError, "expired_login_hint_token" if token == "expired"
        raise "injected resolver outage"
      end
    end
    dispatched = []
    reports = []
    env = {"test.device" => ->(row, _) { dispatched << row },
      "test.processing_error" => ->(error) { reports << error }}
    assert_error post("/backchannel-authentication", {scope: "openid", login_hint_token: "expired"}, env), "expired_login_hint_token"
    assert_empty reports
    response = post("/backchannel-authentication", {scope: "openid", login_hint_token: "unavailable"}, env)
    assert_equal 500, response.status
    assert_equal "server_error", JSON.parse(response.body)["error"]
    assert_equal 1, reports.size
    assert_empty dispatched
    assert_equal 0, @db[:ciba_requests].count
  end

  def test_hint_token_input_exclusivity_size_and_unknown_user
    enable_hint_token
    [{}, {login_hint_token: ""}, {login_hint_token: ["x"]}, {login_hint_token: "x" * 8193},
      {login_hint: "customer@example.test", login_hint_token: "opaque-customer-reference"},
      {id_token_hint: "x", login_hint_token: "opaque-customer-reference"}].each do |params|
      assert_error post("/backchannel-authentication", {scope: "openid"}.merge(params)), "invalid_request"
    end
    assert_empty @hint_calls
    assert_error post("/backchannel-authentication", scope: "openid", login_hint_token: "unknown"), "unknown_user_id"
    assert_equal 0, @db[:ciba_requests].count
    assert_equal 200, post("/backchannel-authentication", scope: "openid", login_hint: "customer@example.test").status
  end

  def test_hint_token_resolved_user_still_requires_eligible_account_and_matching_approval
    enable_hint_token
    @db[:accounts].where(id: @account_id).update(status_id: 3)
    assert_error post("/backchannel-authentication", scope: "openid", login_hint_token: "opaque-customer-reference"), "unknown_user_id"
    @db[:accounts].where(id: @account_id).update(status_id: 2)
    response = post("/backchannel-authentication", scope: "openid", login_hint_token: "opaque-customer-reference")
    assert_equal 200, response.status
    other = @db[:accounts].insert(email: "other@example.test")
    assert_raises(Rodauth::CibaSupport::IdentityMismatch) do
      auth.approve_ciba_request(@db[:ciba_requests].get(:id), account_id: other)
    end
    assert_equal "pending", @db[:ciba_requests].get(:status)
  end
end
