# frozen_string_literal: true
require_relative "test_helper"
require_relative "ciba_signed_request_test"

class CibaIntegrationTest
  def enable_user_codes
    Rodauth::CibaSupport::Schema.add_user_code(@db)
    @db[:oauth_applications].update(backchannel_user_code_parameter: true)
    calls = @user_code_calls = []
    @app.plugin(:rodauth) do
      ciba_user_code_enabled true
      verify_ciba_user_code do |code, account_id:, oauth_application:|
        calls << [account_id, oauth_application[:client_id], code]
        if code.nil? && oauth_application[:backchannel_user_code_parameter]
          raise Rodauth::CibaSupport::ProtocolError, "missing_user_code"
        end
        code == "test-approval-code" || (code.nil? && !oauth_application[:backchannel_user_code_parameter])
      end
    end
  end

  def test_user_code_requires_explicit_callback_and_checks_before_device_dispatch
    assert_raises(Rodauth::CibaSupport::ConfigurationError) do
      @app.plugin(:rodauth) { ciba_user_code_enabled true }
    end
    enable_user_codes
    params = {scope: "openid", login_hint: "customer@example.test"}
    dispatched = []
    assert_error post("/backchannel-authentication", params), "missing_user_code"
    assert_error post("/backchannel-authentication", params.merge(user_code: "wrong"),
      "test.device" => ->(row, _) { dispatched << row }), "invalid_user_code"
    assert_empty dispatched
    assert_equal 0, @db[:ciba_requests].count
    @db[:accounts].where(id: @account_id).update(status_id: 3)
    assert_error post("/backchannel-authentication", params.merge(user_code: "test-approval-code")), "unknown_user_id"
    assert_equal 2, @user_code_calls.size
  end

  def test_user_code_not_persisted_and_does_not_replace_customer_approval
    enable_user_codes
    snapshots = []
    response = post("/backchannel-authentication", {scope: "openid", login_hint: "customer@example.test", user_code: "test-approval-code"},
      "test.device" => ->(row, _) { snapshots << row }, "test.observe" => ->(event) { snapshots << event })
    assert_equal 200, response.status, response.body
    assert_equal [[@account_id, "support", "test-approval-code"]], @user_code_calls
    refute_includes JSON.generate(snapshots + @db[:ciba_requests].all), "test-approval-code"
    refute_includes JSON.generate(snapshots + @db[:ciba_requests].all), "user_code"
    id = JSON.parse(response.body).fetch("auth_req_id")
    assert_error poll(id), "authorization_pending"
    approve(id)
    assert_equal 200, poll(id, "test.now" => -> { Time.now.to_i + 10 }).status
    assert_equal 1, @user_code_calls.size
    metadata = Rack::MockRequest.new(@app).get("https://op.example.test/.well-known/openid-configuration")
    assert_equal true, JSON.parse(metadata.body)["backchannel_user_code_parameter_supported"]
  end

  def test_user_code_input_and_optional_client_policy
    enable_user_codes
    params = {scope: "openid", login_hint: "customer@example.test"}
    ["", ["x"], "x" * 1025].each do |value|
      assert_error post("/backchannel-authentication", params.merge(user_code: value)), "invalid_request"
    end
    assert_empty @user_code_calls
    @db[:oauth_applications].update(backchannel_user_code_parameter: false)
    assert_equal 200, post("/backchannel-authentication", params).status
    assert_nil @user_code_calls.last.last
    @db[:oauth_applications].update(backchannel_user_code_parameter: nil)
    assert_equal 200, post("/backchannel-authentication", params).status
    assert_nil @user_code_calls.last.last
    @app.plugin(:rodauth) { verify_ciba_user_code { |*args, **kwargs| nil } }
    assert_error post("/backchannel-authentication", params), "invalid_user_code"
    @app.plugin(:rodauth) { ciba_user_code_enabled false }
    assert_error post("/backchannel-authentication", params.merge(user_code: "test-approval-code")), "invalid_request"
  end

  def test_user_code_signed_request_ignores_outer_code_and_propagates_policy_failure
    enable_signed_requests
    enable_user_codes
    assert_error post("/backchannel-authentication", request: signed_ciba_request, user_code: "test-approval-code"), "missing_user_code"
    response = post("/backchannel-authentication", request: signed_ciba_request({user_code: "test-approval-code"}), user_code: "wrong")
    assert_equal 200, response.status, response.body
    @app.plugin(:rodauth) do
      verify_ciba_user_code { |*args, **kwargs| raise "injected policy failure" }
    end
    count = @db[:ciba_requests].count
    reports = []
    response = post("/backchannel-authentication", {request: signed_ciba_request({user_code: "test-approval-code"})},
      "test.processing_error" => ->(error) { reports << error })
    assert_equal 500, response.status
    assert_equal 1, reports.size
    assert_equal count, @db[:ciba_requests].count
  end
end
