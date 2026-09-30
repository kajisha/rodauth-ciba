# frozen_string_literal: true
require_relative "ciba_signed_request_test"

class CibaIntegrationTest
  def enable_request_context
    Rodauth::CibaSupport::Schema.add_request_context(@db)
    @context_values = []
    values = @context_values
    @app.plugin(:rodauth) do
      ciba_request_context_enabled true
      validate_ciba_request_context do |context, oauth_application:|
        values << [context, oauth_application[:client_id]]
        raise Rodauth::CibaSupport::ProtocolError, "invalid_request" if context == "rejected"
      end
    end
  end

  def test_request_context_is_validated_stored_and_not_a_token_claim
    enable_request_context
    snapshots = []
    events = []
    response = post("/backchannel-authentication", {scope: "openid", login_hint: "customer@example.test", request_context: "support-session:demo"},
      "test.device" => ->(row, _) { snapshots << row }, "test.observe" => ->(event) { events << event })
    assert_equal 200, response.status, response.body
    assert_equal [["support-session:demo", "support"]], @context_values
    assert_equal "support-session:demo", snapshots.first[:request_context]
    assert snapshots.first[:request_context].frozen?
    assert_equal "support-session:demo", @db[:ciba_requests].get(:request_context)
    refute_includes JSON.generate(events), "support-session:demo"
    id = JSON.parse(response.body).fetch("auth_req_id")
    approve(id)
    result = post("/token", grant_type: GRANT, auth_req_id: id, request_context: "replacement")
    assert_equal 200, result.status, result.body
    _, identity = decode_id_token(result)
    refute identity.key?("request_context")
    assert_equal "support-session:demo", @db[:ciba_requests].get(:request_context)
    accept_request
    assert_equal [nil, "support"], @context_values.last
  end

  def test_request_context_rejection_precedes_persistence_and_device_dispatch
    enable_request_context
    calls = []
    ["rejected", "", "x" * 8193, ["nested"]].each do |context|
      response = post("/backchannel-authentication", {scope: "openid", login_hint: "customer@example.test", request_context: context},
        "test.device" => ->(*) { calls << true })
      assert_error response, "invalid_request"
    end
    assert_empty calls
    assert_equal 0, @db[:ciba_requests].count
    assert_equal [["rejected", "support"]], @context_values
  end

  def test_request_context_signed_input_replaces_outer_context
    enable_request_context
    enable_signed_requests
    response = post("/backchannel-authentication", request: signed_ciba_request({request_context: "signed-context"}),
      request_context: "rejected")
    assert_equal 200, response.status, response.body
    assert_equal [["signed-context", "support"]], @context_values
    assert_equal "signed-context", @db[:ciba_requests].get(:request_context)
  end

  def test_request_context_policy_failure_is_not_customer_denial
    enable_request_context
    @app.plugin(:rodauth) do
      validate_ciba_request_context { |*, **| raise "context service unavailable" }
    end
    response = post("/backchannel-authentication", {scope: "openid", login_hint: "customer@example.test", request_context: "reference"},
      "test.processing_error" => ->(_) {})
    assert_equal 500, response.status
    assert_equal "server_error", JSON.parse(response.body)["error"]
    assert_equal 0, @db[:ciba_requests].count
  end

  def test_request_context_migration_preserves_existing_requests_and_requires_policy
    accept_request
    original = @db[:ciba_requests].first
    Rodauth::CibaSupport::Schema.add_request_context(@db)
    row = @db[:ciba_requests].first
    assert_nil row.delete(:request_context)
    assert_equal original, row
    assert_raises(Rodauth::CibaSupport::ConfigurationError) do
      @app.plugin(:rodauth) { ciba_request_context_enabled true }
    end
  end
end
