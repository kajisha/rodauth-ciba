# frozen_string_literal: true
require_relative "test_helper"
require_relative "ciba_lifecycle_test"
require_relative "ciba_user_code_test"
require_relative "ciba_registration_test"
require "minitest/mock"

class CibaIntegrationTest
  def enable_ping
    Rodauth::CibaSupport::Schema.add_ping(@db)
    @db[:oauth_applications].update(backchannel_token_delivery_mode: "ping",
      backchannel_client_notification_endpoint: "https://client.example.test/notify")
    @app.plugin(:rodauth) { ciba_ping_enabled true }
  end

  def ping_request(extra = {}, env = {})
    response = post("/backchannel-authentication", {scope: "openid", login_hint: "customer@example.test",
      client_notification_token: "notification-token-123456789"}.merge(extra), env)
    assert_equal 200, response.status, response.body
    JSON.parse(response.body).fetch("auth_req_id")
  end

  def with_ping_sender(status = "204")
    calls = []
    sender = lambda do |uri, request, **options|
      assert_equal false, options.fetch(:read_body)
      refute @db.in_transaction?
      calls << [uri.to_s, request["authorization"], request["content-type"], JSON.parse(request.body)]
      Struct.new(:code).new(status)
    end
    Rodauth::CibaSupport::HTTP.stub(:request, sender) { yield calls }
  end

  def test_ping_approval_denial_and_private_delivery_storage
    enable_ping
    snapshots = []
    id = ping_request({}, "test.device" => ->(row, _) { snapshots << row }, "test.observe" => ->(event) { snapshots << event })
    row_id = @db[:ciba_requests].get(:id)
    snapshots << auth.ciba_request(row_id)
    refute_includes JSON.generate(snapshots), "notification-token-123456789"
    refute_includes JSON.generate(snapshots), id
    assert_equal id, @db[:ciba_ping_deliveries].get(:auth_req_id)
    assert_error poll(id), "authorization_pending"
    with_ping_sender do |calls|
      approve(id)
      assert_equal [["https://client.example.test/notify", "Bearer notification-token-123456789", "application/json", {"auth_req_id" => id}]], calls
    end
    assert_equal 200, poll(id, "test.now" => -> { Time.now.to_i + 10 }).status
    assert_equal :not_deliverable, auth.retry_ciba_ping(row_id)
    denied = ping_request
    with_ping_sender("200") do |calls|
      auth.deny_ciba_request(@db[:ciba_requests].max(:id), account_id: @account_id)
      assert_equal({"auth_req_id" => denied}, calls.last.last)
    end
    assert_error poll(denied), "access_denied"
  end

  def test_ping_delivery_failure_keeps_result_and_retry_is_separate
    enable_ping
    id = ping_request
    row_id = @db[:ciba_requests].get(:id)
    with_ping_sender("503") do |calls|
      assert_raises(Rodauth::CibaSupport::PingDeliveryError) { approve(id) }
      assert_equal 1, calls.size
    end
    assert_equal "approved", auth.ciba_request(row_id)[:status]
    with_ping_sender do |calls|
      assert_equal :delivered, auth.retry_ciba_ping(row_id)
      assert_equal 1, calls.size
    end
    assert_equal 200, poll(id).status
  end

  def test_ping_waits_for_outer_commit_and_rollback_never_sends
    enable_ping
    id = ping_request
    with_ping_sender do |calls|
      @db.transaction(rollback: :always) do
        approve(id)
        assert_empty calls
      end
      assert_empty calls
      assert_equal "pending", @db[:ciba_requests].get(:status)
      @db.transaction do
        approve(id)
        assert_empty calls
      end
      assert_equal 1, calls.size
    end
  end

  def test_ping_rejects_bad_tokens_and_uses_current_registered_destination
    enable_ping
    [nil, "", "bad token", "x" * 1025].each do |token|
      assert_error post("/backchannel-authentication", scope: "openid", login_hint: "customer@example.test", client_notification_token: token), "invalid_request"
    end
    assert_equal 0, @db[:ciba_ping_deliveries].count
    id = ping_request
    with_ping_sender { approve(id) }
    @db[:oauth_applications].update(backchannel_client_notification_endpoint: "https://other.example/notify")
    with_ping_sender do |calls|
      assert_equal :delivered, auth.retry_ciba_ping(@db[:ciba_requests].get(:id))
      assert_equal ["https://other.example/notify", "Bearer notification-token-123456789", "application/json", {"auth_req_id" => id}], calls.fetch(0)
    end
    @db[:oauth_applications].update(backchannel_client_notification_endpoint: "http://client.example/notify")
    assert_raises(Rodauth::CibaSupport::Ineligible) { auth.retry_ciba_ping(@db[:ciba_requests].get(:id)) }
    assert_error post("/backchannel-authentication", scope: "openid", login_hint: "customer@example.test"), "unauthorized_client"
  end

  def test_ping_notification_token_bearer_syntax_and_maximum_length
    enable_ping
    ["x" * 1024, "A09-._~+/=="].each do |token|
      id = ping_request(client_notification_token: token)
      with_ping_sender do |calls|
        approve(id)
        assert_equal "Bearer #{token}", calls.last[1]
      end
    end
    count = @db[:ciba_requests].count
    ["a=b", "=", "a\r\nb", "非ASCII"].each do |token|
      assert_error post("/backchannel-authentication", scope: "openid", login_hint: "customer@example.test",
        client_notification_token: token), "invalid_request"
    end
    assert_equal count, @db[:ciba_requests].count
  end

  def test_ping_metadata_acceptance_rollback_expiry_and_private_data_cleanup
    enable_ping
    metadata = Rack::MockRequest.new(@app).get("https://op.example.test/.well-known/openid-configuration")
    assert_equal %w[poll ping], JSON.parse(metadata.body)["backchannel_token_delivery_modes_supported"]
    response = post("/backchannel-authentication", {scope: "openid", login_hint: "customer@example.test", client_notification_token: "test-token"},
      "test.after_request" => ->(_) { raise "injected request rollback" }, "test.processing_error" => ->(_) {})
    assert_equal 500, response.status
    assert_equal 0, @db[:ciba_ping_deliveries].count
    ping_request
    id = @db[:ciba_requests].get(:id)
    assert_equal :not_deliverable, auth.retry_ciba_ping(id)
    @db.transaction do
      assert_raises(Rodauth::CibaSupport::ConfigurationError) { auth.retry_ciba_ping(id) }
    end
    future = Time.now.to_i + 1000
    instance = auth("test.now" => -> { future })
    assert_equal :not_deliverable, instance.retry_ciba_ping(id)
    assert_equal 1, instance.cleanup_ciba_requests(before: future)
    assert_equal 0, @db[:ciba_ping_deliveries].count
  end

  def test_ping_completion_does_not_hold_transaction_while_waiting_for_receiver
    enable_ping
    id = ping_request
    arrived, release = Queue.new, Queue.new
    sender = lambda do |*_args, **_options|
      arrived << @db.in_transaction?
      Timeout.timeout(10) { release.pop }
      Struct.new(:code).new("204")
    end
    Rodauth::CibaSupport::HTTP.stub(:request, sender) do
      worker = Thread.new { approve(id) }
      begin
        assert_equal false, Timeout.timeout(10) { arrived.pop }
        assert_equal "approved", @db[:ciba_requests].get(:status)
        response = Timeout.timeout(5) { poll(id) }
        assert_equal 200, response.status, response.body
        release << true
        assert_equal :approved, Timeout.timeout(10) { worker.value }
        assert_equal 1, @db[:oauth_grants].count
      ensure
        worker.kill if worker.alive?
        worker.join
      end
    end
  end

  def test_concurrent_ping_retries_can_duplicate_notification_but_not_issue_tokens
    enable_ping
    id = ping_request
    with_ping_sender { approve(id) }
    row_id = @db[:ciba_requests].get(:id)
    arrived, release = Queue.new, Queue.new
    sender = lambda do |_uri, request, **_options|
      @db.synchronize do |connection|
        arrived << [connection.object_id, @db.in_transaction?, JSON.parse(request.body)]
      end
      Timeout.timeout(10) { release.pop }
      Struct.new(:code).new("204")
    end
    Rodauth::CibaSupport::HTTP.stub(:request, sender) do
      workers = Thread.new { parallel_decisions { auth.retry_ciba_ping(row_id) } }
      begin
        sends = Timeout.timeout(10) { 2.times.map { arrived.pop } }
        assert_equal 2, sends.map(&:first).uniq.size
        assert sends.all? { |_, transaction, body| transaction == false && body == {"auth_req_id" => id} }
        response = Timeout.timeout(5) { poll(id) }
        assert_equal 200, response.status, response.body
        2.times { release << true }
        assert_equal [:delivered, :delivered], Timeout.timeout(10) { workers.value }
        assert_equal 1, @db[:oauth_grants].count
        assert_equal :not_deliverable, auth.retry_ciba_ping(row_id)
        assert_error poll(id), "invalid_grant"
        assert @db[:oauth_grants].get(:revoked_at)
      ensure
        workers.kill if workers.alive?
        workers.join
      end
    end
  end

  def test_ping_management_change_during_send_preserves_destination_and_saved_result
    configure_dynamic_registration
    enable_ping
    %w[endpoint mode].each do |change|
      metadata = registration_params.merge("backchannel_token_delivery_mode" => "ping",
        "backchannel_client_notification_endpoint" => "https://client.example.test/notify")
      registered = register(metadata)
      assert_equal 201, registered.status, registered.body
      client = JSON.parse(registered.body)
      headers = {"HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64("#{client.fetch('client_id')}:#{client.fetch('client_secret')}")}"}
      id = ping_request({}, headers)
      row_id = @db[:ciba_requests].max(:id)
      arrived, release = Queue.new, Queue.new
      management_thread = Thread.current
      sender = lambda do |uri, request, **_options|
        arrived << [uri.to_s, request["authorization"], JSON.parse(request.body), @db.in_transaction?]
        Timeout.timeout(10) { release.pop } unless Thread.current == management_thread
        Struct.new(:code).new("204")
      end
      Rodauth::CibaSupport::HTTP.stub(:request, sender) do
        worker = Thread.new { approve(id) }
        begin
          sent = Timeout.timeout(10) { arrived.pop }
          assert_equal ["https://client.example.test/notify", "Bearer notification-token-123456789", {"auth_req_id" => id}, false], sent
          updated = metadata.merge("client_id" => client.fetch("client_id"))
          if change == "endpoint"
            updated["backchannel_client_notification_endpoint"] = "https://replacement.example.test/notify"
          else
            updated["backchannel_token_delivery_mode"] = "poll"
            updated.delete("backchannel_client_notification_endpoint")
          end
          response = Rack::MockRequest.new(@app).put(client.fetch("registration_client_uri"),
            "HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}",
            "CONTENT_TYPE" => "application/json", input: JSON.generate(updated))
          assert_equal 200, response.status, response.body
          if change == "endpoint"
            assert_equal :delivered, auth.retry_ciba_ping(row_id)
            assert_equal ["https://replacement.example.test/notify", "Bearer notification-token-123456789", {"auth_req_id" => id}, false], Timeout.timeout(10) { arrived.pop }
          else
            assert_raises(Rodauth::CibaSupport::Ineligible) { auth.retry_ciba_ping(row_id) }
          end
          assert arrived.empty?, "in-flight sender must not be invoked again"
          issued = poll(id, headers)
          assert_equal 200, issued.status, issued.body
          release << true
          assert_equal :approved, Timeout.timeout(10) { worker.value }
          assert_equal :not_deliverable, auth.retry_ciba_ping(row_id)
          assert_equal 1, @db[:oauth_grants].where(oauth_application_id: @db[:oauth_applications].where(client_id: client.fetch("client_id")).get(:id)).count
          assert_error poll(id, headers), "invalid_grant"
        ensure
          worker.kill if worker.alive?
          worker.join
        end
      end
    end
  end

  def test_signed_ping_required_fields_cannot_be_supplied_outside_signature
    enable_ping
    enable_signed_requests
    enable_user_codes
    outer = {scope: "openid", login_hint: "customer@example.test",
      client_notification_token: "signed-notification-token", user_code: "test-approval-code"}
    valid = signed_ciba_request(outer)
    claims = JSON.parse(Base64.urlsafe_decode64(valid.split(".")[1]))
    dispatched = []
    %w[scope login_hint client_notification_token user_code].each do |name|
      [nil, ""].each do |value|
        inner = claims.dup
        value.nil? ? inner.delete(name) : inner[name] = value
        token = JWT.encode(inner, REQUEST_KEY, "RS256", kid: JWT::JWK.new(REQUEST_KEY).kid)
        error = if name == "user_code" && value.nil?
          "missing_user_code"
        elsif name == "scope" && value == ""
          "invalid_scope"
        else
          "invalid_request"
        end
        assert_error post("/backchannel-authentication", outer.merge(request: token),
          "test.device" => ->(row, _) { dispatched << row }), error
        assert_equal 0, @db[:ciba_requests].count, "#{name}: #{value.inspect}"
        assert_equal 0, @db[:oauth_grants].count
      end
    end
    assert_empty dispatched
    response = post("/backchannel-authentication", outer.merge(request: valid),
      "test.device" => ->(row, _) { dispatched << row })
    assert_equal 200, response.status, response.body
    assert_equal 1, dispatched.size
    assert_equal 1, @db[:ciba_requests].count
  end

  def test_ping_with_signed_request_and_user_code_uses_only_signed_notification_token
    enable_ping
    enable_signed_requests
    enable_user_codes
    request_jwt = signed_ciba_request({client_notification_token: "signed-notification-token", user_code: "test-approval-code"})
    response = post("/backchannel-authentication", request: request_jwt,
      client_notification_token: "unsigned-notification-token", user_code: "wrong")
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body).fetch("auth_req_id")
    assert_equal "test-approval-code", @user_code_calls.last.last
    with_ping_sender do |calls|
      approve(id)
      assert_equal "Bearer signed-notification-token", calls.last[1]
    end
    assert_equal 200, poll(id).status
    assert_equal 1, @user_code_calls.size
  end
end
