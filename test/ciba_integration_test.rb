# frozen_string_literal: true
require_relative "test_helper"

class CibaIntegrationTest
  def test_approved_request_issues_customer_id_token_once
    @app.plugin(:rodauth) { ciba_authentication_claims_by_scope("openid" => %w[auth_time acr amr]) }
    id = accept_request
    time = Time.now.to_i - 30
    approve(id, auth_time: time, acr: "urn:example:verified", amr: ["pwd", "otp"])
    signatures = 0
    response = poll(id, "test.signing_probe" => -> { signatures += 1 })
    assert_equal 200, response.status, response.body
    payload, claims = decode_id_token(response)
    assert_equal "bearer", payload.fetch("token_type").downcase
    assert_kind_of Integer, payload.fetch("expires_in")
    assert_operator payload.fetch("expires_in"), :>, 0
    assert_equal "no-store", response["cache-control"]
    assert_equal "no-cache", response["pragma"]
    assert_equal @account_id.to_s, claims["sub"]
    assert_equal time, claims["auth_time"]
    assert_equal "urn:example:verified", claims["acr"]
    assert_equal %w[otp pwd], claims["amr"]
    assert_operator claims.fetch("exp"), :>, claims.fetch("iat")
    token = payload.fetch("access_token")
    assert_equal Base64.urlsafe_encode64(Digest::SHA256.digest(token)[0, 16], padding: false), claims["at_hash"]
    refute payload.key?("refresh_token")
    assert_equal 1, signatures
    assert_equal 1, @db[:oauth_grants].count
    assert_equal "consumed", @db[:ciba_requests].get(:status)
    assert_error poll(id), "invalid_grant"
    assert_equal 1, @db[:oauth_grants].count
  end

  def test_signing_failure_rolls_back_consumption_and_grant_then_allows_retry
    id = accept_request
    approve(id)
    original = @db[:ciba_requests].first
    probe = -> {
      assert_equal "consumed", @db[:ciba_requests].get(:status)
      assert_equal 1, @db[:oauth_grants].count
    }
    response = poll(id, "test.fail_signing" => true, "test.signing_probe" => probe)
    assert_equal 500, response.status
    assert_equal "server_error", JSON.parse(response.body)["error"]
    refute_includes response.body, "injected signing failure"
    assert_equal original, @db[:ciba_requests].first
    assert_equal 0, @db[:oauth_grants].count
    assert_equal 200, poll(id).status
    assert_error poll(id), "invalid_grant"
  end

  def test_concurrent_polls_issue_one_grant
    10.times do
      id = accept_request
      approve(id)
      arrived, release = Queue.new, Queue.new
      gate = -> { arrived << true; Timeout.timeout(10) { release.pop } }
      connections = Queue.new
      workers = 2.times.map do
        Thread.new do
          @db.synchronize do |connection|
            connections << connection.object_id
            poll(id, "test.token_gate" => gate)
          end
        end
      end
      begin
        Timeout.timeout(10) { 2.times { arrived.pop } }
        assert_equal 2, 2.times.map { connections.pop }.uniq.size
        2.times { release << true }
        responses = workers.map { |t| Timeout.timeout(10) { t.value } }
        assert_equal [200, 400], responses.map(&:status).sort
        assert_error responses.find { |r| r.status == 400 }, "invalid_grant"
        decode_id_token(responses.find { |r| r.status == 200 })
      ensure
        workers.each { |t| t.kill if t.alive? }
        workers.each(&:join)
      end
    end
    assert_equal 10, @db[:oauth_grants].count
  end
end

class CibaIntegrationTest
  def test_pending_poll_updates_survive_json_halt
    id = accept_request
    assert_error poll(id), "authorization_pending"
    refute_nil @db[:ciba_requests].get(:last_polled_at)
    assert_error poll(id), "slow_down"
    assert_equal 10, @db[:ciba_requests].get(:interval)
    assert_error poll(id), "slow_down"
    assert_equal 15, @db[:ciba_requests].get(:interval)
    approve(id)
    assert_equal 200, poll(id).status
  end

  def test_unapproved_poll_responses_never_include_tokens
    id = accept_request
    responses = [poll(id), poll(id)]
    row = @db[:ciba_requests].first
    auth.deny_ciba_request(row[:id], account_id: @account_id)
    responses << poll(id)
    assert_equal %w[authorization_pending slow_down access_denied], responses.map { |r| JSON.parse(r.body)["error"] }
    responses.each do |response|
      assert_equal 400, response.status
      payload = JSON.parse(response.body)
      %w[access_token id_token refresh_token].each { |key| refute payload.key?(key) }
    end
    assert_equal 0, @db[:oauth_grants].count
  end

  def test_missing_authentication_context_is_not_fabricated
    id = accept_request
    approve(id)
    _, claims = decode_id_token(poll(id))
    %w[auth_time acr amr].each { |key| refute claims.key?(key) }
  end

  def test_other_identity_client_and_expiry_cannot_issue
    id = accept_request
    other = @db[:accounts].insert(email: "other@example.test")
    row = @db[:ciba_requests].first
    assert_raises(Rodauth::CibaSupport::CompletionError) { auth.approve_ciba_request(row[:id], account_id: other) }
    assert_equal row, @db[:ciba_requests].first
    @db[:oauth_applications].insert(@db[:oauth_applications].first.reject { |k, _| k == :id }.merge(client_id: "other"))
    response = poll(id, "HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64('other:test-secret')}")
    assert_error response, "invalid_grant"
    assert_equal row, @db[:ciba_requests].first
    approve(id)
    @db[:ciba_requests].update(expires_at: Time.now.to_i)
    assert_error poll(id), "expired_token"
    assert_equal 0, @db[:oauth_grants].count
  end

  def test_client_authentication_is_required_at_both_endpoints
    response = post("/backchannel-authentication", {login_hint: "customer@example.test", scope: "openid"}, "HTTP_AUTHORIZATION" => nil)
    assert_equal 400, response.status
    assert_equal "invalid_request", JSON.parse(response.body).fetch("error")
    assert_nil response["www-authenticate"]
    assert_equal 0, @db[:ciba_requests].count
    id = accept_request
    approve(id)
    rejected = poll(id, "HTTP_AUTHORIZATION" => nil)
    assert_equal 400, rejected.status
    assert_equal "invalid_request", JSON.parse(rejected.body).fetch("error")
    assert_nil rejected["www-authenticate"]
    assert_equal "no-store", rejected["cache-control"]
    assert_equal "no-cache", rejected["pragma"]
    assert_equal 0, @db[:oauth_grants].count
  end

  def test_authorization_code_flow_still_uses_oidc_wrapper
    @db[:oauth_grants].insert(account_id: @account_id, oauth_application_id: @client_id,
      type: "authorization_code", code: "test-code", scopes: "openid", expires_in: Time.now + 60,
      redirect_uri: "https://rp.example.test/callback", nonce: "original-nonce")
    response = post("/token", grant_type: "authorization_code", code: "test-code", redirect_uri: "https://rp.example.test/callback")
    assert_equal 200, response.status, response.body
    _, claims = decode_id_token(response)
    assert_equal @account_id.to_s, claims["sub"]
    assert_equal "original-nonce", claims["nonce"]
    assert_equal 1, claims["auth_time"]
  end

  def test_hooks_see_before_and_after_states_and_failure_rolls_back
    id = accept_request
    approve(id)
    row = @db[:ciba_requests].first
    calls = []
    response = poll(id, "test.before_issue" => -> { calls << @db[:ciba_requests].get(:status) },
      "test.after_issue" => -> { calls << @db[:ciba_requests].get(:status); raise "after hook failed" })
    assert_equal 500, response.status
    refute_includes response.body, "after hook failed"
    assert_equal ["approved", "consumed"], calls
    assert_equal row, @db[:ciba_requests].first
    assert_equal 0, @db[:oauth_grants].count
  end

  def test_observation_waits_for_outer_commit_and_does_not_change_result
    id = accept_request
    approve(id)
    events, reports = [], []
    @db.transaction(mode: :immediate) do
      response = poll(id, "test.observe" => ->(event) { events << event; raise "sink failed" },
        "test.report" => ->(error) { reports << error.class; raise "reporter failed" })
      assert_equal 200, response.status
      assert_empty events
    end
    assert_equal 1, events.size
    assert_equal "token_issued", events.first[:type]
    assert_equal [RuntimeError], reports
    refute events.first.key?(:auth_req_id)
    refute events.first.key?(:access_token)
    assert_equal "consumed", @db[:ciba_requests].get(:status)
    assert_equal 1, @db[:oauth_grants].count
  end

  def test_outer_rollback_discards_issuance_and_observation
    id = accept_request
    approve(id)
    row = @db[:ciba_requests].first
    events = []
    @db.transaction(mode: :immediate, rollback: :always) do
      assert_equal 200, poll(id, "test.observe" => ->(event) { events << event }).status
      assert_empty events
    end
    assert_empty events
    assert_equal row, @db[:ciba_requests].first
    assert_equal 0, @db[:oauth_grants].count
  end

  def test_failure_reported_inside_outer_transaction_still_rolls_back_inner_work
    id = accept_request
    approve(id)
    row = @db[:ciba_requests].first
    @db.transaction(mode: :immediate) do
      assert_equal 500, poll(id, "test.fail_signing" => true).status
      assert_equal row, @db[:ciba_requests].first
      assert_equal 0, @db[:oauth_grants].count
    end
    assert_equal row, @db[:ciba_requests].first
  end
end

class CibaIntegrationTest
  def test_savepoint_rollback_discards_event_even_when_outer_transaction_commits
    id = accept_request
    approve(id)
    row = @db[:ciba_requests].first
    events = []
    @db.transaction(mode: :immediate) do
      @db.transaction(savepoint: true, rollback: :always) do
        assert_equal 200, poll(id, "test.observe" => ->(event) { events << event }).status
      end
      assert_equal row, @db[:ciba_requests].first
    end
    assert_empty events
    assert_equal 0, @db[:oauth_grants].count
  end

  def test_jwt_access_token_configuration_also_works
    @app.plugin(:rodauth) { oauth_jwt_access_tokens true }
    id = accept_request
    approve(id)
    response = poll(id)
    assert_equal 200, response.status, response.body
    payload, id_claims = decode_id_token(response)
    access_claims, = JWT.decode(payload.fetch("access_token"), KEY.public_key, true, algorithms: ["RS256"])
    assert_equal @account_id.to_s, access_claims["sub"]
    assert_equal @account_id.to_s, id_claims["sub"]
    refute payload.key?("refresh_token")
    assert_equal 1, @db[:oauth_grants].count
  end
end
