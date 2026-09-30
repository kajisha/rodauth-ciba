# frozen_string_literal: true
require_relative "test_helper"

class CibaIntegrationTest
  def test_concurrent_approve_and_deny_choose_one_decision
    5.times do
      accept_request
      row = @db[:ciba_requests].order(:id).last
      results = parallel_decisions do |index|
        begin
          method = index.zero? ? :approve_ciba_request : :deny_ciba_request
          auth.public_send(method, row[:id], account_id: @account_id)
        rescue Rodauth::CibaSupport::Conflict
          :conflict
        end
      end
      assert_equal 1, results.count(:conflict)
      assert_equal 1, (results & %i[approved denied]).size
    end
  end

  def test_concurrent_pending_polls_both_receive_retryable_results
    id = accept_request
    results = parallel_decisions { |_index| poll(id) }
    assert_equal %w[authorization_pending slow_down], results.map { |r| JSON.parse(r.body)["error"] }.sort
    assert_equal 10, @db[:ciba_requests].get(:interval)
  end

  def test_completion_hook_failure_rolls_back_and_retry_does_not_repeat_hooks
    accept_request
    row = @db[:ciba_requests].first
    failing = auth("test.after_approve" => ->(_row) { raise "audit failure" })
    assert_raises(RuntimeError) { failing.approve_ciba_request(row[:id], account_id: @account_id) }
    assert_equal row, @db[:ciba_requests].first
    calls = []
    successful = auth("test.after_approve" => ->(request) { calls << request[:status] })
    2.times { successful.approve_ciba_request(row[:id], account_id: @account_id) }
    assert_equal ["approved"], calls
  end

  def test_reentrant_completion_is_rejected_even_from_another_auth_instance
    accept_request
    row = @db[:ciba_requests].first
    nested = ->(_snapshot) { auth.approve_ciba_request(row[:id], account_id: @account_id) }
    instance = auth("test.before_approve" => nested)
    assert_raises(Rodauth::CibaSupport::ReentrantMutation) { instance.approve_ciba_request(row[:id], account_id: @account_id) }
    assert_equal row, @db[:ciba_requests].first
    assert_equal :approved, auth.approve_ciba_request(row[:id], account_id: @account_id)
  end

  def test_expiry_during_before_issue_rolls_back_and_returns_expired
    id = accept_request
    approve(id)
    row = @db[:ciba_requests].first
    now = row[:expires_at] - 1
    response = poll(id, "test.now" => -> { now }, "test.before_issue" => -> { now += 2 })
    assert_error response, "expired_token"
    assert_equal row, @db[:ciba_requests].first
    assert_equal 0, @db[:oauth_grants].count
  end

  def test_client_and_account_changes_are_rechecked
    id = accept_request
    row = @db[:ciba_requests].first
    @db[:oauth_applications].update(scopes: "profile")
    assert_raises(Rodauth::CibaSupport::Ineligible) { auth.approve_ciba_request(row[:id], account_id: @account_id) }
    @db[:oauth_applications].update(scopes: "openid")
    approve(id)
    @db[:accounts].update(status_id: 3)
    assert_error poll(id), "invalid_grant"
    assert_equal "approved", @db[:ciba_requests].get(:status)
    assert_equal 0, @db[:oauth_grants].count
  end

  def test_acceptance_hook_rollback_does_not_notify
    delivered = []
    response = post("/backchannel-authentication", {login_hint: "customer@example.test", scope: "openid"},
      "test.after_request" => ->(_row) { raise "failed" }, "test.accepted" => ->(row) { delivered << row })
    assert_equal 500, response.status
    assert_equal 0, @db[:ciba_requests].count
    assert_empty delivered
  end

  def test_expired_pending_cleanup_and_live_approved_retention
    id = accept_request
    first = @db[:ciba_requests].first
    @db[:ciba_requests].where(id: first[:id]).update(expires_at: Time.now.to_i - 20)
    live = accept_request
    approve(live)
    assert_equal 1, auth.cleanup_ciba_requests(before: Time.now.to_i - 1)
    assert_error poll(id), "invalid_grant"
    assert_equal 200, poll(live).status
  end


end
