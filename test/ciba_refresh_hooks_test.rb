# frozen_string_literal: true
require_relative "ciba_refresh_test"

class CibaIntegrationTest
  def enable_refresh_hooks
    enable_refresh
    @app.plugin(:rodauth) do
      before_ciba_refresh { scope.env["test.before_refresh"]&.call(self) }
      after_ciba_refresh { scope.env["test.after_refresh"]&.call(self) }
    end
  end

  def test_refresh_hook_rollback_and_private_snapshot
    enable_refresh_hooks
    token = issue_refresh
    original = @db[:ciba_refresh_tokens].first
    snapshots = []
    events = []
    response = refresh_with(token, {}, "test.after_refresh" => ->(instance) {
      assert @db.in_transaction?
      snapshots << instance.ciba_current_refresh
      assert snapshots.last.frozen?
      raise "injected mandatory hook failure"
    }, "test.observe" => ->(event) { events << event }, "test.processing_error" => ->(_) {})
    assert_equal 500, response.status
    assert_equal original, @db[:ciba_refresh_tokens].first
    assert_equal 1, @db[:oauth_grants].count
    assert_empty events
    refute snapshots.first.key?(:token_digest)
    refute_includes JSON.generate(snapshots), token
  end

  def test_refresh_revalidates_consent_client_and_expiry_after_hook
    enable_refresh_hooks
    token = issue_refresh
    changes = [
      ->(_) { @db[:ciba_grants].update(revoked_at: Time.now.to_i) },
      ->(_) { @db[:oauth_applications].update(grant_types: GRANT) },
      ->(_) { @db[:ciba_refresh_tokens].update(expires_at: Time.now.to_i - 1) }
    ]
    changes.each do |change|
      response = refresh_with(token, {}, "test.before_refresh" => change)
      assert_error response, "invalid_grant"
      assert_equal 1, @db[:oauth_grants].count
      assert_nil @db[:ciba_refresh_tokens].get(:consumed_at)
    end
    assert_equal 200, refresh_with(token).status
  end

  def test_refresh_observer_waits_for_outer_commit_and_failure_is_nonfatal
    enable_refresh_hooks
    token = issue_refresh
    events = []
    reports = []
    observer = ->(event) { refute @db.in_transaction?; events << event; raise "observer unavailable" }
    env = {"test.observe" => observer, "test.report" => ->(error) { reports << error.class }}
    @db.transaction(rollback: :always) do
      assert_equal 200, refresh_with(token, {}, env).status
      assert_empty events
    end
    assert_empty events
    assert_equal 1, @db[:oauth_grants].count
    @db.transaction do
      assert_equal 200, refresh_with(token, {}, env).status
      assert_empty events
    end
    assert_equal 1, events.size
    assert_equal "token_refreshed", events.first[:type]
    assert_equal @db[:ciba_grants].get(:id), events.first[:grant_id]
    assert_equal false, events.first[:rotated]
    refute events.first.key?(:request_id)
    refute_includes JSON.generate(events), token
    assert_equal [RuntimeError], reports
    assert_equal 2, @db[:oauth_grants].count
  end

  def test_refresh_hook_cannot_reenter_the_same_source
    enable_refresh_hooks
    token = issue_refresh
    errors = []
    response = refresh_with(token, {}, "test.before_refresh" => ->(_) {
      nested = refresh_with(token, {}, "test.processing_error" => ->(error) { errors << error.class })
      assert_equal 500, nested.status
    })
    assert_equal 200, response.status, response.body
    assert_equal [Rodauth::CibaSupport::ReentrantMutation], errors
    assert_equal 2, @db[:oauth_grants].count
  end

  def test_refresh_malformed_scope_does_not_run_state_hooks
    enable_refresh_hooks
    token = issue_refresh
    calls = []
    ["", "x" * 4097].each do |scope|
      response = refresh_with(token, {scope: scope}, "test.before_refresh" => ->(_) { calls << :called })
      assert_error response, "invalid_scope"
    end
    assert_empty calls
    assert_equal 1, @db[:oauth_grants].count
  end
end
