# frozen_string_literal: true
require_relative "ciba_refresh_test"

class CibaIntegrationTest
  def test_refresh_waiting_for_grant_does_not_hold_source_row_lock
    skip "SQLite serializes writers before row-lock ordering applies" if @db.database_type == :sqlite
    enable_refresh
    token = issue_refresh
    @app.plugin(:rodauth) do
      auth_class_eval do
        def ciba_locked_grant(id)
          scope.env["test.grant_lock_probe"]&.call
          super
        end
      end
    end
    reached = Queue.new
    release = Queue.new
    first = true
    probe = -> {
      if first
        first = false
        reached << true
        release.pop
      end
    }
    worker = nil
    begin
      @db.transaction do
        @db[:ciba_grants].for_update.first
        worker = Thread.new { refresh_with(token, {}, "test.grant_lock_probe" => probe) }
        Timeout.timeout(10) { reached.pop }
        # The refresh has read its source and is about to obtain its grant lock.
        # Grant-scoped invalidation can still lock the source on this connection.
        row = Timeout.timeout(10) { @db[:ciba_refresh_tokens].for_update.first }
        assert_equal Digest::SHA256.hexdigest(token), row[:token_digest]
        release << true
      end
      response = Timeout.timeout(10) { worker.value }
      assert_equal 200, response.status, response.body
    ensure
      release << true
      worker&.kill if worker&.alive?
      worker&.join
    end
  end
end
