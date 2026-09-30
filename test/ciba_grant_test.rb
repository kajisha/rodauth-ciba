# frozen_string_literal: true
require_relative "test_helper"

class CibaIntegrationTest
  def test_consent_lifetime_rejects_zero_configuration
    assert_raises(ArgumentError) { @app.plugin(:rodauth) { ciba_grant_lifetime 0 } }
  end

  def test_new_consent_defaults_to_fourteen_days_without_changing_existing_rows
    grant_request
    now = Time.now.to_i
    instance = auth("test.now" => -> { now })
    values = {account_id: @account_id, oauth_application_id: @client_id, scopes: "openid"}
    legacy_id = @db[:ciba_grants].insert(values.merge(created_at: now, expires_at: nil))
    default = instance.create_ciba_grant(**values)
    assert_equal now + 14 * 24 * 60 * 60, default[:expires_at]
    assert_nil instance.ciba_grant(legacy_id)[:expires_at]
    assert_nil instance.create_ciba_grant(**values, expires_at: nil)[:expires_at]
    assert_equal now + 60, instance.create_ciba_grant(**values, expires_at: now + 60)[:expires_at]
  end

  def test_configured_consent_lifetime_and_convenience_approval
    @app.plugin(:rodauth) { ciba_grant_lifetime 60 }
    public_id, id = grant_request
    now = Time.now.to_i
    instance = auth("test.now" => -> { now })
    instance.approve_ciba_request(id, account_id: @account_id)
    grant = instance.ciba_grant(instance.ciba_request(id)[:grant_id])
    assert_equal now + 60, grant[:expires_at]
    response = poll(public_id, "test.now" => -> { now + 60 })
    assert_error response, "invalid_grant"
    assert_equal 0, @db[:oauth_grants].count
    assert_equal "approved", instance.ciba_request(id)[:status]
  end

  def grant_request(scope = "openid read delete")
    @app.plugin(:rodauth) { oauth_application_scopes %w[openid read delete] }
    @db[:oauth_applications].update(scopes: "openid read delete")
    response = post("/backchannel-authentication", login_hint: "customer@example.test", scope: scope)
    assert_equal 200, response.status, response.body
    [JSON.parse(response.body).fetch("auth_req_id"), @db[:ciba_requests].order(:id).last[:id]]
  end

  def saved_consent(scopes = "openid read", **values)
    auth.create_ciba_grant(account_id: @account_id, oauth_application_id: @client_id,
      scopes: scopes, **values)
  end

  def test_saved_grant_separates_requested_and_approved_scopes
    public_id, id = grant_request
    consent = saved_consent
    assert_equal 0, @db[:oauth_grants].count
    assert_equal :approved, auth.backchannel_result(id, consent, auth_time: 1)
    assert_equal "openid read delete", auth.ciba_request(id)[:scopes]
    assert_equal consent[:id], auth.ciba_request(id)[:grant_id]
    response = poll(public_id)
    assert_equal 200, response.status, response.body
    assert_equal "openid read", JSON.parse(response.body)["scope"]
    assert_equal "openid read", @db[:oauth_grants].get(:scopes)
    assert_equal :already_completed, auth.backchannel_result(id, consent[:id], auth_time: 1)
    assert_error poll(public_id), "invalid_grant"
  end

  def test_result_uses_persisted_grant_and_never_expands_requested_scope
    public_id, id = grant_request("openid read")
    consent = saved_consent("openid read delete")
    auth.backchannel_result(id, consent.merge(scopes: "openid secret"))
    response = poll(public_id)
    assert_equal "openid read", JSON.parse(response.body)["scope"]
  end

  def test_result_rejects_grants_for_another_account_or_client
    _, id = grant_request
    other_account = @db[:accounts].insert(email: "other@example.test")
    other_client = @db[:oauth_applications].insert(@db[:oauth_applications].first.reject { |key, _| key == :id }.merge(client_id: "other"))
    [[other_account, @client_id], [@account_id, other_client]].each do |account, client|
      consent = auth.create_ciba_grant(account_id: account, oauth_application_id: client, scopes: "openid")
      assert_raises(Rodauth::CibaSupport::IdentityMismatch) { auth.backchannel_result(id, consent) }
      assert_equal "pending", auth.ciba_request(id)[:status]
    end
    assert_equal 0, @db[:oauth_grants].count
  end

  def test_revoked_or_expired_grant_cannot_be_redeemed
    ["revoked", "expired"].each do |condition|
      public_id, id = grant_request
      consent = saved_consent(expires_at: Time.now.to_i + 60)
      auth.backchannel_result(id, consent)
      if condition == "revoked"
        auth.revoke_ciba_grant(consent[:id])
      else
        @db[:ciba_grants].where(id: consent[:id]).update(expires_at: Time.now.to_i)
      end
      assert_error poll(public_id), "invalid_grant"
      assert_equal "approved", auth.ciba_request(id)[:status]
    end
    assert_equal 0, @db[:oauth_grants].count
  end

  def test_legacy_approval_creates_one_persisted_grant_and_rolls_it_back_on_hook_failure
    public_id, id = grant_request
    assert_raises(RuntimeError) do
      auth("test.after_approve" => ->(_) { raise "abort" }).approve_ciba_request(id, account_id: @account_id)
    end
    assert_equal 0, @db[:ciba_grants].count
    assert_equal "pending", auth.ciba_request(id)[:status]
    2.times { approve(public_id) }
    assert_equal 1, @db[:ciba_grants].count
    assert_equal "openid read delete", @db[:ciba_grants].get(:scopes)
  end

  def test_backchannel_result_accepts_denial_without_a_grant
    public_id, id = grant_request
    error = Rodauth::CibaSupport::ProtocolError.new("access_denied")
    assert_equal :denied, auth.backchannel_result(id, error)
    assert_error poll(public_id), "access_denied"
    assert_equal 0, @db[:ciba_grants].count
  end
end

class CibaIntegrationTest
  def test_grant_revocation_survives_request_cleanup_and_preserves_unrelated_tokens
    public_id, id = grant_request
    consent = saved_consent
    auth.backchannel_result(id, consent)
    response = poll(public_id)
    assert_equal 200, response.status, response.body
    token_id = @db[:oauth_grants].get(:id)
    unrelated = @db[:oauth_grants].insert(account_id: @account_id, oauth_application_id: @client_id,
      scopes: "openid", token: "unrelated", type: "authorization_code")
    now = Time.now.to_i + 1
    assert_equal 1, auth("test.now" => -> { now }).cleanup_ciba_requests(before: now)
    assert_equal 0, @db[:ciba_requests].count
    assert_equal :revoked, auth.revoke_ciba_grant(consent[:id])
    assert @db[:oauth_grants].where(id: token_id).get(:revoked_at)
    assert_nil @db[:oauth_grants].where(id: unrelated).get(:revoked_at)
  end

  def test_grant_expiry_during_before_issue_prevents_tokens
    now = Time.now.to_i
    public_id, id = grant_request
    instance = auth("test.now" => -> { now })
    consent = instance.create_ciba_grant(account_id: @account_id, oauth_application_id: @client_id,
      scopes: "openid", expires_at: now + 1)
    instance.backchannel_result(id, consent)
    response = poll(public_id, "test.now" => -> { now }, "test.before_issue" => -> { now += 1 })
    assert_error response, "invalid_grant"
    assert_equal 0, @db[:oauth_grants].count
    assert_equal "approved", auth.ciba_request(id)[:status]
  end

  def test_grant_expiry_during_before_approve_does_not_record_approval
    _, id = grant_request
    now = Time.now.to_i
    consent = saved_consent(expires_at: now + 1)
    instance = auth("test.now" => -> { now }, "test.before_approve" => ->(_) { now += 1 })
    assert_raises(Rodauth::CibaSupport::Ineligible) { instance.backchannel_result(id, consent) }
    assert_equal "pending", auth.ciba_request(id)[:status]
    assert_nil auth.ciba_request(id)[:grant_id]
  end

  def test_grant_revocation_during_before_approve_rolls_back_the_completion
    _, id = grant_request
    consent = saved_consent
    instance = auth("test.before_approve" => ->(_) { auth.revoke_ciba_grant(consent[:id]) })
    assert_raises(Rodauth::CibaSupport::Ineligible) { instance.backchannel_result(id, consent) }
    assert_equal "pending", auth.ciba_request(id)[:status]
    # The hook participates in the same transaction, including its revocation.
    assert_nil auth.ciba_grant(consent[:id])[:revoked_at]
  end

  def test_result_rejects_changed_grant_on_retry
    _, id = grant_request
    first = saved_consent
    second = saved_consent("openid")
    auth.backchannel_result(id, first)
    assert_raises(Rodauth::CibaSupport::Conflict) { auth.backchannel_result(id, second) }
    assert_equal first[:id], auth.ciba_request(id)[:grant_id]
  end

  def test_grant_creation_rejects_invalid_or_unregistered_scope
    grant_request
    ["", "openid\tread", "openid é"].each do |scopes|
      assert_raises(ArgumentError) { saved_consent(scopes) }
    end
    ["read", "openid secret", "openid offline_access"].each do |scopes|
      assert_raises(Rodauth::CibaSupport::Ineligible) { saved_consent(scopes) }
    end
    assert_raises(ArgumentError) { saved_consent(expires_at: Time.now.to_i) }
    assert_equal 0, @db[:ciba_grants].count
  end
end

class CibaIntegrationTest
  def test_revocation_and_issuance_leave_no_live_token_after_revocation
    public_id, id = grant_request
    consent = saved_consent
    auth.backchannel_result(id, consent)
    gate = Queue.new
    threads = [
      Thread.new { gate.pop; poll(public_id) },
      Thread.new { gate.pop; auth.revoke_ciba_grant(consent[:id]) }
    ]
    2.times { gate << true }
    response, revoked = threads.map(&:value)
    assert_includes [200, 400], response.status
    assert_equal "invalid_grant", JSON.parse(response.body)["error"] if response.status == 400
    assert_equal :revoked, revoked
    assert_equal 0, @db[:oauth_grants].where(ciba_grant_id: consent[:id], revoked_at: nil).count
    assert auth.ciba_grant(consent[:id])[:revoked_at]
  end
end

class CibaIntegrationTest
  def test_custom_grant_table_and_token_reference
    @db.drop_table(:ciba_requests)
    @db.alter_table(:oauth_grants) { drop_foreign_key :ciba_grant_id }
    @db.drop_table(:ciba_grants)
    Rodauth::CibaSupport::Schema.create_grants(@db, table: :consents)
    Rodauth::CibaSupport::Schema.add_grant_reference(@db, column: :consent_ref, grants_table: :consents)
    Rodauth::CibaSupport::Schema.create(@db, grants_table: :consents, columns: {grant_id: :consent_ref})
    @app.plugin(:rodauth) do
      ciba_grants_table :consents
      oauth_grants_ciba_grant_id_column :consent_ref
      ciba_request_columns(grant_id: :consent_ref)
    end
    public_id, id = grant_request
    consent = saved_consent
    auth.backchannel_result(id, consent)
    assert_equal 200, poll(public_id).status
    assert_equal consent[:id], @db[:oauth_grants].get(:consent_ref)
    auth.revoke_ciba_grant(consent[:id])
    assert @db[:oauth_grants].get(:revoked_at)
    @db[:consents].where(id: consent[:id]).delete
    assert_equal 0, @db[:oauth_grants].count
    assert_equal 0, @db[:ciba_requests].count
  end
end
