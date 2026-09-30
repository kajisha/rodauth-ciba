# frozen_string_literal: true
require_relative "test_helper"

class CibaIntegrationTest
  def test_refresh_storage_is_additive_and_preserves_consumed_tokens
    request_id = accept_request
    approve(request_id)
    assert_equal 200, poll(request_id).status
    requests = @db[:ciba_requests].all
    tokens = @db[:oauth_grants].all
    consents = @db[:ciba_grants].all

    Rodauth::CibaSupport::Schema.create_refresh_tokens(@db)
    assert_equal requests, @db[:ciba_requests].all
    assert_equal tokens, @db[:oauth_grants].all
    assert_equal consents, @db[:ciba_grants].all
    values = refresh_storage_values(consents.first[:id])
    old_id = @db[:ciba_refresh_tokens].insert(values)
    @db[:ciba_refresh_tokens].where(id: old_id).update(consumed_at: 120, lock_version: 1)
    @db[:ciba_refresh_tokens].insert(values.merge(token_digest: "b" * 64, issued_at: 120, rotations: 1))
    assert_equal 2, @db[:ciba_refresh_tokens].count
    assert_equal 120, @db[:ciba_refresh_tokens].where(id: old_id).get(:consumed_at)
    assert_raises(Sequel::UniqueConstraintViolation) { @db[:ciba_refresh_tokens].insert(values) }

    # Request cleanup cannot destroy a still-valid refresh source or its replay ledger.
    @db[:ciba_requests].delete
    assert_equal 2, @db[:ciba_refresh_tokens].count
    @db[:ciba_grants].delete
    assert_equal 0, @db[:ciba_refresh_tokens].count
  end

  def test_refresh_storage_rollback_and_custom_table
    consent = auth.create_ciba_grant(account_id: @account_id, oauth_application_id: @client_id, scopes: "openid")
    Rodauth::CibaSupport::Schema.create_refresh_tokens(@db, table: :renewal_sources)
    values = refresh_storage_values(consent[:id])
    @db.transaction(rollback: :always) { @db[:renewal_sources].insert(values) }
    assert_equal 0, @db[:renewal_sources].count
    @db[:renewal_sources].insert(values)
    row = @db[:renewal_sources].first
    assert_equal 0, row[:lock_version]
    assert_equal 0, row[:rotations]
    assert_equal "openid offline_access", row[:scopes]
    assert_equal({"id_token" => {"email" => nil}}, JSON.parse(row[:requested_claims]))
    assert_equal ["https://api.example.test/a"], JSON.parse(row[:requested_resources])
    refute @db.table_exists?(:ciba_refresh_tokens)
  end

  def refresh_storage_values(grant_id)
    {token_digest: "a" * 64, grant_id: grant_id, account_id: @account_id,
     oauth_application_id: @client_id, scopes: "openid offline_access", created_at: 100,
     issued_at: 100, expires_at: 1000, auth_time: 90, nonce: "original-nonce",
     requested_claims: JSON.generate(id_token: {email: nil}),
     requested_resources: JSON.generate(["https://api.example.test/a"])}
  end
end
