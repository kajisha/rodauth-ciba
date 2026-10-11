# frozen_string_literal: true
require_relative "ciba_refresh_test"

class CibaIntegrationTest
  def test_refresh_issuance_requires_offline_access_in_saved_consent
    enable_refresh
    response = post("/backchannel-authentication", scope: "openid offline_access", login_hint: "customer@example.test")
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body).fetch("auth_req_id")
    consent = auth.create_ciba_grant(account_id: @account_id, oauth_application_id: @client_id, scopes: "openid")
    approve(id, grant_id: consent.fetch(:id))
    issued = poll(id)
    assert_equal 200, issued.status, issued.body
    payload = JSON.parse(issued.body)
    assert_equal "openid", payload.fetch("scope")
    refute payload.key?("refresh_token"), issued.body
    assert_equal 0, @db[:ciba_refresh_tokens].count
  end

  def test_refresh_requires_offline_access_to_remain_in_saved_consent
    enable_refresh
    token = issue_refresh
    @db[:ciba_grants].update(scopes: "openid")
    sources = @db[:ciba_refresh_tokens].all
    issued = @db[:oauth_grants].all
    assert_error refresh_with(token), "invalid_grant"
    assert_equal sources, @db[:ciba_refresh_tokens].all
    assert_equal issued, @db[:oauth_grants].all
  end

  def test_ciba_rejects_account_client_scope_unique_token_storage
    @db.add_index(:oauth_grants, [:oauth_application_id, :account_id, :scopes], unique: true)
    error = assert_raises(Rodauth::CibaSupport::ConfigurationError) { @app.plugin(:rodauth) {} }
    assert_match(/CIBA.*unique/i, error.message)
  end

  def test_distinct_ciba_tokens_keep_their_consent_when_reuse_is_configured
    [false, true].each do |reuse|
      [false, true].each do |jwt|
        @app.plugin(:rodauth) do
          oauth_reuse_access_token reuse
          oauth_jwt_access_tokens jwt
        end
        first = accept_request
        approve(first)
        first_response = poll(first)
        assert_equal 200, first_response.status, first_response.body
        second = accept_request
        approve(second)
        second_response = poll(second)
        assert_equal 200, second_response.status, second_response.body
        tokens = [first_response, second_response].map { |response| JSON.parse(response.body).fetch("access_token") }
        refute_equal(*tokens)
        grants = @db[:ciba_requests].order(:id).all.last(2).map { |row| row[:grant_id] }
        assert_equal 2, @db[:oauth_grants].where(ciba_grant_id: grants).count
        tokens.each do |token|
          result = Rack::MockRequest.new(@app).get("https://op.example.test/userinfo", "HTTP_AUTHORIZATION" => "Bearer #{token}")
          assert_equal 200, result.status, result.body
        end
        auth.revoke_ciba_grant(grants.first)
        tokens.each_with_index do |token, index|
          result = Rack::MockRequest.new(@app).get("https://op.example.test/userinfo", "HTTP_AUTHORIZATION" => "Bearer #{token}")
          assert_equal(index.zero? ? 401 : 200, result.status, "reuse=#{reuse} jwt=#{jwt} #{result.body}")
        end
      end
    end
  end

  def test_required_authentication_time_cannot_be_omitted_from_approval
    @db.alter_table(:oauth_applications) { add_column :require_auth_time, TrueClass }
    @db[:oauth_applications].update(require_auth_time: true)
    id = accept_request
    @db[:oauth_applications].update(require_auth_time: false)
    assert_raises(Rodauth::CibaSupport::Ineligible) { approve(id) }
    assert_equal "pending", @db[:ciba_requests].first[:status]
    assert_equal 0, @db[:oauth_grants].count
    approve(id, auth_time: 123)
    response = poll(id)
    assert_equal 200, response.status, response.body
    claims = JWT.decode(JSON.parse(response.body).fetch("id_token"), KEY.public_key, true, algorithms: ["RS256"]).first
    assert_equal 123, claims.fetch("auth_time")
  end

  def test_required_authentication_time_cannot_be_omitted_from_issuance
    @db.alter_table(:oauth_applications) { add_column :require_auth_time, TrueClass }
    @db[:oauth_applications].update(require_auth_time: true)
    id = accept_request
    approve(id, auth_time: 123)
    @db[:ciba_requests].update(auth_time: nil)
    assert_error poll(id), "invalid_grant"
    assert_equal "approved", @db[:ciba_requests].first[:status]
    assert_equal 0, @db[:oauth_grants].count
  end

  def test_required_authentication_time_cannot_be_omitted_from_refresh
    enable_refresh
    @db.alter_table(:oauth_applications) { add_column :require_auth_time, TrueClass }
    @db[:oauth_applications].update(require_auth_time: true)
    token = issue_refresh
    @db[:ciba_refresh_tokens].update(auth_time: nil)
    source = @db[:ciba_refresh_tokens].first
    issued_rows = @db[:oauth_grants].all
    @db[:oauth_applications].update(require_auth_time: false)
    rotation_time = auth.ciba_now + auth.ciba_refresh_token_lifetime * 8 / 10
    assert_error refresh_with(token, {}, "test.now" => -> { rotation_time }), "invalid_grant"
    assert_equal [source], @db[:ciba_refresh_tokens].all
    assert_equal issued_rows, @db[:oauth_grants].all
  end
end
