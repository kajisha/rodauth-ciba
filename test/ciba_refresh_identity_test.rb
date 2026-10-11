# frozen_string_literal: true
require_relative "ciba_claim_constraints_test"
require_relative "ciba_refresh_test"

class CibaIntegrationTest
  def identity_refresh_setup
    enable_refresh
    @app.plugin(:rodauth) do
      ciba_authentication_claims_by_scope("openid" => %w[auth_time acr amr])
      before_ciba_refresh { scope.env["test.before_refresh"]&.call }
    end
  end

  def test_refresh_identity_saves_actual_initial_public_claims_and_rotates
    assert_refresh_identity_public_rotation
  end

  def test_refresh_identity_saves_actual_initial_public_jwt_claims_and_rotates
    @app.plugin(:rodauth) { oauth_jwt_access_tokens true }
    assert_refresh_identity_public_rotation
  end

  def assert_refresh_identity_public_rotation
    identity_refresh_setup
    token = issue_refresh
    row = @db[:ciba_refresh_tokens].first
    saved = JSON.parse(row[:authentication_claims])
    assert_kind_of Hash, saved
    assert_equal 2, saved["version"]
    assert_equal({"iss" => "https://op.example.test", "sub" => @account_id.to_s, "aud" => "support", "auth_time" => 123}, saved["initial_id_token"])
    @db[:ciba_requests].delete
    now = Time.now.to_i
    @db[:ciba_refresh_tokens].update(issued_at: now - 800, expires_at: now + 200)
    payload, claims = decode_id_token(refresh_with(token, {}, "test.now" => -> { now + 1 }))
    %w[iss sub aud].each { |key| assert_equal saved["initial_id_token"][key], claims[key] }
    assert_equal 123, claims["auth_time"]
    assert_in_delta Time.now.to_i, claims["iat"], 2
    refute claims.key?("nonce")
    refute_equal token, payload["refresh_token"]
    assert_equal saved, JSON.parse(@db[:ciba_refresh_tokens].order(:id).last[:authentication_claims])
  end

  def test_refresh_identity_missing_required_time_is_rejected_before_hook
    identity_refresh_setup
    @db.alter_table(:oauth_applications) { add_column :require_auth_time, TrueClass }
    @db[:oauth_applications].update(require_auth_time: true)
    token = issue_refresh
    saved = JSON.parse(@db[:ciba_refresh_tokens].get(:authentication_claims))
    saved.fetch("initial_id_token").delete("auth_time")
    @db[:ciba_refresh_tokens].update(authentication_claims: JSON.generate(saved))
    before = @db[:ciba_refresh_tokens].first
    called = false
    assert_error refresh_with(token, {}, "test.before_refresh" => -> { called = true }), "invalid_grant"
    refute called
    assert_equal before, @db[:ciba_refresh_tokens].first
    assert_equal 1, @db[:oauth_grants].count
  end

  def test_refresh_identity_undisclosed_time_stays_absent
    enable_refresh
    token = issue_refresh
    saved = JSON.parse(@db[:ciba_refresh_tokens].get(:authentication_claims))
    refute saved.fetch("initial_id_token").key?("auth_time")
    @app.plugin(:rodauth) { ciba_authentication_claims_by_scope("openid" => %w[auth_time]) }
    _, claims = decode_id_token(refresh_with(token))
    refute claims.key?("auth_time")
  end

  def test_refresh_identity_final_payload_mismatch_rolls_back_rotation
    identity_refresh_setup
    token = issue_refresh
    now = Time.now.to_i
    @db[:ciba_refresh_tokens].update(issued_at: now - 800, expires_at: now + 200)
    before = @db[:ciba_refresh_tokens].all
    @app.plugin(:rodauth) do
      auth_class_eval do
        def jwt_encode(payload, **options)
          payload[:sub] = "changed-after-validation" if options.dig(:headers, :typ) == "id_token+jwt"
          super
        end
      end
    end
    assert_error refresh_with(token), "invalid_grant"
    assert_equal before, @db[:ciba_refresh_tokens].all
    assert_equal 1, @db[:oauth_grants].count
  end

  def test_refresh_identity_legacy_concurrent_requests_have_no_side_effects
    identity_refresh_setup
    token = issue_refresh
    @db[:ciba_refresh_tokens].update(authentication_claims: "[]")
    before = @db[:ciba_refresh_tokens].all
    responses = parallel_decisions { |_| refresh_with(token) }
    responses.each { |response| assert_error response, "invalid_grant" }
    assert_equal before, @db[:ciba_refresh_tokens].all
    assert_equal 1, @db[:oauth_grants].count
    assert_nil @db[:ciba_grants].get(:revoked_at)
  end

  def test_refresh_identity_rejects_legacy_and_corrupt_sources_before_hooks
    identity_refresh_setup
    token = issue_refresh
    valid = {version: 2, selected: [], initial_id_token: {iss: "https://op.example.test", sub: @account_id.to_s, aud: "support"}}
    invalid = [nil, "[]", "null", "{", JSON.generate(valid.merge(version: 3)),
      JSON.generate(valid.merge(selected: [1])), JSON.generate(valid.merge(initial_id_token: nil)),
      JSON.generate(valid.merge(initial_id_token: {iss: "https://op.example.test", sub: "", aud: "support"})),
      JSON.generate(valid.merge(initial_id_token: {iss: "https://op.example.test", sub: @account_id.to_s, aud: ["support"]}))]
    called = false
    invalid.each do |json|
      @db[:ciba_refresh_tokens].update(authentication_claims: json)
      before = [@db[:ciba_refresh_tokens].all, @db[:oauth_grants].all, @db[:ciba_grants].all]
      assert_error refresh_with(token, {}, "test.before_refresh" => -> { called = true }), "invalid_grant"
      refute called
      assert_equal before, [@db[:ciba_refresh_tokens].all, @db[:oauth_grants].all, @db[:ciba_grants].all]
    end
  end

  def test_refresh_identity_rejects_changed_issuer_and_audience
    identity_refresh_setup
    token = issue_refresh
    before = @db[:ciba_refresh_tokens].first
    @app.plugin(:rodauth) { oauth_jwt_issuer { "https://changed.example.test" } }
    assert_error refresh_with(token), "invalid_grant"
    assert_equal before, @db[:ciba_refresh_tokens].first
    @app.plugin(:rodauth) { oauth_jwt_issuer { "https://op.example.test" } }
    @db[:oauth_applications].where(id: @client_id).update(client_id: "renamed")
    assert_error refresh_with(token, {}, "HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64('renamed:test-secret')}"), "invalid_grant"
    assert_equal before, @db[:ciba_refresh_tokens].first
    assert_equal 1, @db[:oauth_grants].count
  end

  def test_refresh_identity_revalidates_after_hook_and_rolls_back_corruption
    identity_refresh_setup
    token = issue_refresh
    before = @db[:ciba_refresh_tokens].first
    callback = -> { @db[:ciba_refresh_tokens].update(authentication_claims: "[]") }
    assert_error refresh_with(token, {}, "test.before_refresh" => callback), "invalid_grant"
    assert_equal before, @db[:ciba_refresh_tokens].first
    assert_equal 1, @db[:oauth_grants].count
  end

  def test_refresh_identity_pairwise_qualifier_survives_sector_change
    identity_refresh_setup
    enable_explicit_claims
    @db[:oauth_applications].update(scopes: "openid offline_access")
    @app.plugin(:rodauth) { oauth_application_scopes %w[openid offline_access] }
    configure_pairwise
    initial = auth.send(:jwt_subject, @account_id, @db[:oauth_applications].where(id: @client_id).first)
    id = constraint_request({id_token: {sub: {value: initial}}, userinfo: {sub: {value: initial}}},
      scope: "openid offline_access", extra: pairwise_assertion, headers: {"HTTP_AUTHORIZATION" => nil})
    approve(id, auth_time: 123)
    response = post("/token", pairwise_assertion.merge(grant_type: GRANT, auth_req_id: id), "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, response.status, response.body
    token = JSON.parse(response.body).fetch("refresh_token")
    @db[:oauth_applications].where(id: @client_id).update(jwks_uri: "https://changed.example.test/jwks")
    @db[:ciba_requests].delete
    response = post("/token", pairwise_assertion(audience: "https://op.example.test/token").merge(grant_type: "refresh_token", refresh_token: token), "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, response.status, response.body
    payload, claims = decode_id_token(response)
    assert_equal initial, claims["sub"]
    info = Rack::MockRequest.new(@app).get("https://op.example.test/userinfo", "HTTP_AUTHORIZATION" => "Bearer #{payload.fetch('access_token')}")
    assert_equal 200, info.status, info.body
    assert_equal initial, JSON.parse(info.body)["sub"]
  end
end
