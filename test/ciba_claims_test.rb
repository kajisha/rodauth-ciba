# frozen_string_literal: true
require_relative "test_helper"

class CibaIntegrationTest
  def enable_explicit_claims
    Rodauth::CibaSupport::Schema.add_claims(@db)
    @claim_reads = []
    reads = @claim_reads
    @app.plugin(:rodauth) do
      ciba_claims_enabled true
      oauth_application_scopes %w[openid email]
      get_oidc_param do |_account, name|
        reads << name
        {email: "customer@example.test", email_verified: true}[name]
      end
    end
    @db[:oauth_applications].update(scopes: "openid email")
  end

  def claim_exchange(requested, allowed: [], rejected: [], scope: "openid")
    response = post("/backchannel-authentication", login_hint: "customer@example.test", scope: scope, claims: JSON.generate(requested))
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body).fetch("auth_req_id")
    request_id = @db[:ciba_requests].order(:id).last[:id]
    grant = auth.create_ciba_grant(account_id: @account_id, oauth_application_id: @client_id,
      scopes: scope, claims: allowed, rejected_claims: rejected)
    auth.backchannel_result(request_id, grant.merge(claims: JSON.generate(allowed: ["email", "email_verified"], rejected: [])))
    @claim_reads.clear
    result = post("/token", grant_type: GRANT, auth_req_id: id,
      claims: JSON.generate(id_token: {email: nil, email_verified: nil}))
    assert_equal 200, result.status, result.body
    decode_id_token(result)
  end

  def test_explicit_claims_match_reference_consent_and_targets
    enable_explicit_claims
    [
      [{id_token: {email: nil}}, [], [], false, false],
      [{id_token: {email: nil}}, ["email"], [], true, false],
      [{id_token: {email: nil}}, ["email"], ["email"], false, false],
      [{userinfo: {email: nil}}, ["email"], [], false, true],
      [{id_token: {}}, ["email"], [], false, false]
    ].each do |requested, allowed, rejected, id_email, user_email|
      payload, claims = claim_exchange(requested, allowed: allowed, rejected: rejected)
      assert_equal id_email, claims.key?("email")
      assert_equal id_email ? [:email] : [], @claim_reads
      refute claims.key?("email_verified")
      @claim_reads.clear
      response = Rack::MockRequest.new(@app).get("https://op.example.test/userinfo",
        "HTTP_AUTHORIZATION" => "Bearer #{payload.fetch('access_token')}")
      assert_equal 200, response.status, response.body
      assert_equal user_email, JSON.parse(response.body).key?("email")
      assert_equal user_email ? [:email] : [], @claim_reads
    end
  end

  def test_claim_rejection_overrides_scope_and_request_value_is_not_identity_data
    enable_explicit_claims
    payload, claims = claim_exchange({id_token: {email: {value: "attacker@example.test"}}}, allowed: ["email"])
    assert_equal "customer@example.test", claims.fetch("email")
    payload, claims = claim_exchange({userinfo: {email: nil}}, rejected: ["email"], scope: "openid email")
    refute claims.key?("email")
    @claim_reads.clear
    response = Rack::MockRequest.new(@app).get("https://op.example.test/userinfo",
      "HTTP_AUTHORIZATION" => "Bearer #{payload.fetch('access_token')}")
    assert_equal 200, response.status
    body = JSON.parse(response.body)
    refute body.key?("email")
    assert_equal true, body.fetch("email_verified")
    assert_equal [:email_verified], @claim_reads
  end

  def test_claim_input_validation_and_disabled_consent
    assert_raises(ArgumentError) do
      auth.create_ciba_grant(account_id: @account_id, oauth_application_id: @client_id, scopes: "openid", claims: ["email"])
    end
    enable_explicit_claims
    ["{", "[]", '{"id_token":[]}', '{"id_token":{"email":true}}'].each do |value|
      assert_error post("/backchannel-authentication", login_hint: "customer@example.test", scope: "openid", claims: value), "invalid_request"
    end
    assert_equal 0, @db[:ciba_requests].count
    assert_raises(ArgumentError) do
      auth.create_ciba_grant(account_id: @account_id, oauth_application_id: @client_id, scopes: "openid", claims: ["sub"])
    end
  end

  def test_jwt_userinfo_uses_exact_issuance_and_revocation_even_after_feature_disabled
    enable_explicit_claims
    @app.plugin(:rodauth) { oauth_jwt_access_tokens true }
    first, = claim_exchange({userinfo: {email: nil}}, allowed: ["email"])
    first_grant = @db[:oauth_grants].order(:id).last
    second, claims = claim_exchange({userinfo: {email: nil}})
    refute claims.key?("urn:rodauth:ciba:token_id")
    @app.plugin(:rodauth) { ciba_claims_enabled false }
    [[first, true], [second, false]].each do |payload, expected|
      @claim_reads.clear
      response = Rack::MockRequest.new(@app).get("https://op.example.test/userinfo",
        "HTTP_AUTHORIZATION" => "Bearer #{payload.fetch('access_token')}")
      assert_equal 200, response.status, response.body
      assert_equal expected, JSON.parse(response.body).key?("email")
      assert_equal expected ? [:email] : [], @claim_reads
    end
    auth.revoke_ciba_grant(first_grant[:ciba_grant_id])
    response = Rack::MockRequest.new(@app).get("https://op.example.test/userinfo",
      "HTTP_AUTHORIZATION" => "Bearer #{first.fetch('access_token')}")
    assert_equal 401, response.status
  end

  def test_claims_migration_preserves_legacy_requests_and_consent
    public_id = accept_request
    approve(public_id)
    request = @db[:ciba_requests].first
    grant = @db[:ciba_grants].first
    enable_explicit_claims
    assert_equal request, @db[:ciba_requests].first.reject { |key, _| key == :requested_claims }
    assert_equal grant, @db[:ciba_grants].first.reject { |key, _| key == :claims }
    assert_equal 200, poll(public_id).status
  end

  def test_legacy_jwt_never_borrows_claim_consent_from_another_issuance
    @app.plugin(:rodauth) { oauth_jwt_access_tokens true }
    id = accept_request
    approve(id)
    legacy, = decode_id_token(poll(id))
    # Reproduce the pre-marker wire format explicitly. New CIBA JWT issuance
    # binds the row even when the optional claims capability is disabled.
    legacy_claims, legacy_header = JWT.decode(legacy.fetch("access_token"), nil, false)
    legacy_claims.delete("urn:rodauth:ciba:token_id")
    legacy["access_token"] = JWT.encode(legacy_claims, KEY, "RS256", legacy_header)
    old_row = @db[:oauth_grants].get(:id)
    enable_explicit_claims
    claim_exchange({userinfo: {email: nil}}, allowed: ["email"])
    # Simulate old issuance cleanup while its signed JWT is still in circulation.
    # The only remaining row for the account/client authorizes explicit email.
    @db[:oauth_grants].where(id: old_row).delete
    @claim_reads.clear
    response = Rack::MockRequest.new(@app).get("https://op.example.test/userinfo",
      "HTTP_AUTHORIZATION" => "Bearer #{legacy.fetch('access_token')}")
    assert_equal 200, response.status, response.body
    refute JSON.parse(response.body).key?("email")
    assert_empty @claim_reads
  end

  def test_new_ciba_jwt_without_explicit_claims_is_bound_to_issuance
    @app.plugin(:rodauth) { oauth_jwt_access_tokens true }
    id = accept_request
    approve(id)
    payload, = decode_id_token(poll(id))
    http = Rack::MockRequest.new(@app)
    headers = {"HTTP_AUTHORIZATION" => "Bearer #{payload.fetch('access_token')}"}
    assert_equal 200, http.get("https://op.example.test/userinfo", headers).status
    @db[:oauth_grants].delete
    assert_equal 401, http.get("https://op.example.test/userinfo", headers).status
  end
end
