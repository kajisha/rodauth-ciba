# frozen_string_literal: true
require_relative "ciba_conformance_test"
require_relative "ciba_pairwise_test"

class CibaIntegrationTest
  def constraint_request(claims, scope: "openid", extra: {}, headers: {})
    response = post("/backchannel-authentication", {scope: scope, login_hint: "customer@example.test",
      claims: JSON.generate(claims)}.merge(extra), headers)
    assert_equal 200, response.status, response.body
    JSON.parse(response.body).fetch("auth_req_id")
  end

  def test_constraints_essential_acr_and_sub_at_approval
    enable_explicit_claims
    [{acr: {essential: true, values: ["required"]}}, {sub: {value: "wrong"}}].each do |claims|
      id = constraint_request({id_token: claims})
      assert_raises(Rodauth::CibaSupport::Ineligible) { approve(id, acr: "other") }
      assert_equal "pending", @db[:ciba_requests].order(:id).last[:status]
      assert_empty @db[:ciba_grants].all
    end
  end

  def test_constraints_issuance_rechecks_and_refresh_preserves_requirements
    enable_explicit_claims
    enable_refresh
    id = constraint_request({id_token: {acr: {essential: true, value: "required"}, sub: {values: [@account_id.to_s]}}}, scope: "openid offline_access")
    approve(id, acr: "required")
    row = @db[:ciba_requests].first
    @db[:ciba_requests].where(id: row[:id]).update(acr: "other")
    assert_error poll(id), "invalid_grant"
    assert_empty @db[:oauth_grants].all
    @db[:ciba_requests].where(id: row[:id]).update(acr: "required")
    payload, claims = decode_id_token(poll(id))
    assert_equal "required", claims["acr"]
    refresh = @db[:ciba_refresh_tokens].first
    @db[:ciba_refresh_tokens].where(id: refresh[:id]).update(acr: "other")
    before = @db[:ciba_refresh_tokens].first
    assert_error post("/token", grant_type: "refresh_token", refresh_token: payload.fetch("refresh_token")), "invalid_grant"
    assert_equal before, @db[:ciba_refresh_tokens].first
  end

  def test_constraints_public_subject_matching_and_generic_essential_absence
    enable_explicit_claims
    id = constraint_request({id_token: {sub: {value: @account_id.to_s}, email: {essential: true}}})
    approve(id)
    _, claims = decode_id_token(poll(id))
    assert_equal @account_id.to_s, claims["sub"]
    refute claims.key?("email")
  end

  def test_constraints_pairwise_compares_rp_subject_not_account_id
    enable_explicit_claims
    configure_pairwise
    subject = OpenSSL::HMAC.hexdigest("SHA256", "pairwise-test-secret", JSON.generate(["keys.example.test", @account_id]))
    headers = {"HTTP_AUTHORIZATION" => nil}
    wrong = constraint_request({id_token: {sub: {value: @account_id.to_s}}}, extra: pairwise_assertion, headers: headers)
    assert_raises(Rodauth::CibaSupport::Ineligible) { approve(wrong) }
    id = constraint_request({id_token: {sub: {value: subject}}}, extra: pairwise_assertion, headers: headers)
    approve(id)
    result = post("/token", pairwise_assertion.merge(grant_type: GRANT, auth_req_id: id), headers)
    assert_equal 200, result.status, result.body
    assert_equal subject, decode_id_token(result).last["sub"]
  end

  def test_constraints_ordinary_values_filter_both_targets_without_injection
    enable_explicit_claims
    ["id_token", "userinfo"].each do |target|
      ["wrong", "customer@example.test"].each do |value|
        payload, claims = claim_exchange({target => {email: {essential: true, values: [value]}}}, allowed: ["email"])
        if target == "userinfo"
          response = Rack::MockRequest.new(@app).get("https://op.example.test/userinfo", "HTTP_AUTHORIZATION" => "Bearer #{payload.fetch('access_token')}")
          assert_equal 200, response.status, response.body
          claims = JSON.parse(response.body)
        end
        assert_equal value == "customer@example.test", claims.key?("email")
      end
    end
  end

  def test_constraints_invalid_qualifier_shapes
    enable_explicit_claims
    [{essential: "true"}, {values: "wrong"}, {essential: nil}].each do |options|
      assert_error post("/backchannel-authentication", scope: "openid", login_hint: "customer@example.test",
        claims: JSON.generate(id_token: {email: options})), "invalid_request"
    end
    assert_empty @db[:ciba_requests].all
  end

  def test_constraints_signed_positive_integral_json_numbers
    enable_signed_requests
    [60, 60.0, 6e1, "60"].each do |value|
      response = post("/backchannel-authentication", request: signed_ciba_request({requested_expiry: value}))
      assert_equal 200, response.status, response.body
      assert_equal 60, JSON.parse(response.body)["expires_in"]
    end
    [60.5, 0.0, -1.0].each do |value|
      assert_error post("/backchannel-authentication", request: signed_ciba_request({requested_expiry: value})), "invalid_request"
    end
  end

  def test_constraints_missing_required_acr_and_malformed_persisted_options
    enable_explicit_claims
    id = constraint_request({id_token: {acr: {essential: true, values: ["required"]}}})
    assert_raises(Rodauth::CibaSupport::Ineligible) { approve(id) }
    approve(id, acr: "required")
    @db[:ciba_requests].update(requested_claims: JSON.generate(id_token: {acr: {essential: true, values: "required"}}))
    assert_error poll(id), "invalid_grant"
    assert_empty @db[:oauth_grants].all
  end

  def test_constraints_refresh_subject_tampering_and_account_value_changes
    enable_explicit_claims
    enable_refresh
    id = constraint_request({id_token: {sub: {value: @account_id.to_s}, email: {value: "customer@example.test"}},
      userinfo: {email: {value: "customer@example.test"}}}, scope: "openid offline_access")
    grant = auth.create_ciba_grant(account_id: @account_id, oauth_application_id: @client_id,
      scopes: "openid offline_access", claims: ["email"])
    row = @db[:ciba_requests].order(:id).last
    auth.approve_ciba_request(row[:id], account_id: @account_id, grant_id: grant[:id])
    payload, claims = decode_id_token(poll(id))
    assert_equal "customer@example.test", claims["email"]
    @app.plugin(:rodauth) { get_oidc_param { |_account, _name| "changed@example.test" } }
    response = post("/token", grant_type: "refresh_token", refresh_token: payload.fetch("refresh_token"))
    assert_equal 200, response.status, response.body
    renewed, claims = decode_id_token(response)
    refute claims.key?("email")
    info = Rack::MockRequest.new(@app).get("https://op.example.test/userinfo", "HTTP_AUTHORIZATION" => "Bearer #{renewed.fetch('access_token')}")
    assert_equal 200, info.status, info.body
    refute JSON.parse(info.body).key?("email")
    @db[:ciba_refresh_tokens].update(requested_claims: JSON.generate(id_token: {sub: {value: "wrong"}}))
    assert_error post("/token", grant_type: "refresh_token", refresh_token: renewed.fetch("refresh_token")), "invalid_grant"
  end

  def test_constraints_optional_auth_claim_mismatch_and_voluntary_acr
    enable_explicit_claims
    id = constraint_request({id_token: {auth_time: {value: 111}, amr: {value: ["otp"]}, acr: {values: ["preferred"]}}})
    approve(id, auth_time: 123, acr: "achieved", amr: ["pwd"])
    _, claims = decode_id_token(poll(id))
    refute claims.key?("auth_time")
    refute claims.key?("amr")
    assert_equal "achieved", claims["acr"]
  end

  def test_constraints_nonce_cannot_be_omitted_to_satisfy_value
    enable_explicit_claims
    id = constraint_request({id_token: {nonce: {value: "wrong"}}}, extra: {nonce: "actual"})
    approve(id)
    assert_error poll(id), "invalid_grant"
    assert_empty @db[:oauth_grants].all
  end

  def test_constraints_pairwise_userinfo_preserves_issued_subject_after_sector_change
    enable_explicit_claims
    configure_pairwise
    subject = OpenSSL::HMAC.hexdigest("SHA256", "pairwise-test-secret", JSON.generate(["keys.example.test", @account_id]))
    headers = {"HTTP_AUTHORIZATION" => nil}
    id = constraint_request({id_token: {sub: {value: subject}}, userinfo: {sub: {value: subject}}}, extra: pairwise_assertion, headers: headers)
    approve(id)
    response = post("/token", pairwise_assertion.merge(grant_type: GRANT, auth_req_id: id), headers)
    assert_equal 200, response.status, response.body
    payload, claims = decode_id_token(response)
    @db[:oauth_applications].update(jwks_uri: "https://changed-sector.example.test/jwks")
    info = Rack::MockRequest.new(@app).get("https://op.example.test/userinfo", "HTTP_AUTHORIZATION" => "Bearer #{payload.fetch('access_token')}")
    assert_equal 200, info.status, info.body
    assert_equal claims.fetch("sub"), JSON.parse(info.body).fetch("sub")
  end

  def test_constraints_signed_userinfo_final_issuer_and_audience
    enable_explicit_claims
    @db.alter_table(:oauth_applications) { add_column :userinfo_signed_response_alg, String }
    @db[:oauth_applications].update(userinfo_signed_response_alg: "RS256")
    id = constraint_request({userinfo: {iss: {value: "wrong"}}})
    assert_raises(Rodauth::CibaSupport::Ineligible) { approve(id) }
    id = constraint_request({userinfo: {iss: {value: "https://op.example.test"}, aud: {value: "support"}}})
    approve(id)
    payload, = decode_id_token(poll(id))
    http = Rack::MockRequest.new(@app)
    headers = {"HTTP_AUTHORIZATION" => "Bearer #{payload.fetch('access_token')}"}
    response = http.get("https://op.example.test/userinfo", headers)
    assert_equal 200, response.status, response.body
    claims, = JWT.decode(response.body, KEY.public_key, true, algorithms: ["RS256"])
    assert_equal "https://op.example.test", claims["iss"]
    assert_equal "support", claims["aud"]
    @app.plugin(:rodauth) { oauth_jwt_issuer { "https://changed.example.test" } }
    assert_equal 401, http.get("https://op.example.test/userinfo", headers).status
  end

  def test_constraints_numeric_timestamp_qualifier_is_json_number
    enable_explicit_claims
    id = constraint_request({id_token: {auth_time: {essential: true, value: 123.0}}})
    approve(id, auth_time: 123)
    assert_equal 123, decode_id_token(poll(id)).last["auth_time"]
  end

  def test_constraints_object_values_compare_json_member_names
    enable_explicit_claims
    @app.plugin(:rodauth) { get_oidc_param { |_account, name| "Tokyo" if name == :locality } }
    ["Tokyo", "Osaka"].each do |city|
      payload, claims = claim_exchange({id_token: {address: {value: {locality: city}}}}, allowed: ["address"])
      assert_equal city == "Tokyo", claims.key?("address")
      assert_equal({"locality" => "Tokyo"}, claims["address"]) if city == "Tokyo"
    end
  end
end
