# frozen_string_literal: true
require_relative "ciba_authentication_claims_test"

class CibaIntegrationTest
  def test_conformance_expiry_origin_precedes_hint_resolution
    now = 1_800_000_000
    started = now
    @app.plugin(:rodauth) do
      resolve_ciba_login_hint do |hint, oauth_application:|
        scope.env.fetch("test.resolve_delay").call
        db[:accounts].where(email: hint).get(:id)
      end
    end
    response = post("/backchannel-authentication",
      {scope: "openid", login_hint: "customer@example.test", requested_expiry: "20"},
      "test.now" => -> { now }, "test.resolve_delay" => -> { now += 7 },
      "test.device" => ->(_, _) { now += 3 })
    assert_equal 200, response.status, response.body
    row = @db[:ciba_requests].first
    assert_equal started, row[:created_at]
    assert_equal started + 20, row[:expires_at]
    assert_equal 20, JSON.parse(response.body).fetch("expires_in")
  end

  def test_conformance_processing_delay_does_not_extend_receipt_based_lifetime
    now = 1_800_000_000
    response = post("/backchannel-authentication",
      {scope: "openid", login_hint: "customer@example.test", requested_expiry: "20"},
      "test.now" => -> { now }, "test.device" => ->(_, _) { now += 20 })
    assert_equal 200, response.status, response.body
    payload = JSON.parse(response.body)
    assert_equal 20, payload.fetch("expires_in")
    assert_error poll(payload.fetch("auth_req_id"), "test.now" => -> { now }), "expired_token"
    assert_empty @db[:oauth_grants].all
  end

  def test_conformance_auth_time_required_by_request_is_saved_and_enforced
    enable_explicit_claims
    enable_refresh
    [
      {max_age: "0"},
      {max_age: "60"},
      {claims: JSON.generate(id_token: {auth_time: {essential: true}})}
    ].each do |extra|
      response = post("/backchannel-authentication",
        {scope: "openid offline_access", login_hint: "customer@example.test"}.merge(extra))
      assert_equal 200, response.status, response.body
      id = JSON.parse(response.body).fetch("auth_req_id")
      assert_raises(Rodauth::CibaSupport::Ineligible) { approve(id) }
      assert_equal "pending", @db[:ciba_requests].order(:id).last[:status]
      approve(id, auth_time: 123)
      issued = poll(id)
      assert_equal 200, issued.status, issued.body
      payload, claims = decode_id_token(issued)
      assert_equal 123, claims.fetch("auth_time")
      refreshed = refresh_with(payload.fetch("refresh_token"))
      assert_equal 200, refreshed.status, refreshed.body
      assert_equal 123, decode_id_token(refreshed).last.fetch("auth_time")
      source = @db[:ciba_refresh_tokens].order(:id).last
      @db[:ciba_refresh_tokens].where(id: source[:id]).update(auth_time: nil)
      assert_error refresh_with(payload.fetch("refresh_token")), "invalid_grant"
      assert_equal source.merge(auth_time: nil), @db[:ciba_refresh_tokens].where(id: source[:id]).first
    end
  end

  def test_conformance_essential_auth_time_is_checked_again_at_issuance
    enable_explicit_claims
    response = post("/backchannel-authentication", scope: "openid", login_hint: "customer@example.test",
      claims: JSON.generate(id_token: {auth_time: {essential: true}}))
    id = JSON.parse(response.body).fetch("auth_req_id")
    approve(id, auth_time: 123)
    @db[:ciba_requests].update(auth_time: nil)
    assert_error poll(id), "invalid_grant"
    assert_equal "approved", @db[:ciba_requests].first[:status]
    assert_empty @db[:oauth_grants].all
  end

  def test_conformance_voluntary_auth_time_remains_optional
    enable_explicit_claims
    [nil, false].each do |essential|
      value = essential.nil? ? nil : {essential: essential}
      response = post("/backchannel-authentication", scope: "openid", login_hint: "customer@example.test",
        claims: JSON.generate(id_token: {auth_time: value}))
      assert_equal 200, response.status, response.body
      id = JSON.parse(response.body).fetch("auth_req_id")
      approve(id)
      result = poll(id)
      assert_equal 200, result.status, result.body
      refute decode_id_token(result).last.key?("auth_time")
    end
  end
end
