# frozen_string_literal: true
require_relative "ciba_refresh_test"
require_relative "ciba_claims_test"
require_relative "ciba_rar_test"

class CibaIntegrationTest
  def refresh_permissions_scenario(jwt:)
    enable_rar(jwt: jwt)
    enable_explicit_claims
    enable_refresh
    @db[:oauth_applications].update(scopes: "openid offline_access read")
    @app.plugin(:rodauth) { oauth_application_scopes %w[openid offline_access read] }
    response = post("/backchannel-authentication", scope: "openid offline_access read", login_hint: "customer@example.test",
      resource: RESOURCE_A, claims: JSON.generate(id_token: {email: nil, auth_time: nil}),
      authorization_details: JSON.generate(rar_details(%w[read delete])))
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body).fetch("auth_req_id")
    consent = auth.create_ciba_grant(account_id: @account_id, oauth_application_id: @client_id,
      scopes: "openid offline_access", claims: ["email"], resources: {RESOURCE_A => "read"},
      authorization_details: rar_details(["read"]))
    auth.backchannel_result(@db[:ciba_requests].get(:id), consent, auth_time: 123)
    initial = resource_poll(id, RESOURCE_A)
    assert_equal 200, initial.status, initial.body
    payload, identity = decode_id_token(initial)
    assert_equal "customer@example.test", identity["email"]
    token = payload.fetch("refresh_token")
    source = @db[:ciba_refresh_tokens].first
    assert_equal rar_details(%w[read delete]), JSON.parse(source[:requested_authorization_details])

    now = Time.now.to_i
    @db[:ciba_refresh_tokens].update(issued_at: now - 800, expires_at: now + 200)
    forbidden = refresh_with(token, resource: RESOURCE_A,
      authorization_details: JSON.generate(rar_details(["delete"])))
    assert_error forbidden, "invalid_authorization_details"
    assert_equal 1, @db[:ciba_refresh_tokens].count
    assert_nil @db[:ciba_refresh_tokens].get(:consumed_at)
    @db[:ciba_grants].where(id: consent[:id]).update(claims: JSON.generate(allowed: ["email"], rejected: ["email"]))
    @claim_reads.clear
    updated = refresh_with(token, resource: RESOURCE_A,
      claims: JSON.generate(id_token: {email: nil, email_verified: nil}))
    assert_equal 200, updated.status, updated.body
    updated_payload, updated_identity = decode_id_token(updated)
    refute updated_identity.key?("email")
    refute updated_identity.key?("email_verified")
    assert_empty @claim_reads
    assert_equal 123, updated_identity["auth_time"]
    assert_equal rar_details(["read"]), updated_payload["authorization_details"]
    refute updated_identity.key?("authorization_details")
    successor = updated_payload.fetch("refresh_token")
    refute_equal token, successor
    saved = @db[:ciba_refresh_tokens].order(:id).last
    %i[requested_claims requested_resources requested_authorization_details auth_time scopes].each do |key|
      assert_equal source[key], saved[key]
    end
    if jwt
      claims, = JWT.decode(updated_payload.fetch("access_token"), KEY.public_key, true, algorithms: ["RS256"])
      assert_equal rar_details(["read"]), claims["authorization_details"]
    else
      introspected = post("/introspect", token: updated_payload.fetch("access_token"))
      assert_equal rar_details(["read"]), JSON.parse(introspected.body)["authorization_details"]
    end
    @app.plugin(:rodauth) { ciba_authorization_details_enabled false }
    assert_error refresh_with(successor, resource: RESOURCE_A), "invalid_grant"
    @app.plugin(:rodauth) { ciba_authorization_details_enabled true }
    @db[:ciba_grants].where(id: consent[:id]).update(authorization_details: "[]")
    reduced = refresh_with(successor, resource: RESOURCE_A)
    assert_equal 200, reduced.status, reduced.body
    refute JSON.parse(reduced.body).key?("authorization_details")
  end

  def test_refresh_claims_and_rar_opaque
    refresh_permissions_scenario(jwt: false)
  end

  def test_refresh_claims_and_rar_jwt
    refresh_permissions_scenario(jwt: true)
  end
end
