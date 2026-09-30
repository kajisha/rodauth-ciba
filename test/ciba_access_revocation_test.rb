# frozen_string_literal: true
require_relative "ciba_refresh_test"

class CibaIntegrationTest
  def test_access_revocation_preserves_consent_but_invalidates_its_artifacts
    enable_refresh
    @app.plugin(:rodauth) { enable :oauth_token_revocation, :oauth_token_introspection }
    other = @db[:oauth_applications].first.reject { |key, _| key == :id }
    @db[:oauth_applications].insert(other.merge(client_id: "other"))
    [nil, "access_token", "refresh_token", "unknown"].each do |hint|
      started = post("/backchannel-authentication", scope: "openid offline_access", login_hint: "customer@example.test")
      assert_equal 200, started.status
      id = JSON.parse(started.body).fetch("auth_req_id")
      approve(id)
      issued = JSON.parse(poll(id).body)
      consent = auth.ciba_grant(@db[:ciba_grants].max(:id))
      sibling = refresh_with(issued.fetch("refresh_token"))
      assert_equal 200, sibling.status
      params = {token: issued.fetch("access_token")}
      params[:token_type_hint] = hint if hint
      foreign = post("/revoke", params, "HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64('other:test-secret')}")
      assert_error foreign, "invalid_request"
      response = post("/revoke", params)
      assert_equal 200, response.status, response.body
      assert_equal "", response.body
      assert_equal consent, auth.ciba_grant(consent[:id])
      assert_error refresh_with(issued.fetch("refresh_token")), "invalid_grant"
      assert_error poll(id), "invalid_grant"
      assert_nil auth.ciba_grant(consent[:id])[:revoked_at]
      introspected = post("/introspect", token: JSON.parse(sibling.body).fetch("access_token"))
      assert_equal false, JSON.parse(introspected.body)["active"]
      assert_equal 200, post("/revoke", params, "HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64('other:test-secret')}").status
      next_id = accept_request
      auth.backchannel_result(@db[:ciba_requests].max(:id), consent)
      assert_equal 200, poll(next_id).status
    end
  end

  def test_access_revocation_without_optional_refresh_storage
    @app.plugin(:rodauth) { enable :oauth_token_revocation }
    id = accept_request
    approve(id)
    access = JSON.parse(poll(id).body).fetch("access_token")
    refute @db.table_exists?(:ciba_refresh_tokens)
    unauthenticated = post("/revoke", {token: access}, "HTTP_AUTHORIZATION" => nil,
      "rack.session" => {account_id: @account_id})
    assert_equal 401, unauthenticated.status
    assert_equal 200, post("/revoke", token: access).status
    assert_nil @db[:ciba_grants].get(:revoked_at)
    assert_equal 0, @db[:ciba_requests].count
    assert_equal 0, @db[:oauth_grants].where(revoked_at: nil).count
  end

  def test_access_revocation_preserves_unrelated_oauth_route_behavior
    @app.plugin(:rodauth) { enable :oauth_token_revocation }
    id = accept_request
    approve(id)
    assert_equal 200, poll(id).status
    ordinary = "ordinary-opaque-access"
    row_id = @db[:oauth_grants].insert(account_id: @account_id, oauth_application_id: @client_id,
      type: "authorization_code", scopes: "openid", expires_in: Time.now + 3600,
      token: auth.send(:generate_token_hash, ordinary))
    response = post("/revoke", {}, input: JSON.generate(token: ordinary),
      "CONTENT_TYPE" => "application/json", "rack.session" => {})
    assert_equal 200, response.status, response.body
    assert_equal ordinary, JSON.parse(response.body)["token"]
    refute_nil @db[:oauth_grants].where(id: row_id).get(:revoked_at)
    assert_nil @db[:ciba_grants].get(:revoked_at)
    assert_equal 1, @db[:ciba_requests].count
  end

  def test_access_revocation_and_refresh_serialize_on_saved_consent
    enable_refresh
    @app.plugin(:rodauth) { enable :oauth_token_revocation }
    token = issue_refresh
    access = JSON.parse(refresh_with(token).body).fetch("access_token")
    results = parallel_decisions { |index| index.zero? ? post("/revoke", token: access) : refresh_with(token) }
    assert_equal 200, results.first.status, results.first.body
    assert_includes [200, 400], results.last.status
    assert_equal 0, @db[:ciba_refresh_tokens].count
    assert_equal 0, @db[:ciba_requests].count
    assert_equal 0, @db[:oauth_grants].where(revoked_at: nil).count
    assert_nil @db[:ciba_grants].get(:revoked_at)
  end

  def test_access_revocation_hook_failure_restores_deleted_sources
    enable_refresh
    @app.plugin(:rodauth) do
      enable :oauth_token_revocation
      after_revoke { raise "injected hook failure" }
    end
    token = issue_refresh
    access = JSON.parse(refresh_with(token).body).fetch("access_token")
    response = post("/revoke", {token: access}, "test.processing_error" => ->(_) {})
    assert_equal 500, response.status
    assert_equal 1, @db[:ciba_requests].count
    assert_equal 1, @db[:ciba_refresh_tokens].count
    assert_equal 2, @db[:oauth_grants].where(revoked_at: nil).count
    assert_equal 200, refresh_with(token).status
  end

  def test_access_revocation_recognizes_cleaned_up_namespaced_tokens
    @app.plugin(:rodauth) { enable :oauth_token_revocation }
    id = accept_request
    approve(id)
    token = JSON.parse(poll(id).body).fetch("access_token")
    assert token.start_with?("ciba_at_")
    @db[:oauth_grants].delete
    [token, "ciba_at_unknown"].each do |value|
      [nil, "refresh_token", "unknown"].each do |hint|
        params = {token: value}
        params[:token_type_hint] = hint if hint
        response = post("/revoke", params)
        assert_equal 200, response.status, response.body
        assert_equal "", response.body
      end
    end
    assert_nil @db[:ciba_grants].get(:revoked_at)
    assert_equal 1, @db[:ciba_requests].count
    assert_equal 401, post("/revoke", {token: "ciba_at_unknown"}, "HTTP_AUTHORIZATION" => nil).status
    assert_error post("/revoke", token: "ciba_at_#{'x' * 1024}"), "invalid_request"
  end

  def test_access_revocation_accepts_legacy_unprefixed_stored_ciba_tokens
    @app.plugin(:rodauth) { enable :oauth_token_revocation }
    id = accept_request
    approve(id)
    assert_equal 200, poll(id).status
    legacy = "legacy-opaque-ciba-token"
    @db[:oauth_grants].update(token: auth.send(:generate_token_hash, legacy))
    assert_equal 200, post("/revoke", token: legacy).status
    assert_equal 0, @db[:ciba_requests].count
    assert_nil @db[:ciba_grants].get(:revoked_at)
  end

  def test_access_revocation_rejects_signed_ciba_jwt_without_changing_consent
    @app.plugin(:rodauth) do
      enable :oauth_token_revocation
      oauth_jwt_access_tokens true
    end
    id = accept_request
    approve(id)
    response = poll(id)
    payload, identity = decode_id_token(response)
    token = payload.fetch("access_token")
    claims, = JWT.decode(token, KEY.public_key, true, algorithms: ["RS256"])
    assert_equal @db[:oauth_grants].get(:id), claims["urn:rodauth:ciba:token_id"]
    refute identity.key?("urn:rodauth:ciba:token_id")
    [nil, "refresh_token", "access_token", "unknown"].each do |hint|
      params = {token: token}
      params[:token_type_hint] = hint if hint
      assert_error post("/revoke", params), "unsupported_token_type"
    end
    expired = JWT.encode(claims.merge("exp" => 1), KEY, "RS256", typ: "at+jwt")
    assert_error post("/revoke", token: expired), "unsupported_token_type"
    assert_equal 401, post("/revoke", {token: token}, "HTTP_AUTHORIZATION" => nil).status
    refute @db[:oauth_grants].get(:revoked_at)
    refute @db[:ciba_grants].get(:revoked_at)
    assert_equal 1, @db[:ciba_requests].count
    @db[:oauth_grants].delete
    assert_error post("/revoke", token: token), "unsupported_token_type"
  end

  def test_access_revocation_does_not_trust_forged_jwt_markers
    @app.plugin(:rodauth) do
      enable :oauth_token_revocation
      oauth_jwt_access_tokens true
    end
    id = accept_request
    approve(id)
    token = JSON.parse(poll(id).body).fetch("access_token")
    claims, = JWT.decode(token, nil, false)
    other_key = OpenSSL::PKey::RSA.generate(2048)
    forged = [
      JWT.encode(claims, other_key, "RS256", typ: "at+jwt"),
      JWT.encode(claims.merge("iss" => "https://other.example.test"), KEY, "RS256", typ: "at+jwt"),
      JWT.encode(claims, KEY, "RS256", typ: "id_token+jwt"),
      JWT.encode(claims, nil, "none", typ: "at+jwt")
    ]
    forged.each { |value| assert_error post("/revoke", token: value), "invalid_request" }
    assert_nil @db[:ciba_grants].get(:revoked_at)
    assert_nil @db[:oauth_grants].get(:revoked_at)
    assert_equal 1, @db[:ciba_requests].count
  end
end
