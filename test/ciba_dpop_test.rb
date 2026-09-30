# frozen_string_literal: true
require_relative "test_helper"

class CibaIntegrationTest
  def test_ciba_dpop_opaque_introspection_exposes_binding
    assert_ciba_dpop_introspection
  end

  def test_ciba_dpop_resource_introspection_exposes_binding
    assert_ciba_dpop_introspection(resource: "https://api.example.test/data")
  end

  def assert_ciba_dpop_introspection(resource: nil)
    configure_ciba_dpop
    @app.plugin(:rodauth) { enable :oauth_token_introspection }
    if resource
      Rodauth::CibaSupport::Schema.add_resources(@db)
      @db[:oauth_applications].update(scopes: "openid read")
      @app.plugin(:rodauth) do
        ciba_resources_enabled true
        ciba_resource_servers(resource => {scopes: ["read"], audience: resource})
        oauth_application_scopes %w[openid read]
      end
    end
    start = {scope: resource ? "openid read" : "openid", login_hint: "customer@example.test"}
    start[:resource] = resource if resource
    response = post("/backchannel-authentication", start)
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body).fetch("auth_req_id")
    consent = {account_id: @account_id, oauth_application_id: @client_id, scopes: "openid"}
    consent[:resources] = {resource => "read"} if resource
    auth.backchannel_result(@db[:ciba_requests].get(:id), auth.create_ciba_grant(**consent))
    params = {grant_type: GRANT, auth_req_id: id}
    params[:resource] = resource if resource
    issued = post("/token", params, "HTTP_DPOP" => ciba_dpop_proof)
    assert_equal 200, issued.status, issued.body
    token = JSON.parse(issued.body).fetch("access_token")
    unauthorized = post("/introspect", {token: token}, "HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64('support:wrong-secret')}")
    assert_equal 401, unauthorized.status
    response = post("/introspect", token: token)
    assert_equal 200, response.status, response.body
    info = JSON.parse(response.body)
    assert_equal true, info.fetch("active")
    assert_equal "DPoP", info.fetch("token_type")
    assert_equal JWT::JWK::Thumbprint.new(JWT::JWK.new(@dpop_key)).generate, info.fetch("cnf").fetch("jkt")
    assert_equal resource, info.fetch("aud") if resource
    assert_equal(resource ? "read" : "openid", info.fetch("scope"))
    assert_equal 1, @db[:ciba_client_assertions].count # Introspection is not proof presentation.
    assert_equal({"active" => false}, JSON.parse(post("/introspect", token: "ciba_at_not-issued").body))
    # An unrelated grant still follows upstream lookup policy, even with a key.
    ordinary = "ordinary-bound-token"
    @db[:oauth_grants].insert(account_id: @account_id, oauth_application_id: @client_id,
      type: "authorization_code", scopes: "openid", token: auth.send(:generate_token_hash, ordinary),
      expires_in: Time.now + 3600, dpop_jkt: info.fetch("cnf").fetch("jkt"))
    assert_equal({"active" => false}, JSON.parse(post("/introspect", token: ordinary).body))
    @db[:oauth_grants].update(expires_in: Time.now - 60)
    assert_equal({"active" => false}, JSON.parse(post("/introspect", token: token).body))
    @db[:oauth_grants].update(expires_in: Time.now + 3600)
    auth.revoke_ciba_grant(@db[:ciba_grants].get(:id))
    assert_equal({"active" => false}, JSON.parse(post("/introspect", token: token).body))
  end

  def test_ciba_dpop_nonce_requires_explicit_secret
    configure_ciba_dpop
    assert_raises(Rodauth::CibaSupport::ConfigurationError) do
      @app.plugin(:rodauth) { oauth_dpop_use_nonce true }
    end
    [false, "", "x" * 31, "x" * 33].each do |secret|
      assert_raises(Rodauth::CibaSupport::ConfigurationError) do
        @app.plugin(:rodauth) { ciba_dpop_nonce_secret secret }
      end
    end
  end

  def test_ciba_dpop_optional_nonce_challenges_old_proof
    configure_ciba_dpop
    @app.plugin(:rodauth) { ciba_dpop_nonce_secret "N" * 32 }
    id = accept_request
    approve(id)
    old = poll(id, "HTTP_DPOP" => ciba_dpop_proof({iat: 1}))
    assert_error old, "use_dpop_nonce"
    assert old["DPoP-Nonce"]
    # Nonce support alone does not require it for a fresh proof.
    fresh = poll(id, "HTTP_DPOP" => ciba_dpop_proof)
    assert_equal 200, fresh.status, fresh.body
    assert fresh["DPoP-Nonce"]
  end

  def test_ciba_dpop_nonce_opaque_flow_and_replay_retention
    assert_ciba_dpop_nonce_flow
  end

  def test_ciba_dpop_nonce_jwt_flow_and_replay_retention
    @app.plugin(:rodauth) { oauth_jwt_access_tokens true }
    assert_ciba_dpop_nonce_flow
  end

  def assert_ciba_dpop_nonce_flow
    configure_ciba_dpop
    @app.plugin(:rodauth) do
      ciba_dpop_nonce_secret "N" * 32
      oauth_dpop_use_nonce true
    end
    id = accept_request
    approve(id)
    challenge = poll(id, "HTTP_DPOP" => ciba_dpop_proof)
    assert_error challenge, "use_dpop_nonce"
    nonce = challenge["DPoP-Nonce"]
    assert_match(/\A[A-Za-z0-9_-]{43}\z/, nonce)
    [nil, true, 1].each do |value|
      assert_error poll(id, "HTTP_DPOP" => ciba_dpop_proof({nonce: value})), "invalid_dpop_proof"
    end
    assert_error poll(id, "HTTP_DPOP" => ciba_dpop_proof({nonce: "wrong"})), "use_dpop_nonce"
    assert_error poll(id, "HTTP_DPOP" => ciba_dpop_proof({nonce: nonce, iat: 0})), "invalid_dpop_proof"
    ancient = ciba_dpop_proof({nonce: nonce, iat: 1})
    issued = poll(id, "HTTP_DPOP" => ancient)
    assert_equal 200, issued.status, issued.body
    assert_equal 0, auth.cleanup_ciba_client_assertions
    assert_equal 1, @db[:ciba_client_assertions].count
    second = accept_request
    approve(second)
    assert_error poll(second, "HTTP_DPOP" => ancient), "invalid_grant"
    assert_equal "approved", @db[:ciba_requests].order(:id).last[:status]
    token = JSON.parse(issued.body).fetch("access_token")
    target = "https://op.example.test/userinfo"
    attributes = {htm: "GET", htu: target, ath: Base64.urlsafe_encode64(Digest::SHA256.digest(token), padding: false)}
    get = ->(proof) { Rack::MockRequest.new(@app).get(target, "HTTP_AUTHORIZATION" => "DPoP #{token}", "HTTP_DPOP" => proof) }
    challenged = get.call(ciba_dpop_proof(attributes))
    assert_equal 401, challenged.status, challenged.body
    assert_equal "use_dpop_nonce", JSON.parse(challenged.body).fetch("error")
    assert challenged["DPoP-Nonce"]
    valid = ciba_dpop_proof(attributes.merge(nonce: nonce, iat: 1))
    info = get.call(valid)
    assert_equal 200, info.status, info.body
    assert_equal @account_id.to_s, JSON.parse(info.body).fetch("sub")
    assert_equal 401, get.call(valid).status
    assert_equal 0, auth.cleanup_ciba_client_assertions
    assert_equal 2, @db[:ciba_client_assertions].count
    expired = poll(second, "HTTP_DPOP" => ciba_dpop_proof({nonce: nonce}), "test.now" => -> { Time.now.to_i + 240 })
    assert_error expired, "use_dpop_nonce"
    @app.plugin(:rodauth) { ciba_dpop_nonce_secret "R" * 32 }
    rotated = poll(second, "HTTP_DPOP" => ciba_dpop_proof({nonce: nonce}))
    assert_error rotated, "use_dpop_nonce"
    refute_equal nonce, rotated["DPoP-Nonce"]
    assert_equal 200, poll(second, "HTTP_DPOP" => ciba_dpop_proof({nonce: rotated["DPoP-Nonce"]})).status
  end

  def configure_ciba_dpop
    @db.alter_table(:oauth_grants) { add_column :dpop_jkt, String }
    @app.plugin(:rodauth) { enable :oauth_dpop }
    @dpop_key = OpenSSL::PKey::EC.generate("prime256v1")
  end

  def ciba_dpop_proof(changes = {}, key: @dpop_key, header_changes: {})
    claims = {jti: SecureRandom.uuid, iat: Time.now.to_i, htm: "POST",
      htu: "https://op.example.test/token"}.merge(changes)
    header = {alg: "ES256", typ: "dpop+jwt", jwk: JWT::JWK.new(key).export}.merge(header_changes)
    # Sign malformed claim shapes too, so rejection tests reach the verifier.
    input = [header, claims].map { |value| Base64.urlsafe_encode64(JSON.generate(value), padding: false) }.join(".")
    signature = JWT::JWA.resolve("ES256").sign(data: input, signing_key: key)
    "#{input}.#{Base64.urlsafe_encode64(signature, padding: false)}"
  end

  def test_ciba_dpop_random_identifier_and_replay_rollback
    configure_ciba_dpop
    id = accept_request
    proof = ciba_dpop_proof
    assert_error poll(id, "HTTP_DPOP" => proof), "authorization_pending"
    assert_equal 0, @db[:ciba_client_assertions].count
    approve(id)
    response = poll(id, "HTTP_DPOP" => proof, "test.now" => -> { Time.now.to_i + 10 })
    assert_equal 200, response.status, response.body
    assert_equal "DPoP", JSON.parse(response.body).fetch("token_type")
    expected = JWT::JWK::Thumbprint.new(JWT::JWK.new(@dpop_key)).generate
    assert_equal expected, @db[:oauth_grants].get(:dpop_jkt)
    assert_equal 1, @db[:ciba_client_assertions].count
    second = accept_request
    approve(second)
    assert_error poll(second, "HTTP_DPOP" => proof), "invalid_grant"
    assert_equal "approved", @db[:ciba_requests].order(:id).last[:status]
    assert_equal 1, @db[:oauth_grants].count
    assert_equal 200, poll(second, "HTTP_DPOP" => ciba_dpop_proof).status
  end

  def test_ciba_dpop_invalid_proofs_do_not_consume_approval
    configure_ciba_dpop
    id = accept_request
    approve(id)
    [{iat: Time.now.to_i - 3600}, {iat: Time.now.to_i + 3600}, {iat: "now"},
      {iat: nil}, {jti: ""}, {jti: 1}, {htm: "GET"}, {htu: "https://other.example.test/token"}].each do |changes|
      assert_error poll(id, "HTTP_DPOP" => ciba_dpop_proof(changes)), "invalid_dpop_proof"
    end
    ["bad", "x" * 8193].each do |proof|
      assert_error poll(id, "HTTP_DPOP" => proof), "invalid_dpop_proof"
    end
    [{typ: "JWT"}, {alg: "none"}, {crit: ["unknown"]}, {jwk: {}}, {jwk: "bad"},
      {jwk: JWT::JWK.new(@dpop_key).export(include_private: true)}].each do |header|
      assert_error poll(id, "HTTP_DPOP" => ciba_dpop_proof(header_changes: header)), "invalid_dpop_proof"
    end
    signature = ciba_dpop_proof.split(".")
    signature[2][0] = signature[2][0] == "A" ? "B" : "A"
    assert_error poll(id, "HTTP_DPOP" => signature.join(".")), "invalid_dpop_proof"
    assert_equal "approved", @db[:ciba_requests].get(:status)
    assert_equal 0, @db[:oauth_grants].count
    assert_equal 0, @db[:ciba_client_assertions].count
    assert_equal 200, poll(id, "HTTP_DPOP" => ciba_dpop_proof({htu: "https://op.example.test/token?ignored=1#fragment"})).status
  end

  def test_ciba_dpop_signing_failure_rolls_back_proof_claim
    configure_ciba_dpop
    id = accept_request
    approve(id)
    proof = ciba_dpop_proof
    failed = poll(id, "HTTP_DPOP" => proof, "test.fail_signing" => true, "test.processing_error" => ->(_) {})
    assert_equal 500, failed.status, failed.body
    assert_equal "approved", @db[:ciba_requests].get(:status)
    assert_equal 0, @db[:oauth_grants].count
    assert_equal 0, @db[:ciba_client_assertions].count
    assert_equal 200, poll(id, "HTTP_DPOP" => proof).status
  end

  def test_ciba_dpop_required_client_does_not_implicitly_require_nonce
    configure_ciba_dpop
    @db.alter_table(:oauth_applications) { add_column :dpop_bound_access_tokens, TrueClass }
    @db[:oauth_applications].update(dpop_bound_access_tokens: true)
    id = accept_request
    approve(id)
    assert_error poll(id), "invalid_grant"
    assert_equal 200, poll(id, "HTTP_DPOP" => ciba_dpop_proof).status
    # The scope of the fix does not replace upstream's other OAuth grant rules.
    ordinary = post("/token", {grant_type: "authorization_code", code: "not-a-code"}, "HTTP_DPOP" => ciba_dpop_proof)
    assert_equal "Invalid DPoP jti", JSON.parse(ordinary.body).fetch("error_description")
  end

  def test_ciba_dpop_same_proof_cannot_issue_two_concurrent_requests
    configure_ciba_dpop
    ids = 2.times.map { id = accept_request; approve(id); id }
    proof = ciba_dpop_proof
    responses = parallel_decisions { |index| poll(ids[index], "HTTP_DPOP" => proof) }
    responses.each_with_index do |response, index|
      if response.status == 503
        assert_equal "temporarily_unavailable", JSON.parse(response.body).fetch("error")
        responses[index] = poll(ids[index], "HTTP_DPOP" => proof)
      end
    end
    assert_equal [200, 400], responses.map(&:status).sort
    assert_equal "invalid_grant", JSON.parse(responses.find { |r| r.status == 400 }.body).fetch("error")
    assert_equal 1, @db[:oauth_grants].count
    assert_equal 1, @db[:ciba_client_assertions].count
    assert_equal ["approved", "consumed"], @db[:ciba_requests].select_map(:status).sort
  end

  def test_ciba_dpop_confidential_refresh_accepts_new_key
    assert_ciba_dpop_confidential_refresh
  end

  def test_ciba_dpop_jwt_confidential_refresh_accepts_new_key
    @app.plugin(:rodauth) { oauth_jwt_access_tokens true }
    assert_ciba_dpop_confidential_refresh
  end

  def assert_ciba_dpop_confidential_refresh
    configure_ciba_dpop
    Rodauth::CibaSupport::Schema.create_refresh_tokens(@db)
    @db[:oauth_applications].update(scopes: "openid offline_access", grant_types: "#{GRANT} refresh_token")
    @app.plugin(:rodauth) do
      ciba_refresh_tokens_enabled true
      oauth_application_scopes %w[openid offline_access]
    end
    response = post("/backchannel-authentication", scope: "openid offline_access", login_hint: "customer@example.test")
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body).fetch("auth_req_id")
    approve(id)
    response = poll(id, "HTTP_DPOP" => ciba_dpop_proof)
    assert_equal 200, response.status, response.body
    original = JSON.parse(response.body)
    @dpop_key = OpenSSL::PKey::EC.generate("prime256v1")
    proof = ciba_dpop_proof
    params = {grant_type: "refresh_token", refresh_token: original.fetch("refresh_token")}
    response = post("/token", params, "HTTP_DPOP" => proof)
    assert_equal 200, response.status, response.body
    renewed = JSON.parse(response.body)
    assert_equal "DPoP", renewed.fetch("token_type")
    thumbprint = JWT::JWK::Thumbprint.new(JWT::JWK.new(@dpop_key)).generate
    assert_equal thumbprint, @db[:oauth_grants].order(:id).last[:dpop_jkt]
    if auth.send(:oauth_jwt_access_tokens)
      claims, = JWT.decode(renewed.fetch("access_token"), KEY.public_key, true,
        algorithms: ["RS256"], verify_iss: true, iss: "https://op.example.test")
      assert_equal thumbprint, claims.fetch("cnf").fetch("jkt")
    end
    before = @db[:ciba_refresh_tokens].all
    assert_error post("/token", params, "HTTP_DPOP" => proof), "invalid_grant"
    assert_equal before, @db[:ciba_refresh_tokens].all
    assert_equal 2, @db[:oauth_grants].count
  end

  def test_ciba_dpop_opaque_userinfo_enforces_key_hash_and_replay
    assert_ciba_dpop_userinfo
  end

  def test_ciba_dpop_jwt_userinfo_enforces_key_hash_and_replay
    @app.plugin(:rodauth) { oauth_jwt_access_tokens true }
    assert_ciba_dpop_userinfo
  end

  def test_ciba_dpop_opaque_post_userinfo
    assert_ciba_dpop_userinfo(method: "POST")
  end

  def test_ciba_dpop_jwt_post_userinfo
    @app.plugin(:rodauth) { oauth_jwt_access_tokens true }
    assert_ciba_dpop_userinfo(method: "POST")
  end

  def test_ciba_dpop_plaintext_token_userinfo
    @app.plugin(:rodauth) { oauth_grants_token_hash_column nil }
    assert_ciba_dpop_userinfo(method: "POST")
  end

  def test_ciba_dpop_custom_token_hash_column_userinfo
    @db.alter_table(:oauth_grants) { add_column :token_digest, String, unique: true }
    @app.plugin(:rodauth) { oauth_grants_token_hash_column :token_digest }
    assert_ciba_dpop_userinfo(method: "POST")
  end

  def assert_ciba_dpop_userinfo(method: "GET")
    configure_ciba_dpop
    bearer_id = accept_request
    approve(bearer_id)
    bearer = JSON.parse(poll(bearer_id).body).fetch("access_token")
    unbound = Rack::MockRequest.new(@app).request(method, "https://op.example.test/userinfo", "HTTP_AUTHORIZATION" => "Bearer #{bearer}")
    assert_equal 200, unbound.status, "unbound CIBA bearer: #{unbound.body}"
    id = accept_request
    approve(id)
    issued = poll(id, "HTTP_DPOP" => ciba_dpop_proof)
    assert_equal 200, issued.status, issued.body
    token = JSON.parse(issued.body).fetch("access_token")
    unless auth.send(:oauth_jwt_access_tokens)
      hash_column = auth.send(:oauth_grants_token_hash_column)
      row = @db[:oauth_grants].order(:id).last
      if hash_column
        assert_equal auth.send(:generate_token_hash, token), row.fetch(hash_column)
        refute_equal token, row.fetch(hash_column)
        assert_nil row[:token] if hash_column != :token
      else
        assert_equal token, row.fetch(:token)
      end
    end
    target = "https://op.example.test/userinfo"
    attributes = {htm: method, htu: target, ath: Base64.urlsafe_encode64(Digest::SHA256.digest(token), padding: false)}
    get = lambda do |scheme, proof, access = token|
      Rack::MockRequest.new(@app).request(method, target, "HTTP_AUTHORIZATION" => "#{scheme} #{access}", "HTTP_DPOP" => proof)
    end
    other_key = OpenSSL::PKey::EC.generate("prime256v1")
    [["Bearer", nil], ["DPoP", nil], ["DPoP", "bad"],
      ["DPoP", ciba_dpop_proof(attributes, key: other_key)],
      ["DPoP", ciba_dpop_proof(attributes.merge(htm: method == "GET" ? "POST" : "GET"))],
      ["DPoP", ciba_dpop_proof(attributes.merge(ath: "wrong"))],
      ["DPoP", ciba_dpop_proof(attributes.merge(iat: Time.now.to_i - 3600))]].each do |scheme, proof|
      response = get.call(scheme, proof)
      assert_equal 401, response.status, "rejected #{scheme} proof=#{proof.nil? ? 'absent' : 'present'}: #{response.body}"
    end
    assert_equal 1, @db[:ciba_client_assertions].count # Only the issuance proof.
    proof = ciba_dpop_proof(attributes)
    response = get.call("DPoP", proof)
    assert_equal 200, response.status, "valid proof: #{response.body}"
    assert_equal @account_id.to_s, JSON.parse(response.body).fetch("sub")
    assert_equal 2, @db[:ciba_client_assertions].count
    replay = get.call("DPoP", proof)
    assert_equal 401, replay.status, "replayed proof: #{replay.body}"
    assert_equal 2, @db[:ciba_client_assertions].count
    concurrent_proof = ciba_dpop_proof(attributes)
    concurrent = parallel_decisions { get.call("DPoP", concurrent_proof) }
    assert_equal [200, 401], concurrent.map(&:status).sort
    assert_equal 3, @db[:ciba_client_assertions].count
    if auth.send(:oauth_jwt_access_tokens)
      segments = token.split(".")
      segments[2][0] = segments[2][0] == "A" ? "B" : "A"
      forged = segments.join(".")
      forged_hash = Base64.urlsafe_encode64(Digest::SHA256.digest(forged), padding: false)
      response = get.call("DPoP", ciba_dpop_proof(attributes.merge(ath: forged_hash)), forged)
      assert_equal 401, response.status, "forged JWT: #{response.body}"
    end
    unknown = "ciba_at_not-issued"
    unknown_hash = Base64.urlsafe_encode64(Digest::SHA256.digest(unknown), padding: false)
    response = get.call("DPoP", ciba_dpop_proof(attributes.merge(ath: unknown_hash)), unknown)
    assert_equal 401, response.status, "unknown token with known key: #{response.body}"
    @db[:oauth_grants].update(expires_in: Time.now - 60)
    response = get.call("DPoP", ciba_dpop_proof(attributes))
    assert_equal 401, response.status, "expired token: #{response.body}"
    @db[:oauth_grants].update(expires_in: Time.now + 3600)
    @db[:oauth_grants].update(revoked_at: Time.now)
    response = get.call("DPoP", ciba_dpop_proof(attributes))
    assert_equal 401, response.status, "revoked token: #{response.body}"
    assert_equal 3, @db[:ciba_client_assertions].count
  end
end
