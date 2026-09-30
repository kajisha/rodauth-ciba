# frozen_string_literal: true
require_relative "test_helper"

class CibaIntegrationTest
  RESOURCE_A = "https://api.example.test/a"
  RESOURCE_B = "https://api.example.test/b"

  def enable_resources(jwt: false)
    Rodauth::CibaSupport::Schema.add_resources(@db)
    @resources = {
      RESOURCE_A => {scopes: %w[read write openid], audience: RESOURCE_A},
      RESOURCE_B => {scopes: %w[read write], audience: "service-b"}
    }
    registry = @resources
    @app.plugin(:rodauth) do
      enable :oauth_token_introspection
      ciba_resources_enabled true
      ciba_resource_servers registry
      oauth_application_scopes %w[openid read write]
      oauth_jwt_access_tokens jwt
    end
    @db[:oauth_applications].update(scopes: "openid read write")
  end

  def resource_post(path, pairs, env = {})
    post(path, {}, {input: URI.encode_www_form(pairs), "CONTENT_TYPE" => "application/x-www-form-urlencoded"}.merge(env))
  end

  def resource_request(targets = [RESOURCE_A, RESOURCE_B], consent: {RESOURCE_A => "read", RESOURCE_B => "write"})
    response = resource_post("/backchannel-authentication",
      [["scope", "openid read write"], ["login_hint", "customer@example.test"]] + targets.map { |v| ["resource", v] })
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body).fetch("auth_req_id")
    grant = auth.create_ciba_grant(account_id: @account_id, oauth_application_id: @client_id,
      scopes: "openid", resources: consent)
    auth.backchannel_result(@db[:ciba_requests].order(:id).last[:id],
      grant.merge(resources: JSON.generate(RESOURCE_A => "read write")))
    id
  end

  def resource_poll(id, resource, env = {})
    post("/token", {grant_type: GRANT, auth_req_id: id, resource: resource}, env)
  end

  def test_resource_scope_and_audience_match_reference_and_id_token_keeps_oidc_context
    enable_resources(jwt: true)
    id = resource_request
    result = resource_poll(id, RESOURCE_A)
    assert_equal 200, result.status, result.body
    payload, identity = decode_id_token(result)
    claims, = JWT.decode(payload.fetch("access_token"), KEY.public_key, true,
      algorithms: ["RS256"], verify_aud: true, aud: RESOURCE_A)
    assert_equal "read", claims.fetch("scope")
    assert_equal "read", payload.fetch("scope")
    assert_equal "support", identity.fetch("aud")
    refute identity.key?("urn:rodauth:ciba:resource")
    assert_equal "read", @db[:oauth_grants].get(:scopes)
    assert_equal RESOURCE_A, @db[:oauth_grants].get(:ciba_resource_audience)
    @app.plugin(:rodauth) { ciba_resources_enabled false }
    response = Rack::MockRequest.new(@app).get("https://op.example.test/userinfo",
      "HTTP_AUTHORIZATION" => "Bearer #{payload.fetch('access_token')}")
    assert_equal 401, response.status
  end

  def test_opaque_resource_introspection_and_userinfo_isolation
    enable_resources
    id = resource_request(consent: {RESOURCE_A => "openid read"})
    result = resource_poll(id, RESOURCE_A)
    assert_equal 200, result.status, result.body
    payload, = decode_id_token(result)
    token = payload.fetch("access_token")
    info = post("/introspect", token: token)
    assert_equal 200, info.status, info.body
    data = JSON.parse(info.body)
    assert_equal true, data.fetch("active")
    assert_equal RESOURCE_A, data.fetch("aud")
    assert_equal "openid read", data.fetch("scope")
    response = Rack::MockRequest.new(@app).get("https://op.example.test/userinfo",
      "HTTP_AUTHORIZATION" => "Bearer #{token}")
    assert_equal 401, response.status
    auth.revoke_ciba_grant(@db[:ciba_grants].get(:id))
    assert_equal false, JSON.parse(post("/introspect", token: token).body).fetch("active")
  end

  def test_resource_omission_uses_oidc_consent
    enable_resources
    result = poll(resource_request)
    assert_equal 200, result.status, result.body
    payload, = decode_id_token(result)
    assert_equal "openid", payload.fetch("scope")
    assert_nil @db[:oauth_grants].get(:ciba_resource)
  end

  def test_resource_jwt_introspection_matches_reference_unsupported_token_type
    enable_resources(jwt: true)
    [:replay, :revoke, :delete].each do |operation|
      id = resource_request
      response = resource_poll(id, RESOURCE_A)
      assert_equal 200, response.status, response.body
      payload, identity = decode_id_token(response)
      token = payload.fetch("access_token")
      refute identity.key?("urn:rodauth:ciba:token_id")
      assert_error post("/introspect", token: token), "unsupported_token_type"
      row = @db[:oauth_grants].order(:id).last
      case operation
      when :replay then assert_error poll(id), "invalid_grant"
      when :revoke then auth.revoke_ciba_grant(row[:ciba_grant_id])
      when :delete then @db[:oauth_grants].where(id: row[:id]).delete
      end
      assert_error post("/introspect", token: token), "unsupported_token_type"
    end
  end

  def test_resource_jwt_with_openid_scope_cannot_access_userinfo
    enable_resources(jwt: true)
    id = resource_request(consent: {RESOURCE_A => "openid read"})
    response = resource_poll(id, RESOURCE_A)
    assert_equal 200, response.status, response.body
    payload, = decode_id_token(response)
    claims, = JWT.decode(payload.fetch("access_token"), KEY.public_key, true, algorithms: ["RS256"])
    assert_equal "openid read", claims.fetch("scope")
    @app.plugin(:rodauth) { ciba_resources_enabled false }
    userinfo = Rack::MockRequest.new(@app).get("https://op.example.test/userinfo",
      "HTTP_AUTHORIZATION" => "Bearer #{payload.fetch('access_token')}")
    assert_equal 401, userinfo.status
  end

  def test_resource_audience_mapping_and_signing_failure_roll_back
    enable_resources(jwt: true)
    id = resource_request
    failed = resource_poll(id, RESOURCE_B, "test.fail_signing" => true)
    assert_equal 500, failed.status
    assert_equal "approved", @db[:ciba_requests].get(:status)
    assert_equal 0, @db[:oauth_grants].count
    result = resource_poll(id, RESOURCE_B)
    assert_equal 200, result.status, result.body
    payload, identity = decode_id_token(result)
    claims, = JWT.decode(payload.fetch("access_token"), KEY.public_key, true,
      algorithms: ["RS256"], verify_aud: true, aud: "service-b")
    assert_equal "write", claims.fetch("scope")
    assert_equal "support", identity.fetch("aud")
  end

  def test_upstream_resource_feature_cannot_override_ciba_audience
    enable_resources(jwt: true)
    @app.plugin(:rodauth) { enable :oauth_resource_indicators }
    response = resource_poll(resource_request, RESOURCE_B)
    assert_equal 200, response.status, response.body
    payload, = decode_id_token(response)
    claims, = JWT.decode(payload.fetch("access_token"), KEY.public_key, true, algorithms: ["RS256"])
    assert_equal "service-b", claims.fetch("aud")
    info = post("/introspect", token: payload.fetch("access_token"))
    assert_error info, "unsupported_token_type"
    parts = payload.fetch("access_token").split(".")
    parts[2][0] = parts[2][0] == "A" ? "B" : "A"
    invalid = post("/introspect", token: parts.join("."))
    assert_equal 200, invalid.status, invalid.body
    assert_equal false, JSON.parse(invalid.body).fetch("active")
    wrong_issuer = JWT.encode(claims.merge("iss" => "https://other.example.test"), KEY, "RS256", typ: "at+jwt")
    assert_equal false, JSON.parse(post("/introspect", token: wrong_issuer).body).fetch("active")
    userinfo = Rack::MockRequest.new(@app).get("https://op.example.test/userinfo",
      "HTTP_AUTHORIZATION" => "Bearer #{payload.fetch('access_token')}")
    assert_equal 401, userinfo.status
  end

  def test_resource_rejection_rolls_back_consumption_and_never_expands_consent
    enable_resources
    id = resource_request([RESOURCE_A])
    assert_error resource_poll(id, RESOURCE_B), "invalid_target"
    assert_equal "approved", @db[:ciba_requests].get(:status)
    assert_equal 0, @db[:oauth_grants].count
    assert_error resource_post("/token", [["grant_type", GRANT], ["auth_req_id", id],
      ["resource", RESOURCE_A], ["resource", RESOURCE_B]]), "invalid_target"
    response = resource_poll(id, RESOURCE_A,
      "test.before_issue" => -> { @resources[RESOURCE_A][:scopes] = ["write"] })
    assert_equal 200, response.status, response.body
    assert_equal "", JSON.parse(response.body).fetch("scope")
  end

  def test_resource_policy_removed_in_hook_and_disabled_pending_request
    enable_resources
    id = resource_request
    assert_error resource_poll(id, RESOURCE_A,
      "test.before_issue" => -> { @resources.delete(RESOURCE_A) }), "invalid_target"
    assert_equal "approved", @db[:ciba_requests].get(:status)
    @app.plugin(:rodauth) { ciba_resources_enabled false }
    assert_error poll(id), "invalid_grant"
    assert_equal 0, @db[:oauth_grants].count
  end

  def test_resource_validation_and_additive_migration
    legacy = accept_request
    approve(legacy)
    assert_raises(ArgumentError) do
      auth.create_ciba_grant(account_id: @account_id, oauth_application_id: @client_id,
        scopes: "openid", resources: {RESOURCE_A => "read"})
    end
    enable_resources
    assert_nil @db[:ciba_requests].get(:requested_resources)
    assert_nil @db[:ciba_grants].get(:resources)
    assert_equal 200, poll(legacy).status
    ["relative", "#{RESOURCE_A}#fragment", "https://unknown.example.test/", ""].each do |target|
      assert_error post("/backchannel-authentication", scope: "openid", login_hint: "customer@example.test",
        resource: target), "invalid_target"
    end
    assert_error resource_post("/backchannel-authentication", [["scope", "openid"], ["scope", "openid"],
      ["login_hint", "customer@example.test"], ["resource", RESOURCE_A]]), "invalid_request"
    assert_raises(Rodauth::CibaSupport::Ineligible) do
      auth.create_ciba_grant(account_id: @account_id, oauth_application_id: @client_id,
        scopes: "openid", resources: {RESOURCE_A => "admin"})
    end
  end

  def test_resource_omission_policy_selects_only_an_original_target
    enable_resources
    @app.plugin(:rodauth) { ciba_use_granted_resource { |_row| true } }
    single = resource_request([RESOURCE_B])
    response = poll(single)
    assert_equal 200, response.status, response.body
    assert_equal RESOURCE_B, @db[:oauth_grants].order(:id).last[:ciba_resource]
    multiple = resource_request
    assert_error poll(multiple), "invalid_target"
    @app.plugin(:rodauth) do
      ciba_default_resource { |_resources, oauth_application:| RESOURCE_B }
    end
    response = poll(multiple)
    assert_equal 200, response.status, response.body
    assert_equal "write", JSON.parse(response.body).fetch("scope")
    unrequested = resource_request([RESOURCE_A, RESOURCE_B])
    @app.plugin(:rodauth) do
      ciba_default_resource { |_resources, oauth_application:| "https://unrequested.example.test/" }
    end
    assert_error poll(unrequested), "invalid_target"
    assert_equal "approved", @db[:ciba_requests].order(:id).last[:status]
  end

  def test_resource_and_explicit_claim_consent_remain_separate
    enable_resources(jwt: true)
    Rodauth::CibaSupport::Schema.add_claims(@db)
    @app.plugin(:rodauth) do
      ciba_claims_enabled true
      get_oidc_param { |_account, name| name == :email ? "customer@example.test" : true }
    end
    start = post("/backchannel-authentication", scope: "openid read", login_hint: "customer@example.test",
      resource: RESOURCE_A, claims: JSON.generate(id_token: {email: nil, email_verified: nil}))
    assert_equal 200, start.status, start.body
    grant = auth.create_ciba_grant(account_id: @account_id, oauth_application_id: @client_id,
      scopes: "openid", resources: {RESOURCE_A => "read"}, claims: ["email"])
    auth.backchannel_result(@db[:ciba_requests].get(:id), grant)
    response = resource_poll(JSON.parse(start.body).fetch("auth_req_id"), RESOURCE_A)
    assert_equal 200, response.status, response.body
    payload, identity = decode_id_token(response)
    assert_equal "customer@example.test", identity.fetch("email")
    refute identity.key?("email_verified")
    access, = JWT.decode(payload.fetch("access_token"), KEY.public_key, true, algorithms: ["RS256"])
    assert_equal RESOURCE_A, access.fetch("aud")
    assert_equal "read", access.fetch("scope")
    refute access.key?("email")
    assert_equal auth.send(:id_token_hash, payload.fetch("access_token"), "RS256"), identity.fetch("at_hash")
  end

  def test_concurrent_resource_selection_issues_one_audience_and_replay_revokes_it
    enable_resources
    id = resource_request
    arrived, release = Queue.new, Queue.new
    gate = -> { arrived << true; Timeout.timeout(10) { release.pop } }
    workers = [RESOURCE_A, RESOURCE_B].map do |resource|
      Thread.new { resource_poll(id, resource, "test.token_gate" => gate) }
    end
    begin
      Timeout.timeout(10) { 2.times { arrived.pop } }
      2.times { release << true }
      responses = workers.map { |worker| Timeout.timeout(10) { worker.value } }
      assert_equal [200, 400], responses.map(&:status).sort
      assert_error responses.find { |r| r.status == 400 }, "invalid_grant"
      assert_equal 1, @db[:oauth_grants].count
      token = @db[:oauth_grants].first
      expected = token[:ciba_resource] == RESOURCE_A ? "read" : "write"
      assert_equal expected, token[:scopes]
      refute_nil token[:revoked_at]
      refute_nil @db[:ciba_grants].get(:revoked_at)
    ensure
      workers.each { |worker| worker.kill if worker.alive? }
      workers.each(&:join)
    end
  end
end
