# frozen_string_literal: true
require_relative "ciba_registration_test"
require "minitest/mock"

class CibaIntegrationTest
  def configure_pairwise
    Rodauth::CibaSupport::Schema.add_pairwise_subject(@db) unless @db[:oauth_grants].columns.include?(:ciba_subject)
    (%i[jwks_uri sector_identifier_uri response_types redirect_uri] - @db[:oauth_applications].columns).each do |column|
      @db.alter_table(:oauth_applications) { add_column column, String }
    end
    @db[:oauth_applications].where(id: @client_id).update(subject_type: "pairwise",
      token_endpoint_auth_method: "private_key_jwt", jwks_uri: "https://keys.example.test/jwks",
      response_types: "")
    @app.plugin(:rodauth) do
      enable :oauth_jwt_bearer_grant
      ciba_pairwise_identifier do |account_id, oauth_application:, sector_identifier:|
        scope.env.fetch("test.pairwise_subject") do
          OpenSSL::HMAC.hexdigest("SHA256", "pairwise-test-secret", JSON.generate([sector_identifier, account_id]))
        end
      end
      ciba_pairwise_enabled true
      auth_class_eval do
        # Key transport is separately covered by actual HTTP integration tests.
        def oauth_application_jwks(_application)
          {keys: [JWT::JWK.new(CibaIntegrationTest::KEY.public_key).export]}
        end
      end
    end
  end

  def pairwise_assertion(client = "support", audience: "https://op.example.test")
    {client_id: client, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: JWT.encode({iss: client, sub: client, aud: audience,
        exp: Time.now.to_i + 60, jti: SecureRandom.uuid}, KEY, "RS256", kid: JWT::JWK.new(KEY).kid)}
  end

  def test_pairwise_requires_explicit_application_identifier
    assert_raises(Rodauth::CibaSupport::ConfigurationError) do
      @app.plugin(:rodauth) { ciba_pairwise_enabled true }
    end
  end

  def test_pairwise_requires_explicit_subject_storage_migration
    error = assert_raises(Rodauth::CibaSupport::ConfigurationError) do
      @app.plugin(:rodauth) do
        ciba_pairwise_identifier { |_account, **_| "test-subject" }
        ciba_pairwise_enabled true
      end
    end
    assert_includes error.message, "migrate CIBA token subject storage"
  end

  def test_pairwise_ciba_issuance_preserves_internal_identity_and_sector_stability
    assert_pairwise_ciba_flow
  end

  def test_pairwise_jwt_access_token_userinfo_and_hint
    @app.plugin(:rodauth) { oauth_jwt_access_tokens true }
    assert_pairwise_ciba_flow
  end

  def test_pairwise_management_update_during_opaque_issuance
    assert_pairwise_management_during_issuance
  end

  def test_pairwise_management_update_during_jwt_issuance
    @app.plugin(:rodauth) { oauth_jwt_access_tokens true }
    assert_pairwise_management_during_issuance
  end

  def assert_pairwise_management_during_issuance
    configure_dynamic_registration
    configure_pairwise
    response = post("/backchannel-authentication", pairwise_assertion.merge(scope: "openid",
      login_hint: "customer@example.test"), "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body).fetch("auth_req_id")
    approve(id)
    management_token, credentials = auth.send(:ciba_new_registration_credentials)
    @db[:oauth_applications].where(id: @client_id).update(credentials)
    replacement = registration_params.merge("client_id" => "support", "subject_type" => "pairwise",
      "token_endpoint_auth_method" => "private_key_jwt", "jwks_uri" => "https://new-sector.example.test/jwks")
    update = lambda do
      Rack::MockRequest.new(@app).put("https://op.example.test/register/support",
        "HTTP_AUTHORIZATION" => "Bearer #{management_token}", "CONTENT_TYPE" => "application/json",
        input: JSON.generate(replacement))
    end
    issue = lambda do |env = {}|
      post("/token", pairwise_assertion.merge(grant_type: GRANT, auth_req_id: id),
        {"HTTP_AUTHORIZATION" => nil}.merge(env))
    end
    if @db.database_type == :sqlite
      # SQLite serializes writers; exercise contention without a barrier that
      # would require a second writer to commit while issuance holds the DB.
      issued_response, updated_response = parallel_decisions { |i| i.zero? ? issue.call : update.call }
      if issued_response.status == 503
        assert_equal "temporarily_unavailable", JSON.parse(issued_response.body).fetch("error")
        issued_response = issue.call
      end
      if updated_response.status == 503
        assert_equal "temporarily_unavailable", JSON.parse(updated_response.body).fetch("error")
        updated_response = update.call
      end
    else
      # Force management to commit after issuance captured the client, but
      # before either token is generated. Each HTTP request uses its own DB
      # connection; no sleeps or scheduler-dependent assertion ordering.
      reached, release = Queue.new, Queue.new
      worker = Thread.new do
        issue.call("test.before_issue" => -> { reached << true; Timeout.timeout(10) { release.pop } })
      end
      begin
        Timeout.timeout(10) { reached.pop }
        updated_response = Timeout.timeout(10) { update.call }
        release << true
        issued_response = Timeout.timeout(10) { worker.value }
      ensure
        release << true
        worker.kill if worker.alive?
        worker.join
      end
    end
    assert_equal 200, updated_response.status, updated_response.body
    assert_equal 200, issued_response.status, issued_response.body
    tokens, claims = decode_id_token(issued_response)
    old_subject = OpenSSL::HMAC.hexdigest("SHA256", "pairwise-test-secret", JSON.generate(["keys.example.test", @account_id]))
    new_subject = OpenSSL::HMAC.hexdigest("SHA256", "pairwise-test-secret", JSON.generate(["new-sector.example.test", @account_id]))
    if @db.database_type == :sqlite
      assert_includes [old_subject, new_subject], claims.fetch("sub")
    else
      assert_equal old_subject, claims.fetch("sub")
    end
    assert_equal 1, @db[:oauth_grants].count
    assert_equal claims.fetch("sub"), @db[:oauth_grants].get(:ciba_subject)
    assert_equal "consumed", @db[:ciba_requests].get(:status)
    if auth.send(:oauth_jwt_access_tokens)
      access, = JWT.decode(tokens.fetch("access_token"), KEY.public_key, true,
        algorithms: ["RS256"], verify_iss: true, iss: "https://op.example.test")
      assert_equal claims.fetch("sub"), access.fetch("sub")
    end
    userinfo = Rack::MockRequest.new(@app).get("https://op.example.test/userinfo",
      "HTTP_AUTHORIZATION" => "Bearer #{tokens.fetch('access_token')}")
    assert_equal 200, userinfo.status, userinfo.body
    assert_equal new_subject, JSON.parse(userinfo.body).fetch("sub")
  end

  def assert_pairwise_ciba_flow
    configure_pairwise
    response = post("/backchannel-authentication", pairwise_assertion.merge(scope: "openid",
      login_hint: "customer@example.test"), "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body).fetch("auth_req_id")
    approve(id)
    response = post("/token", pairwise_assertion.merge(grant_type: GRANT, auth_req_id: id), "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, response.status, response.body
    claims, = JWT.decode(JSON.parse(response.body).fetch("id_token"), KEY.public_key, true,
      algorithms: ["RS256"], verify_iss: true, iss: "https://op.example.test", verify_aud: true, aud: "support")
    expected = OpenSSL::HMAC.hexdigest("SHA256", "pairwise-test-secret", JSON.generate(["keys.example.test", @account_id]))
    assert_equal expected, claims.fetch("sub")
    userinfo = Rack::MockRequest.new(@app).get("https://op.example.test/userinfo",
      "HTTP_AUTHORIZATION" => "Bearer #{JSON.parse(response.body).fetch('access_token')}")
    assert_equal 200, userinfo.status, userinfo.body
    assert_equal expected, JSON.parse(userinfo.body).fetch("sub")
    assert_equal @account_id, @db[:ciba_requests].get(:account_id)
    assert_equal @account_id, @db[:ciba_grants].get(:account_id)
    application = @db[:oauth_applications].where(id: @client_id).first
    assert_equal expected, auth.send(:jwt_subject, @account_id, application.merge(client_id: "other"))
    refute_equal expected, auth.send(:jwt_subject, @account_id, application.merge(jwks_uri: "https://other.example.test/jwks"))
    refute_equal expected, auth.send(:jwt_subject, @account_id, application.merge(jwks_uri: "https://keys.example.test:8443/jwks"))
    assert_equal @account_id.to_s, auth.send(:jwt_subject, @account_id, application.merge(subject_type: "public"))
    @app.plugin(:rodauth) do
      resolve_ciba_id_token_subject do |subject, oauth_application:|
        account = db[:accounts].where(email: "customer@example.test").get(:id)
        sector = ciba_pairwise_sector(oauth_application)
        expected = ciba_pairwise_identifier(account, oauth_application: oauth_application, sector_identifier: sector)
        account if subject == expected
      end
      ciba_id_token_hint_enabled true
    end
    hint = JSON.parse(response.body).fetch("id_token")
    begun = post("/backchannel-authentication", pairwise_assertion.merge(scope: "openid", id_token_hint: hint),
      "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, begun.status, begun.body
    row = @db[:ciba_requests].order(:id).last
    assert_equal @account_id, row[:account_id]
    assert_nil row[:grant_id]
  end

  def test_pairwise_dynamic_registration_reuses_same_eligibility_boundary
    configure_dynamic_registration
    configure_pairwise
    params = registration_params.merge("subject_type" => "pairwise", "token_endpoint_auth_method" => "private_key_jwt",
      "jwks_uri" => "https://keys.example.test/jwks")
    response = register(params)
    assert_equal 201, response.status, response.body
    assert_equal "pairwise", JSON.parse(response.body).fetch("subject_type")
    assert_error register(params.merge("jwks_uri" => nil)), "invalid_client_metadata"
    assert_error register(params.merge("token_endpoint_auth_method" => "client_secret_basic")), "invalid_client_metadata"
  end

  def test_pairwise_signed_request_does_not_waive_client_authentication_policy
    configure_dynamic_registration
    configure_pairwise
    Rodauth::CibaSupport::Schema.add_signed_requests(@db)
    @app.plugin(:rodauth) { ciba_request_signing_algorithms ["RS256"] }
    params = registration_params.merge("subject_type" => "public",
      "token_endpoint_auth_method" => "client_secret_basic",
      "jwks_uri" => "https://keys.example.test/jwks",
      "backchannel_authentication_request_signing_alg" => "RS256")
    response = register(params)
    assert_equal 201, response.status, response.body
    before = @db[:oauth_applications].count
    assert_error register(params.merge("subject_type" => "pairwise")), "invalid_client_metadata"
    assert_equal before, @db[:oauth_applications].count
  end

  def test_pairwise_sector_document_requires_keys_and_hybrid_redirects
    configure_pairwise
    application = @db[:oauth_applications].where(id: @client_id).first.merge(
      sector_identifier_uri: "https://sector.example.test/list", response_types: "code",
      redirect_uri: "https://rp.example.test/callback")
    [[], [application[:jwks_uri]], [application[:redirect_uri]], {}, [1]].each do |body|
      response = Struct.new(:code, :body).new("200", JSON.generate(body))
      Rodauth::CibaSupport::HTTP.stub(:request, response) do
        refute auth.send(:ciba_client_eligible?, application)
      end
    end
    response = Struct.new(:code, :body).new("200", JSON.generate([application[:jwks_uri], application[:redirect_uri]]))
    Rodauth::CibaSupport::HTTP.stub(:request, response) do
      assert auth.send(:ciba_client_eligible?, application)
      assert_equal "sector.example.test", auth.send(:ciba_pairwise_sector, application)
    end
    refute auth.send(:ciba_client_eligible?, application.merge(sector_identifier_uri: nil))
    refute auth.send(:ciba_client_eligible?, application.merge(token_endpoint_auth_method: "client_secret_basic"))
  end

  def test_pairwise_opaque_refresh_rotation_and_identifier_failure_rollback
    assert_pairwise_refresh_flow
  end

  def test_pairwise_sector_redirects_revalidate_destinations_and_bound_loops
    configure_pairwise
    response_type = Struct.new(:code, :body, :location) do
      def [](name)
        location if name == "location"
      end
    end
    [301, 302, 303, 307, 308].each do |code|
      calls = []
      transport = lambda do |uri, request, address_allowed:|
        calls << uri.to_s
        assert_nil request["authorization"]
        refute address_allowed.call("127.0.0.1")
        calls.size == 1 ? response_type.new(code.to_s, "", "https://other.example.test/list") : response_type.new("200", "[]")
      end
      Rodauth::CibaSupport::HTTP.stub(:request, transport) do
        assert_equal "200", auth.send(:ciba_pairwise_sector_response, URI("https://sector.example.test/list")).code
      end
      assert_equal ["https://sector.example.test/list", "https://other.example.test/list"], calls
    end
    ["file:///private/key", "https://user:pass@example.test/list", "http://[broken"].each do |location|
      calls = 0
      Rodauth::CibaSupport::HTTP.stub(:request, lambda { |*_, **_| calls += 1; response_type.new("302", "", location) }) do
        assert_raises(Rodauth::CibaSupport::HTTP::Error) do
          auth.send(:ciba_pairwise_sector_response, URI("https://sector.example.test/list"))
        end
      end
      assert_equal 1, calls
    end
    calls = 0
    Rodauth::CibaSupport::HTTP.stub(:request, lambda { |*_, **_| calls += 1; response_type.new("302", "", "/list") }) do
      assert_raises(Rodauth::CibaSupport::HTTP::Error) do
        auth.send(:ciba_pairwise_sector_response, URI("https://sector.example.test/list"))
      end
    end
    assert_equal 21, calls
  end

  def test_pairwise_sector_redirect_deadline_bounds_whole_chain
    configure_pairwise
    response = Net::HTTPFound.new("1.1", "302", "Found")
    response["location"] = "/list"
    calls = 0
    began = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    Rodauth::CibaSupport::HTTP.stub(:request, lambda { |*_, **_| calls += 1; sleep 0.2; response }) do
      assert_raises(Timeout::Error) do
        auth.send(:ciba_pairwise_sector_response, URI("https://sector.example.test/list"))
      end
    end
    assert_operator calls, :<, 20
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - began, :<, 3.5
  end

  def test_pairwise_sector_validation_reuses_success_for_unchanged_client_metadata
    configure_pairwise
    application = @db[:oauth_applications].where(id: @client_id).first.merge(
      sector_identifier_uri: "https://sector.example.test/list")
    requests = 0
    response = Struct.new(:code, :body).new("200", JSON.generate([application[:jwks_uri]]))
    Rodauth::CibaSupport::HTTP.stub(:request, lambda { |*_, **_| requests += 1; response }) do
      assert auth.send(:ciba_client_eligible?, application)
      assert auth.send(:ciba_client_eligible?, application.dup)
      assert_equal 1, requests
      response.code = "503"
      assert auth.send(:ciba_client_eligible?, application)
      refute auth.send(:ciba_pairwise_sector_document_valid?, application, fresh: true)
      refute auth.send(:ciba_client_eligible?, application.merge(client_name: "changed"))
      assert_equal 3, requests
      response.code = "200"
      assert auth.send(:ciba_client_eligible?, application.merge(client_name: "changed"))
      assert_equal 4, requests
    end
  end

  def test_pairwise_sector_cache_is_bounded_and_evicts_old_metadata
    configure_pairwise
    application = @db[:oauth_applications].where(id: @client_id).first.merge(sector_identifier_uri: "https://sector.example.test/list")
    requests = 0
    response = Struct.new(:code, :body).new("200", JSON.generate([application[:jwks_uri]]))
    Rodauth::CibaSupport::HTTP.stub(:request, lambda { |*_, **_| requests += 1; response }) do
      101.times { |index| assert auth.send(:ciba_client_eligible?, application.merge(client_id: "client-#{index}")) }
      assert_equal 101, requests
      assert auth.send(:ciba_client_eligible?, application.merge(client_id: "client-100"))
      assert_equal 101, requests
      assert auth.send(:ciba_client_eligible?, application.merge(client_id: "client-0"))
      assert_equal 102, requests
    end
  end

  def test_pairwise_jwt_refresh_rotation_and_identifier_failure_rollback
    @app.plugin(:rodauth) { oauth_jwt_access_tokens true }
    assert_pairwise_refresh_flow
  end

  def assert_pairwise_refresh_flow
    @app.plugin(:rodauth) { ciba_authentication_claims_by_scope("openid" => %w[auth_time acr amr]) }
    configure_dynamic_registration
    configure_pairwise
    Rodauth::CibaSupport::Schema.create_refresh_tokens(@db)
    @db[:oauth_applications].update(scopes: "openid offline_access", grant_types: "#{GRANT} refresh_token")
    @app.plugin(:rodauth) do
      ciba_refresh_tokens_enabled true
      oauth_application_scopes %w[openid offline_access]
    end
    response = post("/backchannel-authentication", pairwise_assertion.merge(scope: "openid offline_access",
      login_hint: "customer@example.test"), "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body).fetch("auth_req_id")
    approve(id, auth_time: 123, acr: "customer", amr: ["pwd"])
    response = post("/token", pairwise_assertion.merge(grant_type: GRANT, auth_req_id: id), "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, response.status, response.body
    issued = JSON.parse(response.body)
    refresh = issued.fetch("refresh_token")
    original, = JWT.decode(issued.fetch("id_token"), KEY.public_key, true,
      algorithms: ["RS256"], verify_aud: true, aud: "support")
    now = Time.now.to_i
    @db[:ciba_refresh_tokens].update(issued_at: now - 800, expires_at: now + 200)
    renew = lambda do |token, client = "support", env = {}|
      post("/token", pairwise_assertion(client, audience: "https://op.example.test/token").merge(
        grant_type: "refresh_token", refresh_token: token), {"HTTP_AUTHORIZATION" => nil}.merge(env))
    end
    other = @db[:oauth_applications].where(id: @client_id).first.reject { |column, _| column == :id }
    @db[:oauth_applications].insert(other.merge(client_id: "other"))
    assert_error renew.call(refresh, "other"), "invalid_grant"
    [nil, "", "x" * 256, "顧客"].each do |invalid|
      response = renew.call(refresh, "support", "test.pairwise_subject" => invalid, "test.processing_error" => ->(_) {})
      assert_equal 500, response.status, response.body
      assert_equal 1, @db[:oauth_grants].count
      assert_equal 1, @db[:ciba_refresh_tokens].count
      assert_nil @db[:ciba_refresh_tokens].get(:consumed_at)
    end
    response = renew.call(refresh)
    assert_equal 200, response.status, response.body
    renewed = JSON.parse(response.body)
    successor = renewed.fetch("refresh_token")
    refute_equal refresh, successor
    claims, = JWT.decode(renewed.fetch("id_token"), KEY.public_key, true,
      algorithms: ["RS256"], verify_aud: true, aud: "support")
    assert_equal original.fetch("sub"), claims.fetch("sub")
    assert_equal 123, claims.fetch("auth_time")
    assert_equal [@account_id], @db[:oauth_grants].select_map(:account_id).uniq
    response = Rack::MockRequest.new(@app).get("https://op.example.test/userinfo",
      "HTTP_AUTHORIZATION" => "Bearer #{renewed.fetch('access_token')}")
    assert_equal 200, response.status, response.body
    assert_equal original.fetch("sub"), JSON.parse(response.body).fetch("sub")
    response = post("/backchannel-authentication", pairwise_assertion.merge(scope: "openid",
      login_hint: "customer@example.test"), "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, response.status, response.body
    pending_id = JSON.parse(response.body).fetch("auth_req_id")
    pending_row = @db[:ciba_requests].order(:id).last
    assert_nil pending_row[:grant_id]
    management_token, credentials = auth.send(:ciba_new_registration_credentials)
    @db[:oauth_applications].where(id: @client_id).update(credentials)
    replacement = registration_params.merge("client_id" => "support", "subject_type" => "pairwise",
      "token_endpoint_auth_method" => "private_key_jwt", "jwks_uri" => "https://new-sector.example.test/jwks",
      "grant_types" => [GRANT, "refresh_token"], "scope" => "openid offline_access")
    response = Rack::MockRequest.new(@app).put("https://op.example.test/register/support",
      "HTTP_AUTHORIZATION" => "Bearer #{management_token}", "CONTENT_TYPE" => "application/json",
      input: JSON.generate(replacement))
    assert_equal 200, response.status, response.body
    expected = OpenSSL::HMAC.hexdigest("SHA256", "pairwise-test-secret", JSON.generate(["new-sector.example.test", @account_id]))
    response = Rack::MockRequest.new(@app).get("https://op.example.test/userinfo",
      "HTTP_AUTHORIZATION" => "Bearer #{renewed.fetch('access_token')}")
    assert_equal 200, response.status, response.body
    assert_equal expected, JSON.parse(response.body).fetch("sub")
    if auth.send(:oauth_jwt_access_tokens)
      forged, header = JWT.decode(renewed.fetch("access_token"), nil, false)
      assert_equal original.fetch("sub"), @db[:oauth_grants].where(id: forged.fetch("urn:rodauth:ciba:token_id")).get(:ciba_subject)
      forged["sub"] = expected
      wrong_subject = JWT.encode(forged, KEY, "RS256", header)
      response = Rack::MockRequest.new(@app).get("https://op.example.test/userinfo",
        "HTTP_AUTHORIZATION" => "Bearer #{wrong_subject}")
      assert_equal 401, response.status, response.body
    end
    response = renew.call(successor)
    assert_equal 200, response.status, response.body
    changed, = JWT.decode(JSON.parse(response.body).fetch("id_token"), KEY.public_key, true,
      algorithms: ["RS256"], verify_aud: true, aud: "support")
    assert_equal expected, changed.fetch("sub")
    refute_equal original.fetch("sub"), changed.fetch("sub")
    unchanged = @db[:ciba_requests].where(id: pending_row[:id]).first
    assert_equal @account_id, unchanged[:account_id]
    assert_nil unchanged[:grant_id]
    approve(pending_id)
    response = post("/token", pairwise_assertion.merge(grant_type: GRANT, auth_req_id: pending_id), "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, response.status, response.body
    pending_claims, = JWT.decode(JSON.parse(response.body).fetch("id_token"), KEY.public_key, true,
      algorithms: ["RS256"], verify_aud: true, aud: "support")
    assert_equal expected, pending_claims.fetch("sub")
    assert_error renew.call(refresh), "invalid_grant"
    assert_error renew.call(successor), "invalid_grant"
  end
end
