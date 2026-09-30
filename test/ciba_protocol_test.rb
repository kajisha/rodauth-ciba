# frozen_string_literal: true
require_relative "test_helper"

class CibaIntegrationTest
  def request_ciba(overrides = {}, env = {})
    post("/backchannel-authentication", {login_hint: "customer@example.test", scope: "openid"}.merge(overrides), env)
  end

  def test_discovery_describes_poll_and_keeps_existing_oidc_metadata
    response = Rack::MockRequest.new(@app).get("https://op.example.test/.well-known/openid-configuration")
    assert_equal 200, response.status
    metadata = JSON.parse(response.body)
    assert_equal "https://op.example.test/backchannel-authentication", metadata["backchannel_authentication_endpoint"]
    assert_equal ["poll"], metadata["backchannel_token_delivery_modes_supported"]
    assert_equal false, metadata["backchannel_user_code_parameter_supported"]
    refute metadata.key?("backchannel_authentication_request_signing_alg_values_supported")
    assert_includes metadata["grant_types_supported"], GRANT
    assert_includes metadata["grant_types_supported"], "authorization_code"
    assert_equal %w[public pairwise], metadata["subject_types_supported"]
  end

  def test_discovered_custom_backchannel_route_accepts_requests
    @app.plugin(:rodauth) { backchannel_authentication_route "custom-ciba" }
    http = Rack::MockRequest.new(@app)
    documents = %w[openid-configuration oauth-authorization-server].map do |name|
      response = http.get("https://op.example.test/.well-known/#{name}")
      assert_equal 200, response.status
      JSON.parse(response.body)
    end
    documents.each do |metadata|
      assert_equal "https://op.example.test/custom-ciba", metadata.fetch("backchannel_authentication_endpoint")
      assert_equal ["poll"], metadata.fetch("backchannel_token_delivery_modes_supported")
      assert_includes metadata.fetch("grant_types_supported"), GRANT
    end
    response = http.post(documents.first.fetch("backchannel_authentication_endpoint"),
      "HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64('support:test-secret')}",
      params: {scope: "openid", login_hint: "customer@example.test"})
    assert_equal 200, response.status, response.body
    assert_equal 1, @db[:ciba_requests].count
  end

  def test_request_validation_and_unknown_parameters
    [nil, "", [], {"x" => "y"}].each do |hint|
      assert_error request_ciba(login_hint: hint), "invalid_request"
    end
    %w[id_token_hint login_hint_token request user_code].each do |name|
      assert_error request_ciba(name => "unsupported"), "invalid_request"
    end
    assert_error request_ciba(login_hint: "unknown"), "unknown_user_id"
    assert_error request_ciba(scope: "profile"), "invalid_scope"
    assert_error request_ciba(scope: "openid secret"), "invalid_scope"
    assert_equal 200, request_ciba("future_parameter" => "ignored").status
  end

  def test_login_hint_is_application_defined_and_unknown_fields_cannot_set_state
    account_id = @account_id
    @app.plugin(:rodauth) do
      resolve_ciba_login_hint do |hint, oauth_application:|
        hint == "customer-reference-42" && oauth_application[:client_id] == "support" ? account_id : nil
      end
    end
    delivered = []
    response = request_ciba({login_hint: "customer-reference-42", binding_message: "A7B9",
      acr_values: "urn:preferred urn:fallback", "future_parameter" => "private-unused-value",
      "account_id" => "another-user", "status" => "approved", "expires_at" => "9999999999"},
      "test.device" => ->(snapshot, _) { delivered << snapshot })
    assert_equal 200, response.status, response.body
    row = @db[:ciba_requests].first
    assert_equal @account_id, row[:account_id]
    assert_equal "pending", row[:status]
    assert_equal "urn:preferred urn:fallback", delivered.first[:acr_values]
    assert_equal "A7B9", delivered.first[:binding_message]
    refute_includes JSON.generate(delivered), "private-unused-value"
    assert_operator row[:expires_at], :<, 9_999_999_999
    id = JSON.parse(response.body).fetch("auth_req_id")
    assert_error poll(id), "authorization_pending"
    approve(id, acr: "urn:actually-achieved")
    _, claims = decode_id_token(poll(id))
    assert_equal "urn:actually-achieved", claims.fetch("acr")
  end

  def test_expiry_binding_context_and_offline_access
    response = request_ciba(requested_expiry: "900", binding_message: "W4SCT", acr_values: "urn:first urn:second", scope: "openid offline_access")
    assert_equal 200, response.status
    assert_equal 600, JSON.parse(response.body)["expires_in"]
    row = @db[:ciba_requests].first
    assert_equal "openid", row[:scopes]
    assert_equal "W4SCT", row[:binding_message]
    assert_equal "urn:first urn:second", row[:acr_values]
    %w[0 -1 1.5 abc].each { |value| assert_error request_ciba(requested_expiry: value), "invalid_request" }
    assert_error request_ciba(binding_message: "x" * 129), "invalid_binding_message"
    assert_equal "no-store", response["cache-control"]
    assert_equal "no-cache", response["pragma"]
  end

  def test_post_client_authentication
    @db[:oauth_applications].update(token_endpoint_auth_method: "client_secret_post")
    response = request_ciba({client_id: "support", client_secret: "test-secret"}, "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body).fetch("auth_req_id")
    approve(id)
    token = post("/token", {grant_type: GRANT, auth_req_id: id, client_id: "support", client_secret: "test-secret"}, "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, token.status, token.body
  end

  def test_duplicate_parameters_are_rejected
    response = post("/backchannel-authentication", {}, input: "login_hint=a&login_hint=b&scope=openid", "CONTENT_TYPE" => "application/x-www-form-urlencoded")
    assert_error response, "invalid_request"
  end

  def test_non_tls_and_json_requests_are_rejected
    response = Rack::MockRequest.new(@app).post("http://op.example.test/backchannel-authentication", params: {scope: "openid", login_hint: "customer@example.test"})
    assert_error response, "invalid_request"
    response = request_ciba({}, "CONTENT_TYPE" => "application/json", input: '{"scope":"openid","login_hint":"customer@example.test"}')
    assert_error response, "invalid_request"
  end

  def test_ciba_endpoints_require_tls_post_and_form_before_state_changes
    id = accept_request
    approve(id)
    original = @db[:ciba_requests].first
    credentials = {"HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64('support:test-secret')}"}
    http = Rack::MockRequest.new(@app)
    {
      "/backchannel-authentication" => {scope: "openid", login_hint: "customer@example.test"},
      "/token" => {grant_type: GRANT, auth_req_id: id}
    }.each do |path, params|
      assert_error http.post("http://op.example.test#{path}", credentials.merge(params: params)), "invalid_request"
      rejected = http.post("https://op.example.test#{path}", credentials.merge(
        "CONTENT_TYPE" => "application/json", input: JSON.generate(params)))
      assert_error rejected, "invalid_request"
      get = http.get("https://op.example.test#{path}?#{URI.encode_www_form(params)}", credentials)
      if path == "/token"
        assert_error get, "invalid_request"
      else
        assert_equal 404, get.status, get.body
      end
    end
    assert_equal original, @db[:ciba_requests].first
    assert_equal 1, @db[:ciba_requests].count
    assert_equal 0, @db[:oauth_grants].count
  end

  def test_approval_is_idempotent_and_context_conflicts_are_rejected
    id = accept_request
    row = @db[:ciba_requests].first
    args = {account_id: @account_id, auth_time: Time.now.to_i - 30, amr: %w[pwd otp]}
    assert_equal :approved, auth.approve_ciba_request(row[:id], **args)
    saved = @db[:ciba_requests].first
    assert_equal :already_completed, auth.approve_ciba_request(row[:id], **args.merge(amr: %w[otp pwd]))
    assert_equal saved, @db[:ciba_requests].first
    assert_raises(Rodauth::CibaSupport::Conflict) { auth.approve_ciba_request(row[:id], **args.merge(acr: "different")) }
    assert_raises(Rodauth::CibaSupport::Conflict) { auth.deny_ciba_request(row[:id], account_id: @account_id) }
    assert_equal 200, poll(id).status
    assert_equal :already_completed, auth.approve_ciba_request(row[:id], **args)
  end

  def test_denial_and_expired_completion
    id = accept_request
    row = @db[:ciba_requests].first
    assert_equal :denied, auth.deny_ciba_request(row[:id], account_id: @account_id)
    assert_equal :already_completed, auth.deny_ciba_request(row[:id], account_id: @account_id)
    assert_error poll(id), "access_denied"
    @db[:ciba_requests].update(expires_at: Time.now.to_i)
    assert_raises(Rodauth::CibaSupport::Expired) { auth.deny_ciba_request(row[:id], account_id: @account_id) }
  end

  def test_request_lookup_recovery_and_cleanup
    id = accept_request
    row = @db[:ciba_requests].first
    snapshot = auth.ciba_request(row[:id])
    assert snapshot.frozen?
    assert snapshot[:scopes].frozen?
    refute snapshot.key?(:auth_req_id_digest)
    assert_equal [row[:id]], auth.pending_ciba_requests.map { |r| r[:id] }
    assert_empty auth.pending_ciba_requests(after_id: row[:id])
    assert_equal 0, auth.cleanup_ciba_requests(before: Time.now.to_i)
    approve(id)
    assert_equal 200, poll(id).status
    @db[:ciba_requests].update(consumed_at: Time.now.to_i - 20)
    assert_equal 1, auth.cleanup_ciba_requests(before: Time.now.to_i - 1)
    assert_equal 1, @db[:oauth_grants].count
    assert_raises(Rodauth::CibaSupport::NotFound) { auth.ciba_request(row[:id]) }
    assert_raises(ArgumentError) { auth.cleanup_ciba_requests(before: Time.now.to_i + 60) }
  end

  def test_request_callbacks_after_commit_and_observer_secrets
    events, delivered = [], []
    @db.transaction(mode: :immediate) do
      response = request_ciba({}, "test.observe" => ->(e) { events << e }, "test.accepted" => ->(r) { delivered << r; raise "delivery failure" })
      assert_equal 200, response.status
      assert_empty events
      assert_empty delivered
    end
    assert_equal 1, delivered.length
    assert_equal "request_accepted", events.first[:type]
    assert_equal 1, events.first[:version]
    %w[auth_req_id_digest login_hint access_token client_secret binding_message].each do |key|
      refute events.first.key?(key.to_sym)
    end
  end
end

class CibaIntegrationTest
  def test_basic_credentials_are_form_decoded_and_hashed_secrets_work
    client = "support:encoded"
    secret = "secret + %"
    @db[:oauth_applications].update(client_id: client, client_secret: BCrypt::Password.create(secret, cost: 4).to_s)
    @app.plugin(:rodauth) { oauth_applications_client_secret_hash_column :client_secret }
    credentials = "#{URI.encode_www_form_component(client)}:#{URI.encode_www_form_component(secret)}"
    env = {"HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64(credentials)}"}
    response = request_ciba({}, env)
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body)["auth_req_id"]
    approve(id)
    assert_equal 200, poll(id, env).status
    rejected = request_ciba({}, "HTTP_AUTHORIZATION" => "Basic !!!")
    assert_equal 401, rejected.status
    assert_match(/\ABasic/, rejected["www-authenticate"])
  end

  def test_two_authentication_methods_are_rejected
    assert_error request_ciba(client_id: "support", client_secret: "test-secret"), "invalid_request"
  end
end

class CibaIntegrationTest
  def test_rack_inputs_without_rewind_work_on_both_endpoints
    body_class = Class.new do
      def initialize(body)
        @io = StringIO.new(body)
      end
      def read(*args)
        @io.read(*args)
      end
    end
    headers = {"HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64('support:test-secret')}", "CONTENT_TYPE" => "application/x-www-form-urlencoded"}
    http = Rack::MockRequest.new(@app)
    response = http.post("https://op.example.test/backchannel-authentication", headers.merge("rack.input" => body_class.new("scope=openid&login_hint=customer%40example.test")))
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body)["auth_req_id"]
    approve(id)
    response = http.post("https://op.example.test/token", headers.merge("rack.input" => body_class.new(URI.encode_www_form(grant_type: GRANT, auth_req_id: id))))
    assert_equal 200, response.status, response.body
  end
end
