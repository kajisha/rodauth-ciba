# frozen_string_literal: true
require_relative "ciba_resources_test"

class CibaIntegrationTest
  def enable_rar(jwt: false)
    enable_resources(jwt: jwt)
    Rodauth::CibaSupport::Schema.add_authorization_details(@db)
    @db[:oauth_applications].update(authorization_details_types: JSON.generate(["support_data"]))
    @app.plugin(:rodauth) do
      ciba_authorization_details_enabled true
      ciba_authorization_details_types ["support_data"]
      # Test-only type semantics, not a general RAR subset algorithm.
      ciba_validate_authorization_details do |details, oauth_application:|
        details.all? { |detail| (detail.keys - %w[type actions]).empty? &&
          detail["actions"].is_a?(Array) && (detail["actions"] - %w[read delete]).empty? }
      end
      ciba_authorization_details_for_token do |requested:, approved:, narrowing:, resource:, oauth_application:|
        if narrowing && narrowing.any? { |detail| (detail["actions"] - approved.flat_map { |v| v["actions"] }).any? }
          raise Rodauth::CibaSupport::ProtocolError, "invalid_authorization_details"
        end
        approved.filter_map do |detail|
          actions = detail["actions"] & requested.flat_map { |value| value["actions"] }
          actions &= narrowing.flat_map { |value| value["actions"] } if narrowing
          detail.merge("actions" => actions) unless actions.empty?
        end
      end
    end
  end

  def rar_details(actions)
    [{"type" => "support_data", "actions" => actions}]
  end

  def start_rar(approved_actions: ["read"])
    response = post("/backchannel-authentication", scope: "openid read", login_hint: "customer@example.test",
      resource: RESOURCE_A, authorization_details: JSON.generate(rar_details(%w[read delete])))
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body).fetch("auth_req_id")
    grant = auth.create_ciba_grant(account_id: @account_id, oauth_application_id: @client_id, scopes: "openid",
      resources: {RESOURCE_A => "read"}, authorization_details: rar_details(approved_actions))
    auth.backchannel_result(@db[:ciba_requests].order(:id).last[:id],
      grant.merge(authorization_details: JSON.generate(rar_details(%w[read delete]))))
    id
  end

  def test_rar_opaque_issuance_and_introspection_use_only_saved_approval
    enable_rar
    response = resource_poll(start_rar, RESOURCE_A)
    assert_equal 200, response.status, response.body
    payload, identity = decode_id_token(response)
    assert_equal rar_details(["read"]), payload.fetch("authorization_details")
    refute identity.key?("authorization_details")
    data = JSON.parse(post("/introspect", token: payload.fetch("access_token")).body)
    assert_equal rar_details(["read"]), data.fetch("authorization_details")
    metadata = JSON.parse(Rack::MockRequest.new(@app).get("https://op.example.test/.well-known/openid-configuration").body)
    assert_equal ["support_data"], metadata.fetch("authorization_details_types_supported")
  end

  def test_rar_jwt_contains_effective_details_without_id_token_disclosure
    enable_rar(jwt: true)
    response = resource_poll(start_rar, RESOURCE_A)
    assert_equal 200, response.status, response.body
    payload, identity = decode_id_token(response)
    claims, = JWT.decode(payload.fetch("access_token"), KEY.public_key, true, algorithms: ["RS256"])
    assert_equal rar_details(["read"]), claims.fetch("authorization_details")
    refute identity.key?("authorization_details")
  end

  def test_rar_request_shape_client_types_and_resource_are_validated
    enable_rar
    base = {scope: "openid", login_hint: "customer@example.test", resource: RESOURCE_A}
    ["{}", '[{"type":"other"}]', '[{"type":"support_data","actions":"read"}]',
      '[{"type":"support_data","type":"other"}]'].each do |value|
      assert_error post("/backchannel-authentication", base.merge(authorization_details: value)), "invalid_authorization_details"
    end
    details = JSON.generate(rar_details(["read"]))
    assert_error post("/backchannel-authentication", base.reject { |key, _| key == :resource }.merge(authorization_details: details)), "invalid_target"
    @db[:oauth_applications].update(authorization_details_types: "[]")
    assert_error post("/backchannel-authentication", base.merge(authorization_details: details)), "invalid_authorization_details"
    assert_equal 0, @db[:ciba_requests].count
  end

  def test_rar_poll_expansion_policy_failure_and_disabled_state_roll_back
    enable_rar
    id = start_rar
    assert_error post("/token", grant_type: GRANT, auth_req_id: id, resource: RESOURCE_A,
      authorization_details: JSON.generate(rar_details(["delete"]))), "invalid_authorization_details"
    assert_equal "approved", @db[:ciba_requests].get(:status)
    assert_equal 0, @db[:oauth_grants].count
    @app.plugin(:rodauth) do
      ciba_authorization_details_for_token { |**| [{"type" => "unknown"}] }
    end
    assert_error resource_poll(id, RESOURCE_A), "invalid_authorization_details"
    assert_equal "approved", @db[:ciba_requests].get(:status)
    @app.plugin(:rodauth) { ciba_authorization_details_enabled false }
    assert_error resource_poll(id, RESOURCE_A), "invalid_grant"
    assert_equal 0, @db[:oauth_grants].count
  end

  def test_rar_requires_policy_and_refuses_disabled_consent
    assert_raises(ArgumentError) do
      auth.create_ciba_grant(account_id: @account_id, oauth_application_id: @client_id,
        scopes: "openid", authorization_details: rar_details(["read"]))
    end
    enable_resources
    assert_raises(Rodauth::CibaSupport::ConfigurationError) do
      @app.plugin(:rodauth) do
        ciba_authorization_details_enabled true
        ciba_authorization_details_types ["support_data"]
      end
    end
  end

  def test_disabling_rar_cannot_drop_new_consent_from_a_legacy_request
    id = accept_request
    request_id = @db[:ciba_requests].get(:id)
    enable_rar
    grant = auth.create_ciba_grant(account_id: @account_id, oauth_application_id: @client_id,
      scopes: "openid", authorization_details: rar_details(["read"]))
    auth.backchannel_result(request_id, grant)
    assert_nil @db[:ciba_requests].get(:requested_authorization_details)
    @app.plugin(:rodauth) { ciba_authorization_details_enabled false }
    assert_error poll(id), "invalid_grant"
    assert_equal "approved", @db[:ciba_requests].get(:status)
    assert_equal 0, @db[:oauth_grants].count
  end

  def test_disabling_claims_or_resources_preserves_new_consent_on_legacy_requests
    [:claims, :resources].each do |capability|
      id = accept_request
      request_id = @db[:ciba_requests].order(:id).last[:id]
      if capability == :claims
        Rodauth::CibaSupport::Schema.add_claims(@db)
        @app.plugin(:rodauth) { ciba_claims_enabled true }
        options = {rejected_claims: ["email"]}
      else
        enable_resources
        options = {resources: {RESOURCE_A => "read"}}
      end
      grant = auth.create_ciba_grant(account_id: @account_id, oauth_application_id: @client_id,
        scopes: "openid", **options)
      auth.backchannel_result(request_id, grant)
      @app.plugin(:rodauth) { ciba_claims_enabled false; ciba_resources_enabled false }
      assert_error poll(id), "invalid_grant"
      assert_equal "approved", auth.ciba_request(request_id)[:status]
      assert_equal 0, @db[:oauth_grants].count
    end
  end

  def test_rar_rechecks_client_policy_after_issue_hook_and_omits_empty_permission
    enable_rar
    id = start_rar
    assert_error resource_poll(id, RESOURCE_A,
      "test.before_issue" => -> { @db[:oauth_applications].update(authorization_details_types: "[]") }), "invalid_authorization_details"
    assert_equal "approved", @db[:ciba_requests].get(:status)
    assert_equal 0, @db[:oauth_grants].count
    # The failed hook transaction restores the original client registration.
    @db[:ciba_grants].update(authorization_details: "[]")
    response = resource_poll(id, RESOURCE_A)
    assert_equal 200, response.status, response.body
    refute JSON.parse(response.body).key?("authorization_details")
    assert_nil @db[:oauth_grants].get(:ciba_authorization_details)
  end

  def concurrently_run_rar(*operations)
    arrived, release = Queue.new, Queue.new
    workers = operations.map do |operation|
      Thread.new do
        @db.synchronize do |connection|
          arrived << connection.object_id
          Timeout.timeout(10) { release.pop }
          operation.call
        end
      end
    end
    begin
      connections = Timeout.timeout(10) { operations.size.times.map { arrived.pop } }
      assert_equal operations.size, connections.uniq.size
      operations.size.times { release << true }
      workers.map { |worker| Timeout.timeout(10) { worker.value } }
    ensure
      workers.each { |worker| worker.kill if worker.alive? }
      workers.each(&:join)
    end
  end

  def test_concurrent_rar_poll_narrowing_never_combines_permissions
    enable_rar
    3.times do
      id = start_rar(approved_actions: %w[read delete])
      consent_id = @db[:ciba_requests].order(:id).last[:grant_id]
      results = concurrently_run_rar(*%w[read delete].map do |action|
        -> { post("/token", grant_type: GRANT, auth_req_id: id, resource: RESOURCE_A,
          authorization_details: JSON.generate(rar_details([action]))) }
      end)
      assert_equal [200, 400], results.map(&:status).sort
      winner = results.index { |response| response.status == 200 }
      payload, = decode_id_token(results[winner])
      expected = rar_details([%w[read delete][winner]])
      assert_equal expected, payload.fetch("authorization_details")
      assert_error results[1 - winner], "invalid_grant"
      tokens = @db[:oauth_grants].where(ciba_grant_id: consent_id).all
      assert_equal 1, tokens.size
      assert_equal expected, JSON.parse(tokens.first.fetch(:ciba_authorization_details))
      refute_nil tokens.first[:revoked_at]
      assert_equal false, JSON.parse(post("/introspect", token: payload.fetch("access_token")).body).fetch("active")
    end
  end

  def test_concurrent_rar_revocation_leaves_no_active_token_or_details
    enable_rar
    3.times do
      id = start_rar
      consent_id = @db[:ciba_requests].order(:id).last[:grant_id]
      response, result = concurrently_run_rar(
        -> { resource_poll(id, RESOURCE_A) },
        -> { auth.revoke_ciba_grant(consent_id) }
      )
      assert_equal :revoked, result
      assert_includes [200, 400], response.status
      if response.status == 200
        payload, = decode_id_token(response)
        assert_equal rar_details(["read"]), payload.fetch("authorization_details")
        data = JSON.parse(post("/introspect", token: payload.fetch("access_token")).body)
        assert_equal false, data.fetch("active")
        refute data.key?("authorization_details")
      else
        assert_error response, "invalid_grant"
      end
      assert_equal 0, @db[:oauth_grants].where(ciba_grant_id: consent_id, revoked_at: nil).count
      refute_nil auth.ciba_grant(consent_id)[:revoked_at]
    end
  end
end
