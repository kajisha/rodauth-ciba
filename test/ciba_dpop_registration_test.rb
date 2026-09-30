# frozen_string_literal: true
require_relative "ciba_registration_test"
require_relative "ciba_dpop_test"

class CibaIntegrationTest
  def test_registration_ignores_dpop_metadata_when_upstream_disabled
    configure_dynamic_registration
    @db.alter_table(:oauth_applications) { add_column :dpop_bound_access_tokens, TrueClass }
    [true, "true"].each do |value|
      response = register(registration_params.merge("dpop_bound_access_tokens" => value))
      assert_equal 201, response.status, response.body
      client = JSON.parse(response.body)
      refute client.key?("dpop_bound_access_tokens")
      assert_nil @db[:oauth_applications].where(client_id: client.fetch("client_id")).get(:dpop_bound_access_tokens)
    end
  end

  def test_dynamic_dpop_registration_enforces_policy_and_management_replacement
    configure_dynamic_registration
    configure_ciba_dpop
    assert_error register(registration_params.merge("dpop_bound_access_tokens" => true)), "invalid_client_metadata"
    @db.alter_table(:oauth_applications) { add_column :dpop_bound_access_tokens, TrueClass }
    ["true", "false", 0, 1, [], {}].each do |value|
      count = @db[:oauth_applications].count
      assert_error register(registration_params.merge("dpop_bound_access_tokens" => value)), "invalid_client_metadata"
      assert_equal count, @db[:oauth_applications].count
    end
    [{}, {"dpop_bound_access_tokens" => false}].each do |extra|
      response = register(registration_params.merge(extra))
      assert_equal 201, response.status, response.body
      assert_equal false, JSON.parse(response.body).fetch("dpop_bound_access_tokens")
    end
    response = register(registration_params.merge("dpop_bound_access_tokens" => true))
    assert_equal 201, response.status, response.body
    client = JSON.parse(response.body)
    saved = @db[:oauth_applications].where(client_id: client.fetch("client_id")).first
    assert_equal true, saved.fetch(:dpop_bound_access_tokens)
    credentials = {"HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64("#{client.fetch('client_id')}:#{client.fetch('client_secret')}")}"}
    start = lambda do
      response = post("/backchannel-authentication", {scope: "openid", login_hint: "customer@example.test"}, credentials)
      assert_equal 200, response.status, response.body
      id = JSON.parse(response.body).fetch("auth_req_id")
      approve(id)
      {grant_type: GRANT, auth_req_id: id}
    end
    params = start.call
    assert_error post("/token", params, credentials), "invalid_grant"
    response = post("/token", params, credentials.merge("HTTP_DPOP" => ciba_dpop_proof))
    assert_equal 200, response.status, response.body
    issued = JSON.parse(response.body)
    assert_equal "DPoP", issued.fetch("token_type")
    headers = {"HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}", "CONTENT_TYPE" => "application/json"}
    replacement = registration_params.merge("client_id" => client.fetch("client_id"))
    bad = Rack::MockRequest.new(@app).put(client.fetch("registration_client_uri"), headers.merge(
      input: JSON.generate(replacement.merge("dpop_bound_access_tokens" => "false"))))
    assert_error bad, "invalid_client_metadata"
    assert_equal saved, @db[:oauth_applications].where(id: saved.fetch(:id)).first
    read = Rack::MockRequest.new(@app).get(client.fetch("registration_client_uri"), headers)
    assert_equal 200, read.status, read.body
    assert_equal true, JSON.parse(read.body).fetch("dpop_bound_access_tokens")
    updated = Rack::MockRequest.new(@app).put(client.fetch("registration_client_uri"), headers.merge(input: JSON.generate(replacement)))
    assert_equal 200, updated.status, updated.body
    assert_equal false, JSON.parse(updated.body).fetch("dpop_bound_access_tokens")
    assert_equal false, @db[:oauth_applications].where(id: saved.fetch(:id)).get(:dpop_bound_access_tokens)
    response = post("/token", start.call, credentials)
    assert_equal 200, response.status, response.body
    assert_equal "bearer", JSON.parse(response.body).fetch("token_type").downcase
    old = Rack::MockRequest.new(@app).get("https://op.example.test/userinfo",
      "HTTP_AUTHORIZATION" => "Bearer #{issued.fetch('access_token')}")
    assert_equal 401, old.status, old.body # Updating client policy does not unbind an issued token.
  end
end
