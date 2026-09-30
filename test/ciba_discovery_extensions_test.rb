# frozen_string_literal: true
require_relative "test_helper"

class CibaIntegrationTest
  def test_ciba_discovery_reports_mtls_binding_capability_independently_of_global_policy
    absent = ciba_discovery_document("/.well-known/openid-configuration")
    refute absent.key?("tls_client_certificate_bound_access_tokens")
    @db.alter_table(:oauth_grants) { add_column :certificate_thumbprint, String }
    @app.plugin(:rodauth) do
      enable :oauth_tls_client_auth
      ciba_tls_client_certificate { nil }
      oauth_tls_client_certificate_bound_access_tokens false
    end
    %w[/.well-known/openid-configuration /.well-known/oauth-authorization-server].each do |path|
      data = ciba_discovery_document(path)
      assert_equal true, data["tls_client_certificate_bound_access_tokens"]
    end
  end

  def ciba_discovery_document(path)
    response = Rack::MockRequest.new(@app).get("https://op.example.test#{path}")
    assert_equal 200, response.status, response.body
    JSON.parse(response.body)
  end

  def test_ciba_discovery_omits_disabled_introspection_and_dpop
    data = ciba_discovery_document("/.well-known/openid-configuration")
    %w[introspection_endpoint introspection_endpoint_auth_methods_supported
      introspection_endpoint_auth_signing_alg_values_supported dpop_signing_alg_values_supported].each do |key|
      refute data.key?(key), key
    end
  end

  def test_ciba_discovery_retains_introspection_configuration
    @app.plugin(:rodauth) do
      enable :oauth_token_introspection
      introspect_route "token-status"
    end
    oauth = ciba_discovery_document("/.well-known/oauth-authorization-server")
    oidc = ciba_discovery_document("/.well-known/openid-configuration")
    assert_equal "https://op.example.test/token-status", oidc.fetch("introspection_endpoint")
    assert_equal oauth.fetch("introspection_endpoint_auth_methods_supported"), oidc.fetch("introspection_endpoint_auth_methods_supported")
    refute oidc.key?("introspection_endpoint_auth_signing_alg_values_supported")
    # The discovered route is real and still authenticates the caller.
    assert_equal 401, Rack::MockRequest.new(@app).post(oidc.fetch("introspection_endpoint"), params: {token: "unknown"}).status
    response = post("/token-status", token: "unknown")
    assert_equal 200, response.status
    assert_equal({"active" => false}, JSON.parse(response.body))
  end

  def test_ciba_discovery_retains_configured_dpop_algorithms
    @db.alter_table(:oauth_grants) { add_column :dpop_jkt, String }
    @app.plugin(:rodauth) do
      enable :oauth_dpop
      oauth_dpop_signing_alg_values_supported ["ES256"]
    end
    oauth = ciba_discovery_document("/.well-known/oauth-authorization-server")
    oidc = ciba_discovery_document("/.well-known/openid-configuration")
    assert_equal ["ES256"], oidc.fetch("dpop_signing_alg_values_supported")
    assert_equal oauth.fetch("dpop_signing_alg_values_supported"), oidc.fetch("dpop_signing_alg_values_supported")
    refute oidc.key?("introspection_endpoint")
  end
end
