# frozen_string_literal: true
require_relative "ciba_registration_test"

class CibaIntegrationTest
  def configure_mtls_registration
    configure_dynamic_registration
    @db.alter_table(:oauth_grants) { add_column :certificate_thumbprint, String }
    @app.plugin(:rodauth) do
      enable :oauth_tls_client_auth
      ciba_tls_client_certificate { scope.env["test.tls_certificate"] }
    end
  end

  def test_ciba_registration_ignores_disabled_mtls_metadata
    configure_dynamic_registration
    response = register(registration_params.merge("tls_client_certificate_bound_access_tokens" => "true", "tls_client_auth_subject_dn" => "CN=client"))
    assert_equal 201, response.status, response.body
    data = JSON.parse(response.body)
    refute data.key?("tls_client_certificate_bound_access_tokens")
    refute data.key?("tls_client_auth_subject_dn")
  end

  def test_ciba_mtls_registration_self_signed_client_issues_bound_token
    configure_mtls_registration
    @db.alter_table(:oauth_applications) do
      add_column :jwks, String, text: true
      add_column :tls_client_certificate_bound_access_tokens, TrueClass
    end
    key = OpenSSL::PKey::RSA.generate(2048)
    certificate = OpenSSL::X509::Certificate.new
    certificate.version = 2
    certificate.serial = 1
    certificate.subject = certificate.issuer = OpenSSL::X509::Name.parse("/CN=registered")
    certificate.public_key = key.public_key
    certificate.not_before = Time.now - 60
    certificate.not_after = Time.now + 3600
    certificate.sign(key, OpenSSL::Digest.new("SHA256"))
    jwk = JWT::JWK.new(key.public_key).export.merge(x5c: [Base64.strict_encode64(certificate.to_der)])
    parameters = registration_params.merge("token_endpoint_auth_method" => "self_signed_tls_client_auth",
      "jwks" => {"keys" => [jwk]}, "tls_client_certificate_bound_access_tokens" => true)
    response = register(parameters)
    assert_equal 201, response.status, response.body
    client = JSON.parse(response.body)
    credentials = {"HTTP_AUTHORIZATION" => nil, "test.tls_certificate" => certificate}
    start = lambda do
      response = post("/backchannel-authentication", {client_id: client.fetch("client_id"), scope: "openid", login_hint: "customer@example.test"}, credentials)
      assert_equal 200, response.status, response.body
      id = JSON.parse(response.body).fetch("auth_req_id")
      approve(id)
      result = post("/token", {client_id: client.fetch("client_id"), grant_type: GRANT, auth_req_id: id}, credentials)
      assert_equal 200, result.status, result.body
      JSON.parse(result.body).fetch("access_token")
    end
    original = start.call
    expected = Base64.urlsafe_encode64(Digest::SHA256.digest(certificate.to_der), padding: false)
    assert_equal expected, @db[:oauth_grants].order(:id).last.fetch(:certificate_thumbprint)
    parameters.delete("tls_client_certificate_bound_access_tokens")
    updated = Rack::MockRequest.new(@app).put(client.fetch("registration_client_uri"),
      "HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}", "CONTENT_TYPE" => "application/json",
      input: JSON.generate(parameters.merge("client_id" => client.fetch("client_id"))))
    assert_equal 200, updated.status, updated.body
    assert_equal false, JSON.parse(updated.body).fetch("tls_client_certificate_bound_access_tokens")
    later = start.call
    assert_nil @db[:oauth_grants].order(:id).last[:certificate_thumbprint]
    userinfo = ->(token) { Rack::MockRequest.new(@app).get("https://op.example.test/userinfo", "HTTP_AUTHORIZATION" => "Bearer #{token}") }
    assert_equal 401, userinfo.call(original).status
    assert_equal 200, userinfo.call(later).status
  end

  def test_ciba_mtls_registration_validates_subject_binding_and_storage
    configure_mtls_registration
    flag = "tls_client_certificate_bound_access_tokens"
    assert_error register(registration_params.merge(flag => true)), "invalid_client_metadata"
    @db.alter_table(:oauth_applications) do
      add_column :tls_client_certificate_bound_access_tokens, TrueClass
      add_column :tls_client_auth_subject_dn, String
      add_column :tls_client_auth_san_dns, String
    end
    ["true", "false", 1, 0, [], {}].each do |value|
      assert_error register(registration_params.merge(flag => value)), "invalid_client_metadata"
    end
    pki = registration_params.merge("token_endpoint_auth_method" => "tls_client_auth")
    [{}, {"tls_client_auth_subject_dn" => 1}, {"tls_client_auth_subject_dn" => ""},
      {"tls_client_auth_subject_dn" => "CN=client", "tls_client_auth_san_dns" => "client.example"}].each do |extra|
      assert_error register(pki.merge(extra)), "invalid_client_metadata"
    end
    assert_equal 1, @db[:oauth_applications].count
    response = register(pki.merge("tls_client_auth_subject_dn" => "CN=client", flag => true))
    assert_equal 201, response.status, response.body
    client = JSON.parse(response.body)
    saved = @db[:oauth_applications].where(client_id: client.fetch("client_id")).first
    assert_equal true, saved.fetch(:tls_client_certificate_bound_access_tokens)
    assert_equal "CN=client", saved.fetch(:tls_client_auth_subject_dn)
    headers = {"HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}", "CONTENT_TYPE" => "application/json"}
    replacement = pki.merge("client_id" => client.fetch("client_id"), "tls_client_auth_subject_dn" => "CN=client")
    bad = Rack::MockRequest.new(@app).put(client.fetch("registration_client_uri"), headers.merge(
      input: JSON.generate(replacement.merge(flag => "false"))))
    assert_error bad, "invalid_client_metadata"
    assert_equal saved, @db[:oauth_applications].where(id: saved[:id]).first
    assert_equal 200, Rack::MockRequest.new(@app).get(client.fetch("registration_client_uri"), headers).status
    updated = Rack::MockRequest.new(@app).put(client.fetch("registration_client_uri"), headers.merge(input: JSON.generate(replacement)))
    assert_equal 200, updated.status, updated.body
    assert_equal false, JSON.parse(updated.body).fetch(flag)
    assert_equal false, @db[:oauth_applications].where(id: saved[:id]).get(:tls_client_certificate_bound_access_tokens)
    omitted = register(registration_params.merge("tls_client_auth_subject_dn" => "CN=ignored"))
    assert_equal 201, omitted.status, omitted.body
    refute JSON.parse(omitted.body).key?("tls_client_auth_subject_dn")
    assert_equal false, JSON.parse(omitted.body).fetch(flag)
    assert_error register(registration_params.merge("token_endpoint_auth_method" => "self_signed_tls_client_auth")), "invalid_client_metadata"
    @db.alter_table(:oauth_grants) { add_column :dpop_jkt, String }
    @db.alter_table(:oauth_applications) { add_column :dpop_bound_access_tokens, TrueClass }
    @app.plugin(:rodauth) { enable :oauth_dpop }
    assert_error register(pki.merge("tls_client_auth_subject_dn" => "CN=client", flag => true,
      "dpop_bound_access_tokens" => true)), "invalid_client_metadata"
  end
end
