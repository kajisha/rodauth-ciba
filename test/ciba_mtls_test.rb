# frozen_string_literal: true
require_relative "test_helper"

class CibaIntegrationTest
  def mtls_certificate(key, serial)
    certificate = OpenSSL::X509::Certificate.new
    certificate.version = 2
    certificate.serial = serial
    certificate.subject = certificate.issuer = OpenSSL::X509::Name.parse("/CN=client")
    certificate.public_key = key.public_key
    certificate.not_before = Time.now - 60
    certificate.not_after = Time.now + 3600
    certificate.sign(key, OpenSSL::Digest.new("SHA256"))
  end

  def test_ciba_mtls_requires_explicit_trust_callback
    @db.alter_table(:oauth_grants) { add_column :certificate_thumbprint, String }
    assert_raises(Rodauth::CibaSupport::ConfigurationError) { @app.plugin(:rodauth) { enable :oauth_tls_client_auth } }
  end

  def test_ciba_mtls_requires_thumbprint_storage
    assert_raises(Rodauth::CibaSupport::ConfigurationError) do
      @app.plugin(:rodauth) do
        enable :oauth_tls_client_auth
        ciba_tls_client_certificate { nil }
      end
    end
  end

  def test_ciba_mtls_rejects_simultaneous_dpop_binding_and_rolls_back
    assert_ciba_mtls_flow("tls_client_auth", false, dpop: true)
  end

  def test_ciba_mtls_global_setting_does_not_force_opaque_client_binding
    assert_ciba_mtls_flow("tls_client_auth", false, global_binding: true)
  end

  def test_ciba_mtls_global_setting_does_not_force_jwt_client_binding
    assert_ciba_mtls_flow("tls_client_auth", true, global_binding: true)
  end

  def test_ciba_pki_mtls_opaque_flow
    assert_ciba_mtls_flow("tls_client_auth", false)
  end

  def test_ciba_pki_mtls_jwt_flow
    assert_ciba_mtls_flow("tls_client_auth", true)
  end

  def test_ciba_self_signed_mtls_opaque_flow
    assert_ciba_mtls_flow("self_signed_tls_client_auth", false)
  end

  def test_ciba_self_signed_mtls_jwt_flow
    assert_ciba_mtls_flow("self_signed_tls_client_auth", true)
  end

  def assert_ciba_mtls_flow(method, jwt, dpop: false, global_binding: false)
    key = OpenSSL::PKey::RSA.generate(2048)
    certificate = mtls_certificate(key, 1)
    other_certificate = mtls_certificate(key, 2)
    @db.alter_table(:oauth_applications) do
      add_column :tls_client_auth_subject_dn, String
      add_column :tls_client_certificate_bound_access_tokens, TrueClass
      add_column :jwks, String, text: true
    end
    @db.alter_table(:oauth_grants) { add_column :certificate_thumbprint, String }
    @db.alter_table(:oauth_grants) { add_column :dpop_jkt, String } if dpop
    Rodauth::CibaSupport::Schema.create_refresh_tokens(@db)
    jwk = JWT::JWK.new(key.public_key).export.merge(x5c: [Base64.strict_encode64(certificate.to_der)])
    @db[:oauth_applications].update(token_endpoint_auth_method: method,
      tls_client_auth_subject_dn: "/CN=client", tls_client_certificate_bound_access_tokens: true,
      scopes: "openid offline_access", grant_types: "#{GRANT} refresh_token",
      jwks: JSON.generate(keys: [jwk]))
    @app.plugin(:rodauth) do
      enable :oauth_tls_client_auth, :oauth_token_introspection
      enable :oauth_dpop if dpop
      oauth_jwt_access_tokens jwt
      oauth_tls_client_certificate_bound_access_tokens global_binding
      ciba_refresh_tokens_enabled true
      oauth_application_scopes %w[openid offline_access]
      ciba_tls_client_certificate { scope.env["test.tls_certificate"] }
      ciba_tls_client_certificate_authorized? { scope.env["test.tls_verified"] == true }
      ciba_tls_client_certificate_subject_matches? do |property, expected|
        property == :tls_client_auth_subject_dn &&
          client_certificate.subject.cmp(OpenSSL::X509::Name.parse(expected)).zero?
      end
    end
    trusted = {"HTTP_AUTHORIZATION" => nil, "test.tls_certificate" => certificate, "test.tls_verified" => true}
    start = {client_id: "support", scope: "openid offline_access", login_hint: "customer@example.test"}
    assert_equal 401, post("/backchannel-authentication", start, "HTTP_AUTHORIZATION" => nil).status
    spoof = {"HTTP_AUTHORIZATION" => nil, "HTTP_X_SSL_CLIENT_CERT" => certificate.to_pem, "HTTP_X_SSL_CLIENT_VERIFY" => "SUCCESS"}
    assert_equal 401, post("/backchannel-authentication", start, spoof).status
    assert_equal 401, post("/backchannel-authentication", start, trusted.merge("test.tls_certificate" => "not a certificate")).status
    if method == "tls_client_auth"
      assert_equal 401, post("/backchannel-authentication", start, trusted.merge("test.tls_verified" => false)).status
      @db[:oauth_applications].update(tls_client_auth_subject_dn: "/CN=other")
      assert_equal 401, post("/backchannel-authentication", start, trusted).status
      @db[:oauth_applications].update(tls_client_auth_subject_dn: "/CN=client")
      @db[:oauth_applications].update(token_endpoint_auth_method: "tls_client_auth client_secret_basic")
      assert_equal 401, post("/backchannel-authentication", start,
        trusted.merge("test.tls_verified" => false, "HTTP_X_SSL_CLIENT_VERIFY" => "SUCCESS")).status
      @db[:oauth_applications].update(token_endpoint_auth_method: method)
    else
      assert_equal 401, post("/backchannel-authentication", start, trusted.merge("test.tls_certificate" => other_certificate)).status
    end
    assert_equal 0, @db[:ciba_requests].count
    response = post("/backchannel-authentication", start, trusted)
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body).fetch("auth_req_id")
    approve(id)
    token_params = {client_id: "support", grant_type: GRANT, auth_req_id: id}
    absent = post("/token", token_params, "HTTP_AUTHORIZATION" => nil)
    assert_equal 401, absent.status
    assert_equal "no-store", absent["cache-control"]
    assert_equal "no-cache", absent["pragma"]
    assert_equal "approved", @db[:ciba_requests].get(:status)
    failure = post("/token", token_params, trusted.merge("test.fail_signing" => true, "test.processing_error" => ->(_) {}))
    assert_equal 500, failure.status
    assert_equal "approved", @db[:ciba_requests].get(:status)
    assert_equal 0, @db[:oauth_grants].count
    if dpop
      proof_key = OpenSSL::PKey::EC.generate("prime256v1")
      proof = JWT.encode({jti: SecureRandom.uuid, iat: Time.now.to_i, htm: "POST", htu: "https://op.example.test/token"},
        proof_key, "ES256", typ: "dpop+jwt", jwk: JWT::JWK.new(proof_key).export)
      assert_error post("/token", token_params, trusted.merge("HTTP_DPOP" => proof)), "invalid_request"
      assert_equal "approved", @db[:ciba_requests].get(:status)
      assert_equal 0, @db[:oauth_grants].count
      assert_equal 0, @db[:ciba_client_assertions].count
    end
    issued = post("/token", token_params, trusted)
    assert_equal 200, issued.status, issued.body
    tokens, identity = decode_id_token(issued)
    refute identity.key?("cnf"), "ID Token must not inherit certificate binding"
    expected = Base64.urlsafe_encode64(Digest::SHA256.digest(certificate.to_der), padding: false)
    assert_equal expected, @db[:oauth_grants].get(:certificate_thumbprint)
    if jwt
      claims, = JWT.decode(tokens.fetch("access_token"), KEY.public_key, true, algorithms: ["RS256"])
      assert_equal expected, claims.fetch("cnf").fetch("x5t#S256")
    else
      info = post("/introspect", {client_id: "support", token: tokens.fetch("access_token")}, trusted)
      assert_equal 200, info.status, info.body
      assert_equal true, JSON.parse(info.body)["active"], info.body
      assert_equal expected, JSON.parse(info.body).fetch("cnf").fetch("x5t#S256")
    end
    inspected = post("/introspect", {client_id: "support", token: tokens.fetch("access_token")}, trusted)
    assert_equal 200, inspected.status, inspected.body
    assert_equal expected, JSON.parse(inspected.body).fetch("cnf").fetch("x5t#S256")
    userinfo = lambda do |cert, token = tokens.fetch("access_token")|
      Rack::MockRequest.new(@app).get("https://op.example.test/userinfo", "HTTP_AUTHORIZATION" => "Bearer #{token}", "test.tls_certificate" => cert)
    end
    assert_equal 401, userinfo.call(nil).status
    assert_equal 401, userinfo.call(other_certificate).status
    info = userinfo.call(certificate)
    assert_equal 200, info.status, info.body
    assert_equal @account_id.to_s, JSON.parse(info.body).fetch("sub")
    refreshed = post("/token", {client_id: "support", grant_type: "refresh_token", refresh_token: tokens.fetch("refresh_token")}, trusted)
    assert_equal 200, refreshed.status, refreshed.body
    refute decode_id_token(refreshed).last.key?("cnf")
    assert_equal expected, @db[:oauth_grants].order(:id).last.fetch(:certificate_thumbprint)
    assert_equal 200, userinfo.call(certificate, JSON.parse(refreshed.body).fetch("access_token")).status
    @db[:oauth_grants].update(expires_in: Time.now - 60)
    assert_equal 401, userinfo.call(certificate).status
    assert_equal false, JSON.parse(post("/introspect", {client_id: "support", token: tokens.fetch("access_token")}, trusted).body)["active"]
    @db[:oauth_grants].update(expires_in: Time.now + 3600)
    @db[:oauth_grants].update(revoked_at: Time.now)
    assert_equal 401, userinfo.call(certificate).status
    assert_equal false, JSON.parse(post("/introspect", {client_id: "support", token: tokens.fetch("access_token")}, trusted).body)["active"]
    if global_binding
      @db[:oauth_applications].update(tls_client_certificate_bound_access_tokens: false)
      started = post("/backchannel-authentication", start, trusted)
      assert_equal 200, started.status, started.body
      id = JSON.parse(started.body).fetch("auth_req_id")
      approve(id)
      unbound = post("/token", {client_id: "support", grant_type: GRANT, auth_req_id: id}, trusted)
      assert_equal 200, unbound.status, unbound.body
      assert_nil @db[:oauth_grants].order(:id).last[:certificate_thumbprint]
      token = JSON.parse(unbound.body).fetch("access_token")
      assert_equal 200, userinfo.call(nil, token).status
      assert_equal true, auth.send(:oauth_tls_client_certificate_bound_access_tokens)
    end
  end
end
