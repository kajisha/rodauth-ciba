# frozen_string_literal: true
require_relative "ciba_pairwise_test"
require_relative "ciba_mtls_test"

class CibaIntegrationTest
  def test_pairwise_self_signed_mtls_opaque
    assert_pairwise_self_signed_mtls(false)
  end

  def test_pairwise_self_signed_mtls_jwt
    assert_pairwise_self_signed_mtls(true)
  end

  def test_ciba_introspection_parameter_limit_is_scoped_and_bounded
    @app.plugin(:rodauth) { enable :oauth_token_introspection }
    marker = JWT.encode({"urn:rodauth:ciba:token_id" => "untrusted"}, nil, "none")
    candidate = marker + "x" * (8192 - marker.bytesize)
    read_param = lambda do |path, key, value|
      env = Rack::MockRequest.env_for("https://op.example.test#{path}", method: "POST",
        input: URI.encode_www_form(key => value), "CONTENT_TYPE" => "application/x-www-form-urlencoded")
      auth(env).send(:param_or_nil, key)
    end
    assert_equal candidate, read_param.call("/introspect", "token", candidate)
    assert_nil read_param.call("/introspect", "token", candidate + "x")
    assert_nil read_param.call("/introspect", "token", "x" * 1025)
    assert_nil read_param.call("/token", "token", candidate)
    assert_nil read_param.call("/introspect", "client_secret", candidate)
  end

  def assert_pairwise_self_signed_mtls(jwt)
    configure_pairwise
    certificate = mtls_certificate(KEY, 1)
    other_certificate = mtls_certificate(KEY, 2)
    jwk = JWT::JWK.new(KEY.public_key).export.merge(x5c: [Base64.strict_encode64(certificate.to_der)])
    @db.alter_table(:oauth_grants) { add_column :certificate_thumbprint, String }
    @db.alter_table(:oauth_applications) { add_column :tls_client_certificate_bound_access_tokens, TrueClass }
    Rodauth::CibaSupport::Schema.create_refresh_tokens(@db)
    @db[:oauth_applications].update(token_endpoint_auth_method: "self_signed_tls_client_auth",
      tls_client_certificate_bound_access_tokens: true, grant_types: "#{GRANT} refresh_token", scopes: "openid offline_access")
    @app.plugin(:rodauth) do
      enable :oauth_tls_client_auth, :oauth_token_introspection
      oauth_jwt_access_tokens jwt
      ciba_refresh_tokens_enabled true
      oauth_application_scopes %w[openid offline_access]
      ciba_pairwise_identifier do |account_id, oauth_application:, sector_identifier:|
        "p" * 190 + OpenSSL::HMAC.hexdigest("SHA256", "pairwise-test-secret", JSON.generate([sector_identifier, account_id]))
      end
      ciba_tls_client_certificate { scope.env["test.tls_certificate"] }
      auth_class_eval { define_method(:oauth_application_jwks) { |_application| {keys: [jwk]} } }
    end
    start = {client_id: "support", scope: "openid offline_access", login_hint: "customer@example.test"}
    trusted = {"HTTP_AUTHORIZATION" => nil, "test.tls_certificate" => certificate}
    assert_equal 401, post("/backchannel-authentication", start, trusted.merge("test.tls_certificate" => other_certificate)).status
    response = post("/backchannel-authentication", start, trusted)
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body).fetch("auth_req_id")
    approve(id)
    issued = post("/token", {client_id: "support", grant_type: GRANT, auth_req_id: id}, trusted)
    assert_equal 200, issued.status, issued.body
    tokens, claims = decode_id_token(issued)
    expected = "p" * 190 + OpenSSL::HMAC.hexdigest("SHA256", "pairwise-test-secret", JSON.generate(["keys.example.test", @account_id]))
    assert_equal expected, claims.fetch("sub")
    assert_equal @account_id, @db[:oauth_grants].get(:account_id)
    assert_equal expected, @db[:oauth_grants].get(:ciba_subject)
    inspected = post("/introspect", {client_id: "support", token: tokens.fetch("access_token")}, trusted)
    assert_operator tokens.fetch("access_token").bytesize, :>, 1024 if jwt
    assert_equal 200, inspected.status, inspected.body
    assert_equal true, JSON.parse(inspected.body)["active"]
    assert_equal expected, JSON.parse(inspected.body)["sub"] if jwt
    if jwt
      access = tokens.fetch("access_token")
      payload, = JWT.decode(access, KEY.public_key, true, algorithms: ["RS256"])
      foreign_key = OpenSSL::PKey::RSA.generate(2048)
      invalid_tokens = [
        JWT.encode(payload, foreign_key, "RS256"),
        JWT.encode(payload, nil, "none"),
        JWT.encode(payload.merge("sub" => "another-account"), KEY, "RS256"),
        JWT.encode(payload.merge("urn:rodauth:ciba:token_id" => "unknown-issuance"), KEY, "RS256")
      ]
      invalid_tokens.each do |invalid|
        rejected = post("/introspect", {client_id: "support", token: invalid}, trusted)
        assert_equal 200, rejected.status, rejected.body
        assert_equal false, JSON.parse(rejected.body)["active"], rejected.body
      end
      # The long-token allowance does not authenticate the introspection caller.
      absent = post("/introspect", {client_id: "support", token: access}, "HTTP_AUTHORIZATION" => nil)
      assert_equal 401, absent.status, absent.body
      foreign = post("/introspect", {client_id: "support", token: access},
        trusted.merge("test.tls_certificate" => other_certificate))
      assert_equal 401, foreign.status, foreign.body
    end
    userinfo = lambda do |cert, token|
      Rack::MockRequest.new(@app).get("https://op.example.test/userinfo",
        "HTTP_AUTHORIZATION" => "Bearer #{token}", "test.tls_certificate" => cert)
    end
    assert_equal 401, userinfo.call(nil, tokens.fetch("access_token")).status
    info = userinfo.call(certificate, tokens.fetch("access_token"))
    assert_equal 200, info.status, info.body
    assert_equal expected, JSON.parse(info.body).fetch("sub")
    refreshed = post("/token", {client_id: "support", grant_type: "refresh_token", refresh_token: tokens.fetch("refresh_token")}, trusted)
    assert_equal 200, refreshed.status, refreshed.body
    renewed = userinfo.call(certificate, JSON.parse(refreshed.body).fetch("access_token"))
    assert_equal 200, renewed.status, renewed.body
    assert_equal expected, JSON.parse(renewed.body).fetch("sub")
  end
end
