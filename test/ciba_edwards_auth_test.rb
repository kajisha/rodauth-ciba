# frozen_string_literal: true
# Edwards authentication uses client keys without changing OP signing keys.
require_relative "ciba_registration_test"
require_relative "ciba_configuration_test"

class CibaIntegrationTest
  def test_edwards_client_authentication_at_both_endpoints
    @db.alter_table(:oauth_applications) do
      add_column :jwks, String, text: true
      add_column :token_endpoint_auth_signing_alg, String
    end
    previous_id_algorithms = JSON.parse(Rack::MockRequest.new(@app).get("https://op.example.test/.well-known/openid-configuration").body).fetch("id_token_signing_alg_values_supported")
    @app.plugin(:rodauth) do
      enable :oauth_jwt_bearer_grant
      ciba_client_assertion_signing_algorithms %w[Ed25519 EdDSA]
    end
    key = OpenSSL::PKey.generate_key("ED25519")
    raw = OpenSSL::ASN1.decode(key.public_to_der).value.last.value
    public_jwk = {kty: "OKP", crv: "Ed25519", x: Base64.urlsafe_encode64(raw, padding: false), kid: "client", use: "sig"}
    metadata = JSON.parse(Rack::MockRequest.new(@app).get("https://op.example.test/.well-known/openid-configuration").body)
    assert_equal %w[Ed25519 EdDSA RS256], metadata.fetch("token_endpoint_auth_signing_alg_values_supported").sort
    assert_equal previous_id_algorithms, metadata.fetch("id_token_signing_alg_values_supported")
    outcomes = {}
    %w[Ed25519 EdDSA].each do |algorithm|
      @db[:oauth_applications].update(token_endpoint_auth_method: "client_secret_basic", token_endpoint_auth_signing_alg: nil)
      id = accept_request
      approve(id)
      @db[:oauth_applications].update(token_endpoint_auth_method: "private_key_jwt",
        token_endpoint_auth_signing_alg: algorithm, jwks: JSON.generate(keys: [public_jwk.merge(alg: algorithm)]))
      outcomes[algorithm] = [["/backchannel-authentication", {scope: "openid", login_hint: "customer@example.test"}],
        ["/token", {grant_type: GRANT, auth_req_id: id}]].map do |path, params|
        claims = {iss: "support", sub: "support", aud: "https://op.example.test", exp: Time.now.to_i + 60,
          jti: SecureRandom.uuid}
        parts = [{alg: algorithm, kid: "client"}, claims].map { |part| Base64.urlsafe_encode64(JSON.generate(part), padding: false) }
        signature = key.sign(nil, parts.join("."))
        token = (parts + [Base64.urlsafe_encode64(signature, padding: false)]).join(".")
        send_assertion = lambda do |value|
          post(path, params.merge(client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            client_assertion: value), "HTTP_AUTHORIZATION" => nil)
        end
        wrong = OpenSSL::PKey.generate_key("ED25519")
        forged = (parts + [Base64.urlsafe_encode64(wrong.sign(nil, parts.join(".")), padding: false)]).join(".")
        assert_equal 401, send_assertion.call(forged).status
        [{aud: "https://wrong.example"}, {iss: "other"}, {exp: Time.now.to_i - 60},
         {nbf: Time.now.to_i + 3600}, {nbf: "bad"}].each do |changed|
          modified = [parts.first, Base64.urlsafe_encode64(JSON.generate(claims.merge(changed)), padding: false)]
          altered = (modified + [Base64.urlsafe_encode64(key.sign(nil, modified.join(".")), padding: false)]).join(".")
          assert_equal 401, send_assertion.call(altered).status
        end
        [{alg: "RS256"}, {use: "enc"}, {key_ops: ["sign"]}, {crv: "X25519"}, {x: "bad"}, {kid: "unknown"}].each do |changes|
          @db[:oauth_applications].update(jwks: JSON.generate(keys: [public_jwk.merge(alg: algorithm).merge(changes)]))
          assert_equal 401, send_assertion.call(token).status
        end
        @db[:oauth_applications].update(jwks: JSON.generate(keys: [public_jwk.merge(alg: algorithm)]))
        response = send_assertion.call(token)
        assert_equal 401, send_assertion.call(token).status, "assertion replay must fail"
        [response.status, JSON.parse(response.body)["error"]]
      end
    end
    assert_equal({"Ed25519" => [200, 200], "EdDSA" => [200, 200]}, outcomes.transform_values { |rows| rows.map(&:first) })
  end
  def test_edwards_client_authentication_registration_is_explicit
    configure_dynamic_registration
    @db.alter_table(:oauth_applications) do
      add_column :jwks, String, text: true
      add_column :token_endpoint_auth_signing_alg, String
    end
    @app.plugin(:rodauth) { enable :oauth_jwt_bearer_grant }
    key = OpenSSL::PKey.generate_key("ED25519")
    raw = OpenSSL::ASN1.decode(key.public_to_der).value.last.value
    jwk = {kty: "OKP", crv: "Ed25519", x: Base64.urlsafe_encode64(raw, padding: false)}
    %w[Ed25519 EdDSA].each do |algorithm|
      params = registration_params.merge("token_endpoint_auth_method" => "private_key_jwt",
        "token_endpoint_auth_signing_alg" => algorithm, "jwks" => {"keys" => [jwk.merge(alg: algorithm)]})
      @app.plugin(:rodauth) { ciba_client_assertion_signing_algorithms nil }
      assert_error register(params), "invalid_client_metadata"
      @app.plugin(:rodauth) { ciba_client_assertion_signing_algorithms %w[Ed25519 EdDSA] }
      response = register(params)
      assert_equal 201, response.status, response.body
      assert_equal algorithm, JSON.parse(response.body).fetch("token_endpoint_auth_signing_alg")
      assert_error register(params.merge("token_endpoint_auth_method" => "client_secret_jwt")), "invalid_client_metadata"
    end
  end

  def test_edwards_authentication_configuration_preserves_unrelated_rsa_clients
    configure_assertion_client
    @db[:oauth_applications].update(grant_types: "authorization_code")
    @app.plugin(:rodauth) { ciba_client_assertion_signing_algorithms %w[Ed25519 EdDSA] }
    metadata = JSON.parse(Rack::MockRequest.new(@app).get("https://op.example.test/.well-known/openid-configuration").body)
    assert_equal %w[Ed25519 EdDSA RS256], metadata.fetch("token_endpoint_auth_signing_alg_values_supported").sort
    @db[:oauth_grants].insert(oauth_application_id: @client_id, account_id: @account_id,
      type: "authorization_code", code: "ordinary-rsa-code", scopes: "openid", expires_in: Time.now + 60,
      redirect_uri: "https://rp.example.test/callback")
    response = post("/token", assertion_params("https://op.example.test/token").merge(grant_type: "authorization_code",
      code: "ordinary-rsa-code", redirect_uri: "https://rp.example.test/callback"), "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, response.status, response.body
    assert_equal 0, @db[:ciba_requests].count
    assert_equal 0, @db[:ciba_client_assertions].count
  end

end
