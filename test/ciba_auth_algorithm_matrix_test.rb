# frozen_string_literal: true
require_relative "test_helper"

class CibaIntegrationTest
  def test_configured_client_assertion_algorithms_at_both_ciba_endpoints
    @db.alter_table(:oauth_applications) do
      add_column :jwks, String, text: true
      add_column :token_endpoint_auth_signing_alg, String
    end
    algorithms = %w[RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES384 ES512 HS256 HS384 HS512]
    rsa = OpenSSL::PKey::RSA.generate(2048)
    client_keys = algorithms.to_h do |alg|
      curve = {"ES256" => "prime256v1", "ES384" => "secp384r1", "ES512" => "secp521r1"}[alg]
      [alg, alg.start_with?("HS") ? "s" * 64 : (curve ? OpenSSL::PKey::EC.generate(curve) : rsa)]
    end
    op_keys = client_keys.transform_values { |key| key.is_a?(String) ? "o" * 64 : key }.merge("RS256" => KEY)
    @app.plugin(:rodauth) do
      enable :oauth_jwt_bearer_grant
      oauth_jwt_keys op_keys
    end
    metadata = JSON.parse(Rack::MockRequest.new(@app).get("https://op.example.test/.well-known/openid-configuration").body)
    assert_equal algorithms.sort, metadata.fetch("token_endpoint_auth_signing_alg_values_supported").sort
    methods = metadata.fetch("token_endpoint_auth_methods_supported")
    %w[private_key_jwt client_secret_jwt].each { |method| assert_includes methods, method }
    algorithms.each do |algorithm|
      key = client_keys.fetch(algorithm)
      symmetric = algorithm.start_with?("HS")
      method = symmetric ? "client_secret_jwt" : "private_key_jwt"
      jwk = symmetric ? nil : JWT::JWK.new(key).export.merge(alg: algorithm, use: "sig")
      @db[:oauth_applications].update(token_endpoint_auth_method: method,
        token_endpoint_auth_signing_alg: algorithm, client_secret: "s" * 64,
        jwks: jwk && JSON.generate(keys: [jwk]))
      assertion = lambda do |changes = {}, signing_key = key|
        JWT.encode({iss: "support", sub: "support", aud: "https://op.example.test", exp: Time.now.to_i + 60,
          iat: Time.now.to_i, jti: SecureRandom.uuid}.merge(changes), signing_key, algorithm,
          symmetric ? {} : {kid: jwk.fetch(:kid)})
      end
      params = lambda do |token|
        {client_id: "support", client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: token}
      end
      wrong_key = if symmetric
                    "o" * 64
                  elsif algorithm.start_with?("ES")
                    OpenSSL::PKey::EC.generate(key.group.curve_name)
                  else
                    KEY
                  end
      start = {scope: "openid", login_hint: "customer@example.test"}
      before = @db[:ciba_requests].count
      rejected = post("/backchannel-authentication", start.merge(params.call(assertion.call({aud: "https://foreign.example.test"}))), "HTTP_AUTHORIZATION" => nil)
      assert_equal 401, rejected.status, "#{algorithm}: #{rejected.body}"
      assert_equal before, @db[:ciba_requests].count
      forged = post("/backchannel-authentication", start.merge(params.call(assertion.call({}, wrong_key))), "HTTP_AUTHORIZATION" => nil)
      assert_equal 401, forged.status, "#{algorithm}: #{forged.body}"
      assert_equal before, @db[:ciba_requests].count
      response = post("/backchannel-authentication", start.merge(params.call(assertion.call)), "HTTP_AUTHORIZATION" => nil)
      assert_equal 200, response.status, "#{algorithm}: #{response.body}"
      id = JSON.parse(response.body).fetch("auth_req_id")
      approve(id)
      token_params = {grant_type: GRANT, auth_req_id: id}
      bad = post("/token", token_params.merge(params.call(assertion.call({iss: "other"}))), "HTTP_AUTHORIZATION" => nil)
      assert_equal 401, bad.status, "#{algorithm}: #{bad.body}"
      assert_equal "approved", @db[:ciba_requests].order(:id).last[:status]
      forged = post("/token", token_params.merge(params.call(assertion.call({}, wrong_key))), "HTTP_AUTHORIZATION" => nil)
      assert_equal 401, forged.status, "#{algorithm}: #{forged.body}"
      assert_equal "approved", @db[:ciba_requests].order(:id).last[:status]
      response = post("/token", token_params.merge(params.call(assertion.call)), "HTTP_AUTHORIZATION" => nil)
      assert_equal 200, response.status, "#{algorithm}: #{response.body}"
      assert_equal @account_id.to_s, decode_id_token(response).last.fetch("sub")
    end
  end
end
