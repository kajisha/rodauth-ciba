# frozen_string_literal: true
require_relative "ciba_signed_request_test"
require_relative "ciba_registration_test"
require_relative "ciba_remote_jwks_test"

class CibaIntegrationTest
  def test_node_generated_edwards_vectors_with_inline_keys
    enable_signed_requests
    assert_node_edwards_vectors
  end

  def test_node_generated_edwards_vectors_with_remote_keys
    with_client_jwks_server do |state, _uri, _server|
      assert_node_edwards_vectors(state)
      assert_operator state[:requests], :>=, 2
    end
  end

  def assert_node_edwards_vectors(remote = nil)
    fixture = JSON.parse(File.read(File.expand_path("../examples/fixtures/edwards-requests.json", __dir__)))
    @app.plugin(:rodauth) { ciba_request_signing_algorithms %w[Ed25519 EdDSA] }
    fixture.fetch("vectors").each do |vector|
      @db[:oauth_applications].update(backchannel_authentication_request_signing_alg: vector.fetch("alg"))
      if remote
        auth.send(:http_request_cache).uncache(URI(@db[:oauth_applications].get(:jwks_uri)))
        remote[:keys] = [vector.fetch("jwk")]
      else
        @db[:oauth_applications].update(jwks: JSON.generate(keys: [vector.fetch("jwk")]))
      end
      token = vector.fetch("token")
      env = {"test.now" => -> { fixture.fetch("now") }}
      parts = token.split(".")
      tampered = JSON.parse(Base64.urlsafe_decode64(parts[1])).merge("login_hint" => "another-account")
      parts[1] = Base64.urlsafe_encode64(JSON.generate(tampered), padding: false)
      count = @db[:ciba_requests].count
      assert_error post("/backchannel-authentication", {request: parts.join(".")}, env), "invalid_request"
      assert_equal count, @db[:ciba_requests].count
      response = post("/backchannel-authentication", {request: token}, env)
      assert_equal 200, response.status, response.body
      id = JSON.parse(response.body).fetch("auth_req_id")
      assert_error poll(id, env), "authorization_pending"
      row = @db[:ciba_requests].order(:id).last
      auth(env).approve_ciba_request(row[:id], account_id: @account_id)
      issued = poll(id, env)
      assert_equal 200, issued.status, issued.body
      assert_equal @account_id.to_s, decode_id_token(issued).last.fetch("sub")
    end
  end

  def test_edwards_request_registration_and_discovery
    configure_dynamic_registration
    enable_signed_requests
    @app.plugin(:rodauth) { ciba_request_signing_algorithms %w[Ed25519 EdDSA] }
    key = OpenSSL::PKey.generate_key("ED25519")
    raw = OpenSSL::ASN1.decode(key.public_to_der).value.last.value
    jwk = {"kty" => "OKP", "crv" => "Ed25519", "x" => Base64.urlsafe_encode64(raw, padding: false)}
    metadata = JSON.parse(Rack::MockRequest.new(@app).get("https://op.example.test/.well-known/openid-configuration").body)
    assert_equal %w[Ed25519 EdDSA], metadata.fetch("backchannel_authentication_request_signing_alg_values_supported")
    %w[Ed25519 EdDSA].each do |algorithm|
      params = registration_params.merge("backchannel_authentication_request_signing_alg" => algorithm,
        "jwks" => {"keys" => [jwk.merge("alg" => algorithm)]})
      response = register(params)
      assert_equal 201, response.status, response.body
      assert_equal algorithm, JSON.parse(response.body).fetch("backchannel_authentication_request_signing_alg")
      before = @db[:oauth_applications].count
      assert_error register(params.merge("jwks" => {"keys" => [jwk.merge("d" => "private-material")]})), "invalid_client_metadata"
      assert_equal before, @db[:oauth_applications].count
    end
  end

  def test_edwards_signed_requests_and_key_rejection
    enable_signed_requests
    @app.plugin(:rodauth) { ciba_request_signing_algorithms %w[Ed25519 EdDSA] }
    key = OpenSSL::PKey.generate_key("ED25519")
    wrong_key = OpenSSL::PKey.generate_key("ED25519")
    raw_public = OpenSSL::ASN1.decode(key.public_to_der).value.last.value
    public_jwk = {kty: "OKP", crv: "Ed25519", x: Base64.urlsafe_encode64(raw_public, padding: false), kid: "edwards", use: "sig"}
    %w[Ed25519 EdDSA].each do |algorithm|
      jwk = public_jwk.merge(alg: algorithm)
      @db[:oauth_applications].update(backchannel_authentication_request_signing_alg: algorithm,
        jwks: JSON.generate(keys: [jwk]))
      now = Time.now.to_i
      claims = {iss: "support", aud: "https://op.example.test", exp: now + 60, iat: now, nbf: now - 1,
        jti: SecureRandom.uuid, scope: "openid", login_hint: "customer@example.test"}
      sign = lambda do |signing_key, alg = algorithm|
        input = [{alg: alg, kid: "edwards"}, claims].map { |v| Base64.urlsafe_encode64(JSON.generate(v), padding: false) }.join(".")
        input + "." + Base64.urlsafe_encode64(signing_key.sign(nil, input), padding: false)
      end
      token = sign.call(key)
      count = @db[:ciba_requests].count
      [sign.call(wrong_key), sign.call(key, "RS256")].each do |invalid|
        assert_error post("/backchannel-authentication", request: invalid), "invalid_request"
        assert_equal count, @db[:ciba_requests].count
      end
      [{crv: "X25519"}, {kty: "RSA"}, {x: "bad"}, {x: jwk[:x] + "="},
       {alg: "RS256"}, {use: "enc"}, {key_ops: ["sign"]}].each do |change|
        @db[:oauth_applications].update(jwks: JSON.generate(keys: [jwk.merge(change)]))
        assert_error post("/backchannel-authentication", request: token), "invalid_request"
        assert_equal count, @db[:ciba_requests].count
      end
      @db[:oauth_applications].update(jwks: JSON.generate(keys: [jwk]))
      response = post("/backchannel-authentication", request: token)
      assert_equal 200, response.status, response.body
      id = JSON.parse(response.body).fetch("auth_req_id")
      assert_error poll(id), "authorization_pending"
      approve(id)
      issued = poll(id)
      assert_equal 200, issued.status, issued.body
      assert_equal @account_id.to_s, decode_id_token(issued).last.fetch("sub")
    end
  end
end
