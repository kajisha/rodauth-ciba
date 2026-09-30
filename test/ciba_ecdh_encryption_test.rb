# frozen_string_literal: true
require_relative "ciba_id_token_encryption_test"

class CibaIntegrationTest
  def test_ciba_ecdh_encryption_issuance_and_refresh
    enable_refresh
    @db.alter_table(:oauth_applications) do
      add_column :id_token_encrypted_response_alg, String
      add_column :id_token_encrypted_response_enc, String
      add_column :jwks, String, text: true
    end
    @app.plugin(:rodauth) { ciba_id_token_encryption_enabled true }
    vectors = []
    ephemeral_keys = []
    {"P-256" => "prime256v1", "P-384" => "secp384r1", "P-521" => "secp521r1", "X25519" => nil}.each do |curve, group|
      recipient = group ? OpenSSL::PKey::EC.generate(group) : OpenSSL::PKey.generate_key("X25519")
      jwk = if group
        JWT::JWK.new(recipient).export.transform_keys(&:to_s)
      else
        {"kty" => "OKP", "crv" => curve, "x" => Base64.urlsafe_encode64(OpenSSL::ASN1.decode(recipient.public_to_der).value.last.value, padding: false)}
      end
      %w[ECDH-ES ECDH-ES+A128KW ECDH-ES+A192KW ECDH-ES+A256KW].product(
        %w[A128GCM A192GCM A256GCM A128CBC-HS256 A192CBC-HS384 A256CBC-HS512]
      ).each do |algorithm, method|
        @db[:oauth_applications].update(id_token_encrypted_response_alg: algorithm, id_token_encrypted_response_enc: method,
          jwks: JSON.generate(keys: [jwk.merge("kid" => "recipient", "alg" => algorithm, "use" => "enc")]))
        started = post("/backchannel-authentication", scope: "openid offline_access", login_hint: "customer@example.test")
        assert_equal 200, started.status, started.body
        id = JSON.parse(started.body).fetch("auth_req_id")
        approve(id)
        issued = poll(id, "test.processing_error" => ->(_) {})
        assert_equal 200, issued.status, issued.body
        renewed = refresh_with(JSON.parse(issued.body).fetch("refresh_token"))
        assert_equal 200, renewed.status, renewed.body
        [issued, renewed].each do |response|
          token = JSON.parse(response.body).fetch("id_token")
          parts = token.split(".", -1)
          assert_equal 5, parts.length
          header = JSON.parse(Base64.urlsafe_decode64(parts[0]))
          assert_equal algorithm, header.fetch("alg")
          assert_equal method, header.fetch("enc")
          assert_equal "recipient", header.fetch("kid")
          assert_equal curve, header.fetch("epk").fetch("crv")
          refute header.fetch("epk").key?("d")
          refute_includes ephemeral_keys, header.fetch("epk")
          ephemeral_keys << header.fetch("epk")
          assert_equal algorithm == "ECDH-ES", parts[1].empty?
          epk = auth.send(:ciba_ecdh_public_key, header.fetch("epk"))
          shared = recipient.derive(epk)
          derived = auth.send(:ciba_ecdh_derived_key, shared, algorithm, method)
          cek = algorithm == "ECDH-ES" ? derived : JWE::Alg.decrypt_cek(algorithm.split("+").last, derived, Base64.urlsafe_decode64(parts[1]))
          signed = JWE::Enc.for(method, cek, Base64.urlsafe_decode64(parts[2]), Base64.urlsafe_decode64(parts[4]))
            .decrypt(Base64.urlsafe_decode64(parts[3]), parts[0])
          claims, = JWT.decode(signed, KEY.public_key, true, algorithms: ["RS256"],
            verify_iss: true, iss: "https://op.example.test", verify_aud: true, aud: "support")
          assert_equal @account_id.to_s, claims.fetch("sub")
          vectors << {token: token, algorithm: algorithm, method: method, curve: curve,
            recipient_pem: recipient.private_to_pem, checked_at: Time.now.to_i, subject: @account_id.to_s}
        end
      end
    end
    if ENV["CIBA_ECDH_EXPORT"]
      File.open(ENV.fetch("CIBA_ECDH_EXPORT"), "w", 0o600) do |file|
        file.write(JSON.generate(public_key: JWT::JWK.new(KEY.public_key).export, vectors: vectors))
      end
    end
  end
  def test_ciba_ecdh_encryption_registration_and_discovery
    configure_dynamic_registration
    @db.alter_table(:oauth_applications) do
      add_column :id_token_encrypted_response_alg, String
      add_column :id_token_encrypted_response_enc, String
      add_column :jwks, String, text: true
    end
    @app.plugin(:rodauth) { ciba_id_token_encryption_enabled true }
    metadata = JSON.parse(Rack::MockRequest.new(@app).get("https://op.example.test/.well-known/openid-configuration").body)
    algorithms = %w[ECDH-ES ECDH-ES+A128KW ECDH-ES+A192KW ECDH-ES+A256KW]
    algorithms.each { |algorithm| assert_includes metadata.fetch("id_token_encryption_alg_values_supported"), algorithm }
    {"P-256" => "prime256v1", "P-384" => "secp384r1", "P-521" => "secp521r1", "X25519" => nil}.each do |curve, group|
      key = group ? OpenSSL::PKey::EC.generate(group) : OpenSSL::PKey.generate_key("X25519")
      jwk = group ? JWT::JWK.new(key).export.transform_keys(&:to_s) :
        {"kty" => "OKP", "crv" => curve, "x" => Base64.urlsafe_encode64(OpenSSL::ASN1.decode(key.public_to_der).value.last.value, padding: false)}
      algorithms.each do |algorithm|
        params = registration_params.merge("id_token_encrypted_response_alg" => algorithm,
          "jwks" => {"keys" => [jwk.merge("use" => "enc", "alg" => algorithm)]})
        registered = register(params)
        assert_equal 201, registered.status, registered.body
        client = JSON.parse(registered.body)
        assert_equal "A128CBC-HS256", client.fetch("id_token_encrypted_response_enc")
        headers = {"HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64("#{client.fetch('client_id')}:#{client.fetch('client_secret')}")}"}
        started = post("/backchannel-authentication", {scope: "openid", login_hint: "customer@example.test"}, headers)
        assert_equal 200, started.status, started.body
        id = JSON.parse(started.body).fetch("auth_req_id")
        approve(id)
        issued = post("/token", {grant_type: GRANT, auth_req_id: id}, headers)
        assert_equal 200, issued.status, issued.body
        header = JSON.parse(Base64.urlsafe_decode64(JSON.parse(issued.body).fetch("id_token").split(".").first))
        assert_equal curve, header.fetch("epk").fetch("crv")
        assert_error register(params.reject { |name, _| name == "jwks" }), "invalid_client_metadata"
      end
    end
  end

  def test_ciba_ecdh_encryption_public_key_operations
    @db.alter_table(:oauth_applications) do
      add_column :id_token_encrypted_response_alg, String
      add_column :id_token_encrypted_response_enc, String
      add_column :jwks, String, text: true
    end
    @app.plugin(:rodauth) { ciba_id_token_encryption_enabled true }
    @db[:oauth_applications].update(id_token_encrypted_response_alg: "ECDH-ES", id_token_encrypted_response_enc: "A256GCM")
    %w[P-256 X25519].each do |curve|
      key = curve == "X25519" ? OpenSSL::PKey.generate_key("X25519") : OpenSSL::PKey::EC.generate("prime256v1")
      jwk = curve == "X25519" ?
        {"kty" => "OKP", "crv" => curve, "x" => Base64.urlsafe_encode64(OpenSSL::ASN1.decode(key.public_to_der).value.last.value, padding: false)} :
        JWT::JWK.new(key).export.transform_keys(&:to_s)
      [nil, [], ["deriveBits"], ["sign"], ["encrypt"]].each do |operations|
        candidate = operations.nil? ? jwk : jwk.merge("key_ops" => operations)
        @db[:oauth_applications].update(jwks: JSON.generate(keys: [candidate]))
        started = post("/backchannel-authentication", scope: "openid", login_hint: "customer@example.test")
        assert_equal 200, started.status, started.body
        id = JSON.parse(started.body).fetch("auth_req_id")
        approve(id)
        count = @db[:oauth_grants].count
        response = poll(id, "test.processing_error" => ->(_) {})
        if operations.nil? || operations.empty?
          assert_equal 200, response.status, response.body
          assert_equal count + 1, @db[:oauth_grants].count
        else
          assert_equal 500, response.status, response.body
          assert_equal count, @db[:oauth_grants].count
          assert_equal "approved", @db[:ciba_requests].order(:id).last.fetch(:status)
        end
      end
    end
  end

  def test_ciba_ecdh_encryption_rejects_invalid_recipients
    @db.alter_table(:oauth_applications) do
      add_column :id_token_encrypted_response_alg, String
      add_column :id_token_encrypted_response_enc, String
      add_column :jwks, String, text: true
    end
    @app.plugin(:rodauth) { ciba_id_token_encryption_enabled true }
    @db[:oauth_applications].update(id_token_encrypted_response_alg: "ECDH-ES", id_token_encrypted_response_enc: "A256GCM")
    started = post("/backchannel-authentication", scope: "openid", login_hint: "customer@example.test")
    id = JSON.parse(started.body).fetch("auth_req_id")
    approve(id)
    good = JWT::JWK.new(OpenSSL::PKey::EC.generate("prime256v1")).export.transform_keys(&:to_s)
    zero = Base64.urlsafe_encode64("\0" * 32, padding: false)
    [good.merge("x" => zero, "y" => zero), good.merge("crv" => "P-384"),
      good.merge("use" => "sig"), good.merge("alg" => "ECDH-ES+A128KW"),
      {"kty" => "OKP", "crv" => "Ed25519", "x" => zero},
      {"kty" => "OKP", "crv" => "X25519", "x" => zero},
      {"kty" => "OKP", "crv" => "X25519", "x" => "AA"}].each do |jwk|
      @db[:oauth_applications].update(jwks: JSON.generate(keys: [jwk]))
      response = poll(id, "test.processing_error" => ->(_) {})
      expected_status = jwk["use"] == "sig" || jwk["alg"] == "ECDH-ES+A128KW" ? 400 : 500
      assert_equal expected_status, response.status, response.body
      assert_equal "approved", @db[:ciba_requests].get(:status)
      assert_equal 0, @db[:oauth_grants].count
    end
    @db[:oauth_applications].update(jwks: JSON.generate(keys: [good]))
    response = poll(id)
    assert_equal 200, response.status, response.body
  end

end
