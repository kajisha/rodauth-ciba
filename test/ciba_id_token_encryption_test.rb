# frozen_string_literal: true
require_relative "ciba_lifecycle_test"
require_relative "ciba_refresh_test"
require_relative "ciba_registration_test"

class CibaIntegrationTest
  def test_ciba_encryption_management_replaces_recipient_opaque
    assert_encryption_management(false)
  end

  def test_ciba_encryption_management_replaces_recipient_jwt
    assert_encryption_management(true)
  end

  def test_ecdh_management_ec_opaque
    assert_encryption_management(false, curve: "P-256")
  end

  def test_ecdh_management_ec_jwt
    assert_encryption_management(true, curve: "P-256")
  end

  def test_ecdh_management_okp_opaque
    assert_encryption_management(false, curve: "X25519")
  end

  def test_ecdh_management_okp_jwt
    assert_encryption_management(true, curve: "X25519")
  end

  def assert_encryption_management(jwt, curve: nil)
    configure_dynamic_registration
    enable_refresh
    @db.alter_table(:oauth_applications) do
      add_column :id_token_encrypted_response_alg, String
      add_column :id_token_encrypted_response_enc, String
      add_column :jwks, String, text: true
    end
    @app.plugin(:rodauth) do
      ciba_id_token_encryption_enabled true
      oauth_jwt_access_tokens jwt
    end
    algorithm = curve == "X25519" ? "ECDH-ES+A256KW" : curve ? "ECDH-ES" : "RSA-OAEP-256"
    old_key, new_key = 2.times.map do
      curve == "X25519" ? OpenSSL::PKey.generate_key("X25519") : curve ? OpenSSL::PKey::EC.generate("prime256v1") : OpenSSL::PKey::RSA.generate(2048)
    end
    jwks = lambda do |key, kid|
      public_jwk = if curve == "X25519"
        {"kty" => "OKP", "crv" => curve, "x" => Base64.urlsafe_encode64(OpenSSL::ASN1.decode(key.public_to_der).value.last.value, padding: false)}
      else
        JWT::JWK.new(curve ? key : key.public_key).export.transform_keys(&:to_s)
      end
      {"keys" => [public_jwk.merge("use" => "enc", "kid" => kid)]}
    end
    metadata = registration_params.merge("grant_types" => [GRANT, "refresh_token"], "scope" => "openid offline_access",
      "jwks" => jwks.call(old_key, "old"), "id_token_encrypted_response_alg" => algorithm, "id_token_encrypted_response_enc" => "A256GCM")
    registered = register(metadata)
    assert_equal 201, registered.status, registered.body
    client = JSON.parse(registered.body)
    headers = {"HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64("#{client.fetch('client_id')}:#{client.fetch('client_secret')}")}"}
    started = post("/backchannel-authentication", {scope: "openid offline_access", login_hint: "customer@example.test"}, headers)
    assert_equal 200, started.status, started.body
    id = JSON.parse(started.body).fetch("auth_req_id")
    approve(id)
    issued = post("/token", {grant_type: GRANT, auth_req_id: id}, headers)
    assert_equal 200, issued.status, issued.body
    original = JSON.parse(issued.body)
    verify = lambda do |tokens, key, kid|
      token = tokens.fetch("id_token")
      assert_equal kid, JSON.parse(Base64.urlsafe_decode64(token.split(".").first)).fetch("kid")
      signed = if curve
        parts = token.split(".", -1)
        header = JSON.parse(Base64.urlsafe_decode64(parts[0]))
        method = header.fetch("enc")
        shared = key.derive(auth.send(:ciba_ecdh_public_key, header.fetch("epk")))
        derived = auth.send(:ciba_ecdh_derived_key, shared, algorithm, method)
        cek = algorithm == "ECDH-ES" ? derived : JWE::Alg.decrypt_cek("A256KW", derived, Base64.urlsafe_decode64(parts[1]))
        JWE::Enc.for(method, cek, Base64.urlsafe_decode64(parts[2]), Base64.urlsafe_decode64(parts[4]))
          .decrypt(Base64.urlsafe_decode64(parts[3]), parts[0])
      else
        JWE.decrypt(token, key)
      end
      claims, = JWT.decode(signed, KEY.public_key, true, algorithms: ["RS256"],
        verify_iss: true, iss: "https://op.example.test", verify_aud: true, aud: client.fetch("client_id"))
      assert_equal @account_id.to_s, claims.fetch("sub")
    end
    verify.call(original, old_key, "old")
    replacement = metadata.merge("client_id" => client.fetch("client_id"), "jwks" => jwks.call(new_key, "new"))
    http = Rack::MockRequest.new(@app)
    management_headers = {"HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}", "CONTENT_TYPE" => "application/json"}
    rejected = http.put(client.fetch("registration_client_uri"), management_headers.merge(input: JSON.generate(replacement.merge("id_token_encrypted_response_enc" => "invalid"))))
    assert_error rejected, "invalid_client_metadata"
    renewed = post("/token", {grant_type: "refresh_token", refresh_token: original.fetch("refresh_token")}, headers)
    assert_equal 200, renewed.status, renewed.body
    verify.call(JSON.parse(renewed.body), old_key, "old")
    updated = http.put(client.fetch("registration_client_uri"), management_headers.merge(input: JSON.generate(replacement)))
    assert_equal 200, updated.status, updated.body
    management_headers["HTTP_AUTHORIZATION"] = "Bearer #{JSON.parse(updated.body).fetch('registration_access_token')}"
    renewed = post("/token", {grant_type: "refresh_token", refresh_token: original.fetch("refresh_token")}, headers)
    assert_equal 200, renewed.status, renewed.body
    verify.call(JSON.parse(renewed.body), new_key, "new")
    verify.call(original, old_key, "old")
    defaulted = replacement.reject { |field, _| field == "id_token_encrypted_response_enc" }
    updated = http.put(client.fetch("registration_client_uri"), management_headers.merge(input: JSON.generate(defaulted)))
    assert_equal 200, updated.status, updated.body
    assert_equal "A128CBC-HS256", JSON.parse(updated.body).fetch("id_token_encrypted_response_enc")
    management_headers["HTTP_AUTHORIZATION"] = "Bearer #{JSON.parse(updated.body).fetch('registration_access_token')}"
    renewed = post("/token", {grant_type: "refresh_token", refresh_token: original.fetch("refresh_token")}, headers)
    assert_equal 200, renewed.status, renewed.body
    default_tokens = JSON.parse(renewed.body)
    assert_equal "A128CBC-HS256", JSON.parse(Base64.urlsafe_decode64(default_tokens.fetch("id_token").split(".").first)).fetch("enc")
    verify.call(default_tokens, new_key, "new")
    plain = replacement.reject { |field, _| %w[id_token_encrypted_response_alg id_token_encrypted_response_enc].include?(field) }
    updated = http.put(client.fetch("registration_client_uri"), management_headers.merge(input: JSON.generate(plain)))
    assert_equal 200, updated.status, updated.body
    saved = @db[:oauth_applications].where(client_id: client.fetch("client_id")).first
    assert_nil saved[:id_token_encrypted_response_alg]
    assert_nil saved[:id_token_encrypted_response_enc]
    renewed = post("/token", {grant_type: "refresh_token", refresh_token: original.fetch("refresh_token")}, headers)
    assert_equal 200, renewed.status, renewed.body
    signed = JSON.parse(renewed.body).fetch("id_token")
    assert_equal 3, signed.split(".").length
    claims, = JWT.decode(signed, KEY.public_key, true, algorithms: ["RS256"], verify_aud: true, aud: client.fetch("client_id"))
    assert_equal @account_id.to_s, claims.fetch("sub")
  end

  def test_ciba_encryption_registration_ignores_disabled_capability
    configure_dynamic_registration
    @db.alter_table(:oauth_applications) do
      add_column :id_token_encrypted_response_alg, String
      add_column :id_token_encrypted_response_enc, String
      add_column :jwks, String, text: true
    end
    params = registration_params.merge("id_token_encrypted_response_alg" => "RSA-OAEP-256",
      "id_token_encrypted_response_enc" => "A256GCM", "jwks" => {"keys" => [JWT::JWK.new(KEY.public_key).export.transform_keys(&:to_s)]})
    result = register(params)
    assert_equal 201, result.status, result.body
    client = JSON.parse(result.body)
    refute client.key?("id_token_encrypted_response_alg")
    refute client.key?("id_token_encrypted_response_enc")
    saved = @db[:oauth_applications].where(client_id: client.fetch("client_id")).first
    assert_nil saved[:id_token_encrypted_response_alg]
    assert_nil saved[:id_token_encrypted_response_enc]
  end

  def test_ciba_id_token_encryption_prefers_explicit_recipient_metadata
    @db.alter_table(:oauth_applications) do
      add_column :id_token_encrypted_response_alg, String
      add_column :id_token_encrypted_response_enc, String
      add_column :jwks, String, text: true
    end
    @app.plugin(:rodauth) { ciba_id_token_encryption_enabled true }
    generic = OpenSSL::PKey::RSA.generate(2048)
    precise = OpenSSL::PKey::RSA.generate(2048)
    generic_jwk = JWT::JWK.new(generic.public_key).export.merge(kid: "generic")
    precise_jwk = JWT::JWK.new(precise.public_key).export.merge(kid: "precise", use: "enc", alg: "RSA-OAEP-256")
    @db[:oauth_applications].update(id_token_encrypted_response_alg: "RSA-OAEP-256", id_token_encrypted_response_enc: "A256GCM",
      jwks: JSON.generate(keys: [generic_jwk, precise_jwk]))
    id = accept_request
    approve(id)
    response = poll(id)
    assert_equal 200, response.status, response.body
    token = JSON.parse(response.body).fetch("id_token")
    assert_equal "precise", JSON.parse(Base64.urlsafe_decode64(token.split(".").first)).fetch("kid")
    signed = JWE.decrypt(token, precise)
    claims, = JWT.decode(signed, KEY.public_key, true, algorithms: ["RS256"])
    assert_equal @account_id.to_s, claims.fetch("sub")
  end

  def test_ciba_id_token_recipient_encryption_and_refresh
    enable_refresh
    @db.alter_table(:oauth_applications) do
      add_column :id_token_signed_response_alg, String
      add_column :id_token_encrypted_response_alg, String
      add_column :id_token_encrypted_response_enc, String
      add_column :jwks, String, text: true
    end
    recipient = OpenSSL::PKey::RSA.generate(2048)
    exported = []
    edwards = OpenSSL::PKey.generate_key("ED25519")
    @app.plugin(:rodauth) do
      ciba_id_token_encryption_enabled true
      ciba_id_token_signing_keys("Ed25519" => edwards, "EdDSA" => edwards)
    end
    %w[RS256 Ed25519 EdDSA].product(%w[RSA-OAEP RSA-OAEP-256], Rodauth::CibaSupport::IdTokenEncryption::METHODS).each do |signature, algorithm, encryption|
      jwk = JWT::JWK.new(recipient.public_key).export.merge(use: "enc", alg: algorithm, kid: "recipient")
      @db[:oauth_applications].update(id_token_signed_response_alg: signature,
        id_token_encrypted_response_alg: algorithm, id_token_encrypted_response_enc: encryption,
        jwks: JSON.generate(keys: [jwk]))
      started = post("/backchannel-authentication", scope: "openid offline_access", login_hint: "customer@example.test")
      assert_equal 200, started.status, started.body
      id = JSON.parse(started.body).fetch("auth_req_id")
      approve(id)
      issued = poll(id)
      assert_equal 200, issued.status, issued.body
      refreshed = refresh_with(JSON.parse(issued.body).fetch("refresh_token"))
      assert_equal 200, refreshed.status, refreshed.body
      [issued, refreshed].each do |response|
        token = JSON.parse(response.body).fetch("id_token")
        assert_equal 5, token.split(".").length
        header = JSON.parse(Base64.urlsafe_decode64(token.split(".").first))
        assert_equal algorithm, header.fetch("alg")
        assert_equal encryption, header.fetch("enc")
        assert_equal "JWT", header.fetch("cty")
        assert_equal "recipient", header.fetch("kid")
        signed = JWE.decrypt(token, recipient)
        if signature == "RS256"
          claims, = JWT.decode(signed, KEY.public_key, true, algorithms: [signature])
        else
          parts = signed.split(".")
          assert edwards.verify(nil, Base64.urlsafe_decode64(parts.last), parts.first(2).join("."))
          claims, = JWT.decode(signed, nil, false)
        end
        assert_equal @account_id.to_s, claims.fetch("sub")
        assert_equal "support", claims.fetch("aud")
        exported << {token: token, signature: signature, algorithm: algorithm, encryption: encryption,
          checked_at: Time.now.to_i, verification_key: signature == "RS256" ? JWT::JWK.new(KEY.public_key).export :
            auth.send(:ciba_edwards_public_jwk, edwards, signature)}
      end
    end
    if ENV["CIBA_ENCRYPTED_ID_TOKEN_EXPORT"]
      # Disposable synthetic recipient only; the export must not be committed.
      File.open(ENV.fetch("CIBA_ENCRYPTED_ID_TOKEN_EXPORT"), "w", 0o600) do |file|
        file.write(JSON.generate(recipient: JWT::JWK.new(recipient).export(include_private: true), vectors: exported))
      end
    end
  end

  def test_ciba_id_token_encryption_registration_and_discovery
    configure_dynamic_registration
    @db.alter_table(:oauth_applications) do
      add_column :id_token_encrypted_response_alg, String
      add_column :id_token_encrypted_response_enc, String
      add_column :jwks, String, text: true
    end
    @app.plugin(:rodauth) { ciba_id_token_encryption_enabled true }
    metadata = JSON.parse(Rack::MockRequest.new(@app).get("https://op.example.test/.well-known/openid-configuration").body)
    assert_includes metadata.fetch("id_token_encryption_alg_values_supported"), "RSA-OAEP-256"
    assert_includes metadata.fetch("id_token_encryption_enc_values_supported"), "A256GCM"
    assert_empty auth.send(:oauth_jwt_jwe_algorithms_supported)
    assert_empty Array(metadata["userinfo_encryption_alg_values_supported"])
    jwks = {"keys" => [JWT::JWK.new(KEY.public_key).export.transform_keys(&:to_s).merge("use" => "enc")]}
    params = registration_params.merge("id_token_encrypted_response_alg" => "RSA-OAEP-256", "jwks" => jwks)
    result = register(params)
    assert_equal 201, result.status, result.body
    assert_equal "A128CBC-HS256", JSON.parse(result.body).fetch("id_token_encrypted_response_enc")
    result = register(params.merge("id_token_encrypted_response_enc" => "A256GCM"))
    assert_equal 201, result.status, result.body
    assert_equal "A256GCM", JSON.parse(result.body).fetch("id_token_encrypted_response_enc")
    [params.reject { |key, _| key == "jwks" },
      params.merge("id_token_encrypted_response_alg" => "RSA1_5"),
      params.merge("id_token_encrypted_response_enc" => "invalid"),
      params.reject { |key, _| key == "id_token_encrypted_response_alg" }.merge("id_token_encrypted_response_enc" => "A256GCM")].each do |invalid|
      assert_error register(invalid), "invalid_client_metadata"
    end
  end

  def test_ciba_id_token_encryption_rejects_unsuitable_recipient_keys
    @db.alter_table(:oauth_applications) do
      add_column :id_token_encrypted_response_alg, String
      add_column :id_token_encrypted_response_enc, String
      add_column :jwks, String, text: true
    end
    @app.plugin(:rodauth) { ciba_id_token_encryption_enabled true }
    @db[:oauth_applications].update(id_token_encrypted_response_alg: "RSA-OAEP-256", id_token_encrypted_response_enc: "A256GCM")
    jwk = JWT::JWK.new(KEY.public_key).export
    invalid_metadata = [[], [jwk.merge(use: "sig")], [jwk.merge(alg: "RSA-OAEP")],
      [jwk.merge(key_ops: ["verify"])], [jwk.merge(key_ops: ["wrapKey"])], [jwk.merge(key_ops: "encrypt")]]
    cases = invalid_metadata.map { |keys| [keys, 400] }
    cases << [[JWT::JWK.new(OpenSSL::PKey::RSA.generate(1024).public_key).export], 500]
    cases.each do |keys, expected_status|
      @db[:oauth_applications].update(jwks: JSON.generate(keys: keys))
      id = accept_request
      approve(id)
      response = poll(id, "test.processing_error" => ->(_) {})
      assert_equal expected_status, response.status, response.body
      assert_equal 0, @db[:oauth_grants].count
      assert_equal "approved", @db[:ciba_requests].order(:id).last[:status]
    end
  end

  def test_ciba_rsa_id_token_encryption_cannot_silently_return_plaintext
    @db.alter_table(:oauth_applications) do
      add_column :id_token_encrypted_response_alg, String
      add_column :id_token_encrypted_response_enc, String
    end
    [
      {id_token_encrypted_response_alg: "RSA-OAEP-256", id_token_encrypted_response_enc: "A256GCM"},
      {id_token_encrypted_response_alg: "RSA-OAEP-256", id_token_encrypted_response_enc: nil},
      {id_token_encrypted_response_alg: nil, id_token_encrypted_response_enc: "A256GCM"}
    ].each do |metadata|
      @db[:oauth_applications].update(metadata)
      id = accept_request
      approve(id)
      count = @db[:oauth_grants].count
      errors = []
      response = poll(id, "test.processing_error" => ->(error) { errors << error })
      assert_equal 500, response.status, response.body
      assert_equal "server_error", JSON.parse(response.body).fetch("error")
      assert_equal [Rodauth::CibaSupport::ConfigurationError], errors.map(&:class)
      assert_equal "approved", @db[:ciba_requests].order(:id).last[:status]
      assert_equal count, @db[:oauth_grants].count
      @db[:oauth_applications].update(id_token_encrypted_response_alg: nil, id_token_encrypted_response_enc: nil)
      recovered = poll(id)
      assert_equal 200, recovered.status, recovered.body
      token = JSON.parse(recovered.body).fetch("id_token")
      claims, = JWT.decode(token, KEY.public_key, true, algorithms: ["RS256"],
        verify_iss: true, iss: "https://op.example.test", verify_aud: true, aud: "support")
      assert_equal @account_id.to_s, claims.fetch("sub")
    end
  end
end
