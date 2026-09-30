# frozen_string_literal: true
require_relative "ciba_id_token_encryption_test"

class CibaIntegrationTest
  def test_ciba_symmetric_encryption_registered_client_secret
    vectors = []
    wrapping_ivs = []
    configure_dynamic_registration
    enable_refresh
    @db.alter_table(:oauth_applications) do
      add_column :id_token_encrypted_response_alg, String
      add_column :id_token_encrypted_response_enc, String
    end
    @app.plugin(:rodauth) do
      ciba_id_token_encryption_enabled true
      oauth_applications_client_secret_hash_column :client_secret
    end
    %w[A128GCMKW A192GCMKW A256GCMKW dir A128KW A192KW A256KW].product(
      %w[A128GCM A192GCM A256GCM A128CBC-HS256 A192CBC-HS384 A256CBC-HS512]
    ).each do |algorithm, method|
      registered = register(registration_params.merge("grant_types" => [GRANT, "refresh_token"],
        "scope" => "openid offline_access", "id_token_encrypted_response_alg" => algorithm,
        "id_token_encrypted_response_enc" => method))
      assert_equal 201, registered.status, registered.body
      client = JSON.parse(registered.body)
      secret = client.fetch("client_secret")
      saved = @db[:oauth_applications].where(client_id: client.fetch("client_id")).first
      refute_equal secret, saved.fetch(:client_secret)
      headers = {"HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64("#{client.fetch('client_id')}:#{secret}")}"}
      started = post("/backchannel-authentication", {scope: "openid offline_access", login_hint: "customer@example.test"}, headers)
      assert_equal 200, started.status, started.body
      id = JSON.parse(started.body).fetch("auth_req_id")
      approve(id)
      issued = post("/token", {grant_type: GRANT, auth_req_id: id}, headers)
      assert_equal 200, issued.status, issued.body
      initial = JSON.parse(issued.body)
      renewed = post("/token", {grant_type: "refresh_token", refresh_token: initial.fetch("refresh_token")}, headers)
      assert_equal 200, renewed.status, renewed.body
      bits = (algorithm == "dir" ? (method[/HS(\d+)$/, 1] || method[/^A(\d+)/, 1]) : algorithm[/^A(\d+)/, 1]).to_i
      bytes = bits / 8
      key = OpenSSL::Digest.digest(bytes <= 32 ? "SHA256" : bytes <= 48 ? "SHA384" : "SHA512", secret)[0, bytes]
      [initial, JSON.parse(renewed.body)].each do |tokens|
        token = tokens.fetch("id_token")
        header = JSON.parse(Base64.urlsafe_decode64(token.split('.').first))
        assert_equal algorithm, header.fetch("alg")
        assert_equal method, header.fetch("enc")
        assert_equal "JWT", header.fetch("cty")
        refute header.key?("kid")
        if algorithm.end_with?("GCMKW")
          assert_equal 12, Base64.urlsafe_decode64(header.fetch("iv")).bytesize
          assert_equal 16, Base64.urlsafe_decode64(header.fetch("tag")).bytesize
          refute_includes wrapping_ivs, header.fetch("iv")
          wrapping_ivs << header.fetch("iv")
        end
        claims, = JWT.decode(decrypt_symmetric_test_token(token, key), KEY.public_key, true, algorithms: ["RS256"],
          verify_iss: true, iss: "https://op.example.test", verify_aud: true, aud: client.fetch("client_id"))
        assert_equal @account_id.to_s, claims.fetch("sub")
        assert_raises(StandardError) { decrypt_symmetric_test_token(token, "x" * bytes) }
        vectors << {algorithm: algorithm, method: method, secret: secret, token: token, issuer: "https://op.example.test", audience: client.fetch("client_id"), subject: @account_id.to_s, checked_at: Time.now.to_i}
      end
    end
    if ENV["CIBA_SYMMETRIC_EXPORT"]
      File.open(ENV.fetch("CIBA_SYMMETRIC_EXPORT"), "w", 0o600) do |file|
        file.write(JSON.generate({public_key: JWT::JWK.new(KEY.public_key).export, vectors: vectors}))
      end
    end
  end

  def decrypt_symmetric_test_token(token, key)
    parts = token.split(".")
    header = JSON.parse(Base64.urlsafe_decode64(parts.first))
    return JWE.decrypt(token, key) unless header.fetch("alg").end_with?("GCMKW")
    wrapper = OpenSSL::Cipher.new("aes-#{key.bytesize * 8}-gcm")
    wrapper.decrypt
    wrapper.key = key
    wrapper.iv = Base64.urlsafe_decode64(header.fetch("iv"))
    wrapper.auth_tag = Base64.urlsafe_decode64(header.fetch("tag"))
    wrapper.auth_data = ""
    cek = wrapper.update(Base64.urlsafe_decode64(parts[1])) + wrapper.final
    JWE::Enc.for(header.fetch("enc"), cek, Base64.urlsafe_decode64(parts[2]),
      Base64.urlsafe_decode64(parts[4])).decrypt(Base64.urlsafe_decode64(parts[3]), parts[0])
  end

  def test_ciba_symmetric_encryption_missing_secret_rolls_back
    @db.alter_table(:oauth_applications) do
      add_column :id_token_encrypted_response_alg, String
      add_column :id_token_encrypted_response_enc, String
    end
    @db[:oauth_applications].update(id_token_encrypted_response_alg: "dir", id_token_encrypted_response_enc: "A256GCM")
    @app.plugin(:rodauth) do
      ciba_id_token_encryption_enabled true
      ciba_id_token_encryption_secret { |oauth_application:| nil }
    end
    started = post("/backchannel-authentication", scope: "openid", login_hint: "customer@example.test")
    assert_equal 200, started.status, started.body
    id = JSON.parse(started.body).fetch("auth_req_id")
    approve(id)
    failed = post("/token", {grant_type: GRANT, auth_req_id: id}, "test.processing_error" => ->(_) {})
    assert_equal 500, failed.status, failed.body
    assert_equal "approved", @db[:ciba_requests].get(:status)
    assert_equal 0, @db[:oauth_grants].count
    @app.plugin(:rodauth) do
      ciba_id_token_encryption_secret { |oauth_application:| "application-secret" }
    end
    issued = post("/token", grant_type: GRANT, auth_req_id: id)
    assert_equal 200, issued.status, issued.body
    key = OpenSSL::Digest.digest("SHA256", "application-secret")
    claims, = JWT.decode(JWE.decrypt(JSON.parse(issued.body).fetch("id_token"), key), KEY.public_key, true, algorithms: ["RS256"])
    assert_equal @account_id.to_s, claims.fetch("sub")
  end
end
