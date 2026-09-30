# frozen_string_literal: true
require_relative "ciba_encryption_remote_test"

class CibaIntegrationTest
  def test_ecdh_remote_ec_opaque
    assert_ecdh_remote_flow(false, "P-256", "ECDH-ES")
  end

  def test_ecdh_remote_ec_jwt
    assert_ecdh_remote_flow(true, "P-256", "ECDH-ES")
  end

  def test_ecdh_remote_okp_opaque
    assert_ecdh_remote_flow(false, "X25519", "ECDH-ES+A256KW")
  end

  def test_ecdh_remote_okp_jwt
    assert_ecdh_remote_flow(true, "X25519", "ECDH-ES+A256KW")
  end

  def test_ecdh_real_cache_expiry_ec
    assert_ecdh_remote_flow(false, "P-256", "ECDH-ES", minimum_expiry: true)
  end

  def test_ecdh_real_cache_expiry_okp
    assert_ecdh_remote_flow(false, "X25519", "ECDH-ES+A256KW", minimum_expiry: true)
  end

  def test_ecdh_publisher_authorized_stale_refresh
    assert_ecdh_remote_flow(false, "X25519", "ECDH-ES+A256KW", stale: true)
  end

  def assert_ecdh_remote_flow(jwt, curve, algorithm, minimum_expiry: false, stale: false)
    with_client_jwks_server do |state, uri, _server|
      enable_refresh
      @db.alter_table(:oauth_applications) do
        add_column :id_token_encrypted_response_alg, String
        add_column :id_token_encrypted_response_enc, String
      end
      @db[:oauth_applications].update(backchannel_authentication_request_signing_alg: nil,
        id_token_encrypted_response_alg: algorithm, id_token_encrypted_response_enc: "A256GCM")
      @app.plugin(:rodauth) do
        ciba_id_token_encryption_enabled true
        oauth_jwt_access_tokens jwt
      end
      old_key, new_key = 2.times.map do
        curve == "X25519" ? OpenSSL::PKey.generate_key("X25519") : OpenSSL::PKey::EC.generate("prime256v1")
      end
      public_jwk = lambda do |key|
        jwk = if curve == "X25519"
          {kty: "OKP", crv: curve, x: Base64.urlsafe_encode64(OpenSSL::ASN1.decode(key.public_to_der).value.last.value, padding: false)}
        else
          JWT::JWK.new(key).export
        end
        jwk.merge(alg: algorithm, use: "enc")
      end
      verify = lambda do |tokens, key|
        parts = tokens.fetch("id_token").split(".", -1)
        header = JSON.parse(Base64.urlsafe_decode64(parts[0]))
        shared = key.derive(auth.send(:ciba_ecdh_public_key, header.fetch("epk")))
        derived = auth.send(:ciba_ecdh_derived_key, shared, algorithm, "A256GCM")
        cek = algorithm == "ECDH-ES" ? derived : JWE::Alg.decrypt_cek("A256KW", derived, Base64.urlsafe_decode64(parts[1]))
        signed = JWE::Enc.for("A256GCM", cek, Base64.urlsafe_decode64(parts[2]), Base64.urlsafe_decode64(parts[4]))
          .decrypt(Base64.urlsafe_decode64(parts[3]), parts[0])
        claims, = JWT.decode(signed, KEY.public_key, true, algorithms: ["RS256"],
          verify_iss: true, iss: "https://op.example.test", verify_aud: true, aud: "support")
        assert_equal @account_id.to_s, claims.fetch("sub")
      end
      state[:keys] = [public_jwk.call(old_key)]
      state[:status] = 503
      started = post("/backchannel-authentication", scope: "openid offline_access", login_hint: "customer@example.test")
      assert_equal 200, started.status, started.body
      id = JSON.parse(started.body).fetch("auth_req_id")
      approve(id)
      failed = poll(id, "test.processing_error" => ->(_) {})
      assert_equal 500, failed.status, failed.body
      assert_equal "approved", @db[:ciba_requests].get(:status)
      assert_equal 0, @db[:oauth_grants].count
      state[:status], state[:cache] = 200, minimum_expiry ? "max-age=2" : "max-age=3600"
      state[:cache] = "max-age=3600, stale-if-error=60" if stale
      issued = poll(id)
      assert_equal 200, issued.status, issued.body
      tokens = JSON.parse(issued.body)
      verify.call(tokens, old_key)
      if stale
        cache = auth.send(:http_request_cache)
        clock = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        cache.define_singleton_method(:now) { clock }
        clock += 3600
        state[:status] = 503
        renewed = refresh_with(tokens.fetch("refresh_token"))
        assert_equal 200, renewed.status, renewed.body
        tokens = JSON.parse(renewed.body)
        verify.call(tokens, old_key)
        clock += 60
        snapshot = @db[:ciba_refresh_tokens].order(:id).all
        failed = refresh_with(tokens.fetch("refresh_token"), {}, "test.processing_error" => ->(_) {})
        assert_equal 500, failed.status, failed.body
        assert_equal snapshot, @db[:ciba_refresh_tokens].order(:id).all
        state[:status] = 200
        renewed = refresh_with(tokens.fetch("refresh_token"))
        assert_equal 200, renewed.status, renewed.body
        tokens = JSON.parse(renewed.body)
      end
      requests = state[:requests]
      state[:keys] = [public_jwk.call(new_key)]
      renewed = refresh_with(tokens.fetch("refresh_token"))
      assert_equal 200, renewed.status, renewed.body
      tokens = JSON.parse(renewed.body)
      verify.call(tokens, old_key)
      assert_equal requests, state[:requests]
      if minimum_expiry
        sleep 3
      else
        auth.send(:http_request_cache).uncache(URI(uri))
      end
      renewed = refresh_with(tokens.fetch("refresh_token"))
      assert_equal 200, renewed.status, renewed.body
      tokens = JSON.parse(renewed.body)
      verify.call(tokens, new_key)
      assert_raises(StandardError) { verify.call(tokens, old_key) }
      assert_equal requests + 1, state[:requests]
      auth.send(:http_request_cache).uncache(URI(uri))
      @db[:ciba_refresh_tokens].update(issued_at: Time.now.to_i - 800, expires_at: Time.now.to_i + 200)
      snapshot = @db[:ciba_refresh_tokens].order(:id).all
      grants = @db[:oauth_grants].count
      [[503, nil], [200, "not json"]].each do |status, body|
        state[:status], state[:body] = status, body
        2.times do
          requests = state[:requests]
          failed = refresh_with(tokens.fetch("refresh_token"), {}, "test.processing_error" => ->(_) {})
          assert_equal 500, failed.status, failed.body
          assert_equal requests + 1, state[:requests]
          assert_equal snapshot, @db[:ciba_refresh_tokens].order(:id).all
          assert_equal grants, @db[:oauth_grants].count
        end
      end
      state[:status], state[:body] = 200, nil
      renewed = refresh_with(tokens.fetch("refresh_token"))
      assert_equal 200, renewed.status, renewed.body
      verify.call(JSON.parse(renewed.body), new_key)
      refute_equal tokens.fetch("refresh_token"), JSON.parse(renewed.body).fetch("refresh_token")
    end
  end
end
