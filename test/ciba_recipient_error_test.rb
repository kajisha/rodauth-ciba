# frozen_string_literal: true
require_relative "ciba_id_token_encryption_test"

class CibaIntegrationTest
  def test_ciba_recipient_selection_does_not_fall_back_from_invalid_key
    @db.alter_table(:oauth_applications) do
      add_column :id_token_encrypted_response_alg, String
      add_column :id_token_encrypted_response_enc, String
      add_column :jwks, String, text: true
    end
    @app.plugin(:rodauth) { ciba_id_token_encryption_enabled true }
    rsa = JWT::JWK.new(KEY.public_key).export.transform_keys(&:to_s)
    ec = JWT::JWK.new(OpenSSL::PKey::EC.generate("prime256v1")).export.transform_keys(&:to_s)
    x = OpenSSL::PKey.generate_key("X25519")
    okp = {"kty" => "OKP", "crv" => "X25519", "x" => Base64.urlsafe_encode64(OpenSSL::ASN1.decode(x.public_to_der).value.last.value, padding: false)}
    zero = Base64.urlsafe_encode64("\0" * 32, padding: false)
    [["RSA-OAEP-256", rsa, rsa.merge("n" => "AQ")],
      ["ECDH-ES", ec, ec.merge("x" => zero, "y" => zero)],
      ["ECDH-ES", okp, okp.merge("x" => zero)]].each do |algorithm, good, bad|
      generic = good.merge("kid" => "generic").reject { |name, _| %w[use alg].include?(name) }
      selected = good.merge("kid" => "selected", "alg" => algorithm, "use" => "enc")
      @db[:oauth_applications].update(id_token_encrypted_response_alg: algorithm, id_token_encrypted_response_enc: "A256GCM")
      [[bad.merge("kid" => "bad", "alg" => algorithm, "use" => "enc"), generic],
        [generic, selected], [selected, generic.merge("alg" => algorithm, "use" => "enc")]].each_with_index do |keys, index|
        @db[:oauth_applications].update(jwks: JSON.generate(keys: keys))
        id = accept_request
        approve(id)
        count = @db[:oauth_grants].count
        issued = poll(id, "test.processing_error" => ->(_) {})
        if index.zero?
          assert_equal 500, issued.status, issued.body
          assert_equal count, @db[:oauth_grants].count
          assert_equal "approved", @db[:ciba_requests].order(:id).last.fetch(:status)
        else
          assert_equal 200, issued.status, issued.body
          header = JSON.parse(Base64.urlsafe_decode64(JSON.parse(issued.body).fetch("id_token").split(".").first))
          assert_equal "selected", header.fetch("kid")
        end
      end
    end
  end

  def test_ciba_rsa_recipient_key_operations
    @db.alter_table(:oauth_applications) do
      add_column :id_token_encrypted_response_alg, String
      add_column :id_token_encrypted_response_enc, String
      add_column :jwks, String, text: true
    end
    @app.plugin(:rodauth) { ciba_id_token_encryption_enabled true }
    jwk = JWT::JWK.new(KEY.public_key).export
    [[nil, 200], [[], 400], [["encrypt"], 500], [["wrapKey"], 400], [["encrypt", "wrapKey"], 200]].each do |operations, status|
      key = operations.nil? ? jwk : jwk.merge(key_ops: operations)
      @db[:oauth_applications].update(id_token_encrypted_response_alg: "RSA-OAEP-256", id_token_encrypted_response_enc: "A256GCM", jwks: JSON.generate(keys: [key]))
      id = accept_request
      approve(id)
      count = @db[:oauth_grants].count
      response = poll(id, "test.processing_error" => ->(_) {})
      assert_equal status, response.status, response.body
      if status == 200
        signed = JWE.decrypt(JSON.parse(response.body).fetch("id_token"), KEY)
        claims, = JWT.decode(signed, KEY.public_key, true, algorithms: ["RS256"])
        assert_equal @account_id.to_s, claims.fetch("sub")
        assert_equal count + 1, @db[:oauth_grants].count
      else
        assert_equal status == 400 ? "invalid_client_metadata" : "server_error", JSON.parse(response.body).fetch("error")
        assert_equal count, @db[:oauth_grants].count
        assert_equal "approved", @db[:ciba_requests].order(:id).last.fetch(:status)
      end
    end
  end

  def test_ciba_encryption_missing_recipient_error_and_rollback
    enable_refresh
    @db.alter_table(:oauth_applications) do
      add_column :id_token_encrypted_response_alg, String
      add_column :id_token_encrypted_response_enc, String
      add_column :jwks, String, text: true
    end
    @app.plugin(:rodauth) { ciba_id_token_encryption_enabled true }
    rsa = JWT::JWK.new(KEY.public_key).export
    ec = JWT::JWK.new(OpenSSL::PKey::EC.generate("prime256v1")).export
    x = OpenSSL::PKey.generate_key("X25519")
    okp = {kty: "OKP", crv: "X25519", x: Base64.urlsafe_encode64(OpenSSL::ASN1.decode(x.public_to_der).value.last.value, padding: false)}
    [["RSA-OAEP-256", rsa], ["ECDH-ES", ec], ["ECDH-ES+A256KW", okp]].each do |algorithm, jwk|
      @db[:oauth_applications].update(id_token_encrypted_response_alg: algorithm, id_token_encrypted_response_enc: "A256GCM", jwks: JSON.generate(keys: []))
      started = post("/backchannel-authentication", scope: "openid offline_access", login_hint: "customer@example.test")
      assert_equal 200, started.status, started.body
      id = JSON.parse(started.body).fetch("auth_req_id")
      approve(id)
      count = @db[:oauth_grants].count
      failed = poll(id, "test.processing_error" => ->(_) {})
      assert_equal 400, failed.status, failed.body
      assert_equal "invalid_client_metadata", JSON.parse(failed.body).fetch("error")
      assert_equal "no-store", failed.headers.fetch("cache-control")
      assert_equal "approved", @db[:ciba_requests].order(:id).last.fetch(:status)
      assert_equal count, @db[:oauth_grants].count
      @db[:oauth_applications].update(jwks: JSON.generate(keys: [jwk]))
      issued = poll(id)
      assert_equal 200, issued.status, issued.body
      token = JSON.parse(issued.body).fetch("refresh_token")
      @db[:ciba_refresh_tokens].update(issued_at: Time.now.to_i - 800, expires_at: Time.now.to_i + 200)
      snapshot = @db[:ciba_refresh_tokens].order(:id).all
      count = @db[:oauth_grants].count
      @db[:oauth_applications].update(jwks: JSON.generate(keys: [jwk.merge(use: "sig")]))
      failed = refresh_with(token, {}, "test.processing_error" => ->(_) {})
      assert_equal 400, failed.status, failed.body
      assert_equal "invalid_client_metadata", JSON.parse(failed.body).fetch("error")
      assert_equal snapshot, @db[:ciba_refresh_tokens].order(:id).all
      assert_equal count, @db[:oauth_grants].count
      @db[:oauth_applications].update(jwks: JSON.generate(keys: [jwk]))
      renewed = refresh_with(token)
      assert_equal 200, renewed.status, renewed.body
      refute_equal token, JSON.parse(renewed.body).fetch("refresh_token")
    end
  end
end
