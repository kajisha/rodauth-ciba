# frozen_string_literal: true
require_relative "ciba_pairwise_test"
require_relative "ciba_refresh_test"

class CibaIntegrationTest
  def test_encryption_management_overlap_initial_opaque
    assert_encryption_management_overlap(false, false)
  end

  def test_encryption_management_overlap_initial_jwt
    assert_encryption_management_overlap(true, false)
  end

  def test_encryption_management_overlap_refresh_opaque
    assert_encryption_management_overlap(false, true)
  end

  def test_encryption_management_overlap_refresh_jwt
    assert_encryption_management_overlap(true, true)
  end

  def assert_encryption_management_overlap(jwt, refresh)
    configure_dynamic_registration
    enable_refresh
    @db.alter_table(:oauth_applications) do
      add_column :id_token_encrypted_response_alg, String
      add_column :id_token_encrypted_response_enc, String
      add_column :jwks, String, text: true
    end
    old_key, new_key = 2.times.map { OpenSSL::PKey.generate_key("X25519") }
    jwks = lambda do |key, kid|
      {"keys" => [{"kty" => "OKP", "crv" => "X25519", "kid" => kid, "use" => "enc", "alg" => "ECDH-ES+A256KW",
        "x" => Base64.urlsafe_encode64(OpenSSL::ASN1.decode(key.public_to_der).value.last.value, padding: false)}]}
    end
    @db[:oauth_applications].update(id_token_encrypted_response_alg: "ECDH-ES+A256KW", id_token_encrypted_response_enc: "A256GCM",
      jwks: JSON.generate(jwks.call(old_key, "old")))
    @app.plugin(:rodauth) do
      ciba_id_token_encryption_enabled true
      oauth_jwt_access_tokens jwt
      auth_class_eval do
        def ciba_generate_access_token(row, scopes)
          scope.env["test.pause_generation"]&.call
          super
        end
      end
    end
    started = post("/backchannel-authentication", scope: "openid offline_access", login_hint: "customer@example.test")
    id = JSON.parse(started.body).fetch("auth_req_id")
    approve(id)
    params = {grant_type: GRANT, auth_req_id: id}
    if refresh
      initial = poll(id)
      assert_equal 200, initial.status, initial.body
      params = {grant_type: "refresh_token", refresh_token: JSON.parse(initial.body).fetch("refresh_token")}
    end
    management_token, credentials = auth.send(:ciba_new_registration_credentials)
    @db[:oauth_applications].where(id: @client_id).update(credentials)
    replacement = registration_params.merge("client_id" => "support", "grant_types" => [GRANT, "refresh_token"], "scope" => "openid offline_access",
      "id_token_encrypted_response_alg" => "ECDH-ES+A256KW", "id_token_encrypted_response_enc" => "A256GCM", "jwks" => jwks.call(new_key, "new"))
    update = lambda do
      Rack::MockRequest.new(@app).put("https://op.example.test/register/support",
        "HTTP_AUTHORIZATION" => "Bearer #{management_token}", "CONTENT_TYPE" => "application/json", input: JSON.generate(replacement))
    end
    issue = ->(env = {}) { post("/token", params, env) }
    if @db.database_type == :sqlite
      issued, updated = parallel_decisions { |i| i.zero? ? issue.call : update.call }
      issued = issue.call if issued.status == 503
      updated = update.call if updated.status == 503
    else
      reached, release = Queue.new, Queue.new
      # Initial issuance takes additional locks when consuming the request.
      # Pause after the client snapshot but before that update. Refresh has a
      # second client validation, so pause after it and before token generation.
      hook = refresh ? "test.pause_generation" : "test.before_issue"
      worker = Thread.new { issue.call(hook => -> { reached << true; Timeout.timeout(10) { release.pop } }) }
      begin
        Timeout.timeout(10) { reached.pop }
        updated = Timeout.timeout(10) { update.call }
        release << true
        issued = Timeout.timeout(10) { worker.value }
      ensure
        release << true
        worker.kill if worker.alive?
        worker.join
      end
    end
    assert_equal 200, updated.status, updated.body
    assert_equal 200, issued.status, issued.body
    tokens = JSON.parse(issued.body)
    verify = lambda do |value, expected|
      parts = value.fetch("id_token").split(".", -1)
      header = JSON.parse(Base64.urlsafe_decode64(parts[0]))
      kid = header.fetch("kid")
      assert_includes expected, kid
      key = {"old" => old_key, "new" => new_key}.fetch(kid)
      shared = key.derive(auth.send(:ciba_ecdh_public_key, header.fetch("epk")))
      derived = auth.send(:ciba_ecdh_derived_key, shared, "ECDH-ES+A256KW", "A256GCM")
      cek = JWE::Alg.decrypt_cek("A256KW", derived, Base64.urlsafe_decode64(parts[1]))
      signed = JWE::Enc.for("A256GCM", cek, Base64.urlsafe_decode64(parts[2]), Base64.urlsafe_decode64(parts[4]))
        .decrypt(Base64.urlsafe_decode64(parts[3]), parts[0])
      claims, = JWT.decode(signed, KEY.public_key, true, algorithms: ["RS256"], verify_iss: true, iss: "https://op.example.test", verify_aud: true, aud: "support")
      assert_equal @account_id.to_s, claims.fetch("sub")
    end
    verify.call(tokens, @db.database_type == :sqlite ? %w[old new] : ["old"])
    assert_equal(refresh ? 2 : 1, @db[:oauth_grants].count)
    assert_equal "consumed", @db[:ciba_requests].get(:status)
    subsequent = refresh_with(tokens.fetch("refresh_token"))
    assert_equal 200, subsequent.status, subsequent.body
    verify.call(JSON.parse(subsequent.body), ["new"])
  end
end
