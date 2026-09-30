# frozen_string_literal: true
require_relative "ciba_mtls_test"
require_relative "ciba_remote_jwks_test"

class CibaIntegrationTest
  def test_ciba_mtls_remote_certificate_rotation_and_failure
    with_client_jwks_server do |state, uri, _server|
      key = REQUEST_KEY
      old_certificate = mtls_certificate(key, 1)
      new_certificate = mtls_certificate(key, 2)
      jwk = ->(cert) { JWT::JWK.new(key.public_key).export.merge(x5c: [Base64.strict_encode64(cert.to_der)]) }
      @db.alter_table(:oauth_grants) { add_column :certificate_thumbprint, String }
      @db[:oauth_applications].update(token_endpoint_auth_method: "self_signed_tls_client_auth",
        backchannel_authentication_request_signing_alg: nil)
      @app.plugin(:rodauth) do
        enable :oauth_tls_client_auth
        ciba_tls_client_certificate { scope.env["test.tls_certificate"] }
      end
      state[:cache] = "max-age=3600"
      state[:keys] = [jwk.call(old_certificate)]
      start = lambda do |cert|
        post("/backchannel-authentication", {client_id: "support", scope: "openid", login_hint: "customer@example.test"},
          "HTTP_AUTHORIZATION" => nil, "test.tls_certificate" => cert)
      end
      assert_equal 200, start.call(old_certificate).status
      assert_equal 1, state[:requests]
      state[:keys] = [jwk.call(new_certificate)]
      assert_equal 401, start.call(new_certificate).status
      assert_equal 200, start.call(old_certificate).status
      assert_equal 1, state[:requests]
      # Force cache expiry without wall-clock sleeps; never accept a key miss
      # as permission to fetch arbitrary certificate/JWK header locations.
      auth.send(:http_request_cache).uncache(URI(uri))
      assert_equal 200, start.call(new_certificate).status
      assert_equal 401, start.call(old_certificate).status
      assert_equal 2, state[:requests]
      count = @db[:ciba_requests].count
      [["not json", 400, "invalid_client_metadata"], ['{"keys":[]}', 401, "invalid_client"],
        ['{"keys":{}}', 400, "invalid_client_metadata"]].each do |body, status, error|
        auth.send(:http_request_cache).uncache(URI(uri))
        state[:body] = body
        response = start.call(new_certificate)
        assert_equal status, response.status, response.body
        assert_equal error, JSON.parse(response.body)["error"]
      end
      auth.send(:http_request_cache).uncache(URI(uri))
      state[:status] = 503
      response = start.call(new_certificate)
      assert_equal 400, response.status, response.body
      assert_equal "invalid_client_metadata", JSON.parse(response.body)["error"]
      hits = state[:requests]
      assert_equal 400, start.call(new_certificate).status
      assert_equal hits + 1, state[:requests]
      assert_equal count, @db[:ciba_requests].count
      @app.plugin(:rodauth) { ciba_http_address_allowed? { |_address| false } }
      hits = state[:requests]
      assert_equal 400, start.call(new_certificate).status
      assert_equal hits, state[:requests]
      assert_equal count, @db[:ciba_requests].count
      @app.plugin(:rodauth) { ciba_http_address_allowed? { |address| address == "127.0.0.1" } }
      state[:status] = 200
      state[:body] = nil
      assert_equal 200, start.call(new_certificate).status
    end
  end
end
