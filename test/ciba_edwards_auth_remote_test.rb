# frozen_string_literal: true
require_relative "ciba_remote_jwks_test"

class CibaIntegrationTest
  def test_edwards_client_authentication_remote_rotation_failure_and_ordinary_grant
    with_client_jwks_server do |state, uri, _server|
      @db.alter_table(:oauth_applications) { add_column :token_endpoint_auth_signing_alg, String }
      @db[:oauth_applications].update(token_endpoint_auth_method: "private_key_jwt",
        backchannel_authentication_request_signing_alg: nil)
      @app.plugin(:rodauth) do
        enable :oauth_jwt_bearer_grant
        ciba_client_assertion_signing_algorithms %w[Ed25519 EdDSA]
      end
      %w[Ed25519 EdDSA].each do |algorithm|
        old_key, new_key = 2.times.map { OpenSSL::PKey.generate_key("ED25519") }
        jwk = lambda do |key|
          raw = OpenSSL::ASN1.decode(key.public_to_der).value.last.value
          {kty: "OKP", crv: "Ed25519", x: Base64.urlsafe_encode64(raw, padding: false), alg: algorithm, use: "sig", kid: "rotating"}
        end
        params = lambda do |key, audience = "https://op.example.test"|
          parts = [{alg: algorithm, kid: "rotating"}, {iss: "support", sub: "support", aud: audience,
            exp: Time.now.to_i + 60, jti: SecureRandom.uuid}].map { |part| Base64.urlsafe_encode64(JSON.generate(part), padding: false) }
          token = (parts + [Base64.urlsafe_encode64(key.sign(nil, parts.join(".")), padding: false)]).join(".")
          {client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: token}
        end
        start = lambda do |key|
          post("/backchannel-authentication", params.call(key).merge(scope: "openid", login_hint: "customer@example.test"), "HTTP_AUTHORIZATION" => nil)
        end
        @db[:oauth_applications].update(token_endpoint_auth_signing_alg: algorithm)
        auth.send(:http_request_cache).uncache(URI(uri))
        state[:keys], state[:cache], state[:status], state[:body] = [jwk.call(old_key)], "max-age=3600", 200, nil
        before_fetch = state[:requests]
        accepted = start.call(old_key)
        assert_equal 200, accepted.status, accepted.body
        id = JSON.parse(accepted.body).fetch("auth_req_id")
        approve(id)
        assert_equal before_fetch + 1, state[:requests]
        state[:keys] = [jwk.call(new_key)]
        assert_equal 401, start.call(new_key).status
        assert_equal 200, start.call(old_key).status
        assert_equal before_fetch + 1, state[:requests], "live cache should retain the old key"
        auth.send(:http_request_cache).uncache(URI(uri))
        state[:cache] = "no-cache"
        assert_equal 200, start.call(new_key).status
        assert_equal 401, start.call(old_key).status
        count = @db[:ciba_requests].count
        auth.send(:http_request_cache).uncache(URI(uri))
        state[:status] = 503
        assert_equal 401, start.call(new_key).status
        assert_equal count, @db[:ciba_requests].count
        rejected = post("/token", params.call(new_key).merge(grant_type: GRANT, auth_req_id: id), "HTTP_AUTHORIZATION" => nil)
        assert_equal 401, rejected.status
        assert_equal "approved", @db[:ciba_requests].where(auth_req_id_digest: Digest::SHA256.hexdigest(id)).get(:status)
        state[:status] = 200
        state[:body] = "not json"
        assert_equal 401, start.call(new_key).status
        state[:body] = nil
        issued = post("/token", params.call(new_key).merge(grant_type: GRANT, auth_req_id: id), "HTTP_AUTHORIZATION" => nil)
        assert_equal 200, issued.status, issued.body
        assert_equal @account_id.to_s, decode_id_token(issued).last.fetch("sub")
        # A CIBA-capable client can also authenticate an ordinary upstream code grant.
        @db[:oauth_grants].insert(oauth_application_id: @client_id, account_id: @account_id,
          type: "authorization_code", code: "edwards-code-#{algorithm}", scopes: "openid", expires_in: Time.now + 60,
          redirect_uri: "https://rp.example.test/callback")
        ordinary = post("/token", params.call(new_key, "https://op.example.test/token").merge(grant_type: "authorization_code",
          code: "edwards-code-#{algorithm}", redirect_uri: "https://rp.example.test/callback"), "HTTP_AUTHORIZATION" => nil)
        assert_equal 200, ordinary.status, ordinary.body
      end
    end
  end
end
