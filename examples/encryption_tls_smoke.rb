# frozen_string_literal: true
module CibaEncryptionTlsSmoke
  def self.run(server, untrusted:)
    requests = []
    state = {keys: [], status: 200, cache: "max-age=3600", body: nil}
    server.mount_proc("/encryption-jwks") do |request, response|
      requests << [request.request_method, request["authorization"]]
      response.status = state[:status]
      response["Content-Type"] = "application/json"
      response["Cache-Control"] = state[:cache]
      response.body = state[:body] || JSON.generate(keys: state[:keys])
    end
    endpoint = "https://127.0.0.1:#{server.config[:Port]}/encryption-jwks"
    [false, true].product([nil, "P-256", "X25519"]).each do |jwt, curve|
      algorithm = curve == "X25519" ? "ECDH-ES+A256KW" : curve ? "ECDH-ES" : "RSA-OAEP-256"
      database = Sequel.sqlite
      begin
        CibaDemo.create_schema(database)
        Rodauth::CibaSupport::Schema.create_refresh_tokens(database)
        database.alter_table(:oauth_applications) do
          add_column :jwks_uri, String
          add_column :id_token_encrypted_response_alg, String
          add_column :id_token_encrypted_response_enc, String
        end
        database[:oauth_applications].update(jwks_uri: endpoint, scopes: "openid offline_access",
          grant_types: "#{Rodauth::CibaSupport::GRANT_TYPE} refresh_token",
          id_token_encrypted_response_alg: algorithm, id_token_encrypted_response_enc: "A256GCM")
        old_key, new_key = 2.times.map do
          curve == "X25519" ? OpenSSL::PKey.generate_key("X25519") : curve ? OpenSSL::PKey::EC.generate("prime256v1") : OpenSSL::PKey::RSA.generate(2048)
        end
        jwk = lambda do |key, kid|
          public_key = curve == "X25519" ?
            {kty: "OKP", crv: curve, x: Base64.urlsafe_encode64(OpenSSL::ASN1.decode(key.public_to_der).value.last.value, padding: false)} :
            JWT::JWK.new(curve ? key : key.public_key).export
          public_key.merge(use: "enc", alg: algorithm, kid: kid)
        end
        state.merge!(keys: [jwk.call(old_key, "old")], status: 200, cache: "max-age=3600", body: nil)
        app = CibaDemo.build(database)
        app.plugin(:rodauth) do
          oauth_jwt_access_tokens jwt
          ciba_id_token_encryption_enabled true
          ciba_refresh_tokens_enabled true
          oauth_application_scopes %w[openid offline_access]
          report_ciba_processing_error { |_error| }
        end
        issuer = "http://127.0.0.1:9292"
        http = Rack::MockRequest.new(app)
        metadata = JSON.parse(http.get("#{issuer}/.well-known/openid-configuration").body)
        auth = app.new(Rack::MockRequest.env_for(issuer)).rodauth
        auth.send(:http_request_cache).uncache(URI(endpoint))
        headers = {"HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64('demo-client:demo-secret')}"}
        post = ->(path, params) { http.post(path, headers.merge(params: params)) }
        started = post.call(metadata.fetch("backchannel_authentication_endpoint"), scope: "openid offline_access", login_hint: "customer@example.test")
        raise started.body unless started.status == 200
        id = JSON.parse(started.body).fetch("auth_req_id")
        row = database[:ciba_requests].first
        auth.approve_ciba_request(row[:id], account_id: row[:account_id])
        poll = -> { post.call(metadata.fetch("token_endpoint"), grant_type: Rodauth::CibaSupport::GRANT_TYPE, auth_req_id: id) }
        before = requests.length
        denied = poll.call
        raise "default encryption destination guard bypassed: #{denied.status}" unless denied.status == 500 && requests.length == before && database[:oauth_grants].count.zero?
        raise "failed lookup consumed request" unless database[:ciba_requests].get(:status) == "approved"
        app.plugin(:rodauth) { ciba_http_address_allowed? { |address| address == "127.0.0.1" } }
        issued = poll.call
        if untrusted
          raise "untrusted encryption key TLS accepted" unless issued.status == 500 && requests.length == before && database[:oauth_grants].count.zero?
          raise "untrusted lookup consumed request" unless database[:ciba_requests].get(:status) == "approved"
          puts "PASS: installed HTTPS #{curve || "RSA"}/#{algorithm} encryption keys reject untrusted TLS, #{jwt ? 'JWT' : 'opaque'} mode"
          next
        end
        verify = lambda do |response, key, kid|
          raise response.body unless response.status == 200
          tokens = JSON.parse(response.body)
          encrypted = tokens.fetch("id_token")
          raise "wrong recipient kid" unless JSON.parse(Base64.urlsafe_decode64(encrypted.split('.').first)).fetch("kid") == kid
          signed = if curve
            parts = encrypted.split(".", -1)
            header = JSON.parse(Base64.urlsafe_decode64(parts[0]))
            shared = key.derive(auth.send(:ciba_ecdh_public_key, header.fetch("epk")))
            derived = auth.send(:ciba_ecdh_derived_key, shared, algorithm, "A256GCM")
            cek = algorithm == "ECDH-ES" ? derived : JWE::Alg.decrypt_cek("A256KW", derived, Base64.urlsafe_decode64(parts[1]))
            JWE::Enc.for("A256GCM", cek, Base64.urlsafe_decode64(parts[2]), Base64.urlsafe_decode64(parts[4]))
              .decrypt(Base64.urlsafe_decode64(parts[3]), parts[0])
          else
            JWE.decrypt(encrypted, key)
          end
          public_keys = JSON.parse(http.get(metadata.fetch("jwks_uri")).body)
          claims, = JWT.decode(signed, nil, true, jwks: public_keys, algorithms: ["RS256"],
            verify_iss: true, iss: issuer, verify_aud: true, aud: "demo-client")
          raise "wrong subject" unless claims.fetch("sub") == row[:account_id].to_s
          tokens
        end
        tokens = verify.call(issued, old_key, "old")
        refresh = tokens.fetch("refresh_token")
        renew = -> { post.call(metadata.fetch("token_endpoint"), grant_type: "refresh_token", refresh_token: refresh) }
        state[:keys] = [jwk.call(new_key, "new")]
        cached_requests = requests.length
        verify.call(renew.call, old_key, "old")
        raise "live cache unexpectedly refreshed" unless requests.length == cached_requests
        auth.send(:http_request_cache).uncache(URI(endpoint))
        state[:cache] = "no-cache"
        verify.call(renew.call, new_key, "new")
        source = database[:ciba_refresh_tokens].where(token_digest: Digest::SHA256.hexdigest(refresh))
        source.update(issued_at: Time.now.to_i - 800, expires_at: Time.now.to_i + 200)
        count = database[:oauth_grants].count
        auth.send(:http_request_cache).uncache(URI(endpoint))
        [[503, nil], [200, "invalid JSON"]].each do |status, body|
          state[:status], state[:body] = status, body
          failed = renew.call
          raise "recipient failure returned token" unless failed.status == 500
          raise "recipient failure consumed refresh" unless source.get(:consumed_at).nil? && database[:oauth_grants].count == count && database[:ciba_refresh_tokens].count == 1
        end
        state[:status], state[:body] = 200, nil
        recovered = verify.call(renew.call, new_key, "new")
        raise "refresh did not rotate after recovery" if recovered.fetch("refresh_token") == refresh || source.get(:consumed_at).nil?
        raise "JWKS credential forwarded" unless requests.drop(before).all? { |entry| entry == ["GET", nil] }
        puts "PASS: installed HTTPS #{curve || "RSA"}/#{algorithm} encryption key cache/rotation, 503/malformed rollback and recovery, #{jwt ? 'JWT' : 'opaque'} mode"
      ensure
        database.disconnect
      end
    end
  end
end
