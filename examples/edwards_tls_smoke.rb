# frozen_string_literal: true
# Called by the installed ping fixture with its real, verified HTTPS server.
module CibaEdwardsTlsSmoke
  def self.run(server, untrusted:)
    public_keys = []
    requests = []
    server.mount_proc("/edwards-jwks") do |request, response|
      requests << [request.request_method, request["authorization"]]
      response["Content-Type"] = "application/json"
      response["Cache-Control"] = "no-cache"
      response.body = JSON.generate(keys: public_keys)
    end
    endpoint = "https://127.0.0.1:#{server.config[:Port]}/edwards-jwks"
    [false, true].each do |jwt|
      %w[Ed25519 EdDSA].each do |algorithm|
        database = Sequel.sqlite
        begin
          CibaDemo.create_schema(database)
          Rodauth::CibaSupport::Schema.create_client_assertions(database)
          database.alter_table(:oauth_applications) do
            add_column :jwks_uri, String
            add_column :token_endpoint_auth_signing_alg, String
          end
          database[:oauth_applications].update(token_endpoint_auth_method: "private_key_jwt",
            token_endpoint_auth_signing_alg: algorithm, jwks_uri: endpoint)
          key = OpenSSL::PKey.generate_key("ED25519")
          raw = OpenSSL::ASN1.decode(key.public_to_der).value.last.value
          public_keys = [{kty: "OKP", crv: "Ed25519", x: Base64.urlsafe_encode64(raw, padding: false), alg: algorithm, kid: "client", use: "sig"}]
          app = CibaDemo.build(database)
          app.plugin(:rodauth) do
            enable :oauth_jwt_bearer_grant
            ciba_client_assertion_signing_algorithms %w[Ed25519 EdDSA]
            oauth_jwt_access_tokens jwt
          end
          app.new(Rack::MockRequest.env_for("http://127.0.0.1:9292")).rodauth.send(:http_request_cache).uncache(URI(endpoint))
          http = Rack::MockRequest.new(app)
          issuer = "http://127.0.0.1:9292"
          metadata = JSON.parse(http.get("#{issuer}/.well-known/openid-configuration").body)
          authentication = lambda do
            parts = [{alg: algorithm, kid: "client"}, {iss: "demo-client", sub: "demo-client", aud: issuer,
              exp: Time.now.to_i + 60, jti: SecureRandom.uuid}].map { |part| Base64.urlsafe_encode64(JSON.generate(part), padding: false) }
            token = (parts + [Base64.urlsafe_encode64(key.sign(nil, parts.join(".")), padding: false)]).join(".")
            {client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: token}
          end
          start = -> { http.post(metadata.fetch("backchannel_authentication_endpoint"), params: authentication.call.merge(scope: "openid", login_hint: "customer@example.test")) }
          before = requests.length
          raise "default loopback guard bypassed" unless start.call.status == 401 && requests.length == before
          app.plugin(:rodauth) { ciba_http_address_allowed? { |address| address == "127.0.0.1" } }
          accepted = start.call
          if untrusted
            raise "untrusted JWKS accepted or reached handler" unless accepted.status == 401 && requests.length == before && database[:ciba_requests].count.zero?
            puts "PASS: installed #{algorithm} HTTPS client JWKS rejects untrusted TLS before key retrieval, #{jwt ? 'JWT' : 'opaque'} mode"
            next
          end
          raise accepted.body unless accepted.status == 200
          id = JSON.parse(accepted.body).fetch("auth_req_id")
          row = database[:ciba_requests].first
          app.new(Rack::MockRequest.env_for(issuer)).rodauth.approve_ciba_request(row[:id], account_id: row[:account_id])
          issued = http.post(metadata.fetch("token_endpoint"), params: authentication.call.merge(grant_type: Rodauth::CibaSupport::GRANT_TYPE, auth_req_id: id))
          raise issued.body unless issued.status == 200
          token = JSON.parse(issued.body).fetch("id_token")
          keys = JSON.parse(http.get(metadata.fetch("jwks_uri")).body)
          claims, = JWT.decode(token, nil, true, jwks: keys, algorithms: ["RS256"], verify_iss: true, iss: issuer, verify_aud: true, aud: "demo-client")
          raise "wrong subject" unless claims.fetch("sub") == row[:account_id].to_s
          raise "JWKS credential forwarding or missing fetch" unless requests.length >= before + 2 && requests.drop(before).all? { |entry| entry == ["GET", nil] }
          puts "PASS: installed #{algorithm} HTTPS client JWKS, both endpoint authentication, verified ID Token, #{jwt ? 'JWT' : 'opaque'} access token"
        ensure
          database.disconnect
        end
      end
    end
  end
end
