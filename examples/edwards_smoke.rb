# frozen_string_literal: true
# Uses public Node/jose-generated vectors from the installed artifact.
require "rack/mock"
require "json"
require_relative "demo_app"
fixture = JSON.parse(File.read(File.join(__dir__, "fixtures/edwards-requests.json")))
[false, true].each do |jwt|
  database = Sequel.sqlite
  begin
    CibaDemo.create_schema(database)
    Rodauth::CibaSupport::Schema.add_signed_requests(database)
    database.alter_table(:oauth_applications) { add_column :jwks, String, text: true }
    database[:oauth_applications].update(client_id: "support")
    application = CibaDemo.build(database)
    application.plugin(:rodauth) do
      base_url "https://op.example.test"
      authorization_server_url "https://op.example.test"
      ciba_require_tls true
      ciba_now { fixture.fetch("now") }
      oauth_jwt_access_tokens jwt
      ciba_request_signing_algorithms %w[Ed25519 EdDSA]
    end
    http = Rack::MockRequest.new(application)
    issuer = "https://op.example.test"
    metadata = JSON.parse(http.get("#{issuer}/.well-known/openid-configuration").body)
    headers = {"HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64('support:demo-secret')}"}
    fixture.fetch("vectors").each do |vector|
      database[:oauth_applications].update(backchannel_authentication_request_signing_alg: vector.fetch("alg"),
        jwks: JSON.generate(keys: [vector.fetch("jwk")]))
      started = http.post(metadata.fetch("backchannel_authentication_endpoint"), headers.merge(params: {request: vector.fetch("token")}))
      raise started.body unless started.status == 200
      id = JSON.parse(started.body).fetch("auth_req_id")
      instance = application.new(Rack::MockRequest.env_for(issuer)).rodauth
      row = database[:ciba_requests].order(:id).last
      instance.approve_ciba_request(row[:id], account_id: row[:account_id])
      issued = http.post(metadata.fetch("token_endpoint"), headers.merge(params: {grant_type: Rodauth::CibaSupport::GRANT_TYPE, auth_req_id: id}))
      raise issued.body unless issued.status == 200
      tokens = JSON.parse(issued.body)
      keys = JSON.parse(http.get(metadata.fetch("jwks_uri")).body)
      claims, = JWT.decode(tokens.fetch("id_token"), nil, true, jwks: keys, algorithms: ["RS256"],
        verify_iss: true, iss: issuer, verify_aud: true, aud: "support")
      raise "wrong subject" unless claims.fetch("sub") == row[:account_id].to_s
      raise "missing access token" unless tokens.fetch("access_token").is_a?(String)
      puts "PASS: installed #{vector.fetch('alg')} Node/jose vector, #{jwt ? 'JWT' : 'opaque'} access token, verified ID Token"
    end
    Rodauth::CibaSupport::Schema.create_client_assertions(database)
    database.alter_table(:oauth_applications) { add_column :token_endpoint_auth_signing_alg, String }
    application.plugin(:rodauth) do
      enable :oauth_jwt_bearer_grant
      ciba_client_assertion_signing_algorithms %w[Ed25519 EdDSA]
    end
    key = OpenSSL::PKey.generate_key("ED25519")
    raw = OpenSSL::ASN1.decode(key.public_to_der).value.last.value
    jwk = {kty: "OKP", crv: "Ed25519", x: Base64.urlsafe_encode64(raw, padding: false), kid: "auth", use: "sig"}
    %w[Ed25519 EdDSA].each do |algorithm|
      database[:oauth_applications].update(backchannel_authentication_request_signing_alg: nil,
        token_endpoint_auth_method: "private_key_jwt", token_endpoint_auth_signing_alg: algorithm,
        jwks: JSON.generate(keys: [jwk.merge(alg: algorithm)]))
      authentication = lambda do
        parts = [{alg: algorithm, kid: "auth"}, {iss: "support", sub: "support", aud: issuer,
          exp: Time.now.to_i + 60, jti: SecureRandom.uuid}].map { |part| Base64.urlsafe_encode64(JSON.generate(part), padding: false) }
        token = (parts + [Base64.urlsafe_encode64(key.sign(nil, parts.join(".")), padding: false)]).join(".")
        {client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: token}
      end
      start_auth = authentication.call
      started = http.post(metadata.fetch("backchannel_authentication_endpoint"), params: start_auth.merge(scope: "openid", login_hint: "customer@example.test"))
      raise started.body unless started.status == 200
      replay = http.post(metadata.fetch("backchannel_authentication_endpoint"), params: start_auth.merge(scope: "openid", login_hint: "customer@example.test"))
      raise "assertion replay accepted" unless replay.status == 401
      id = JSON.parse(started.body).fetch("auth_req_id")
      instance = application.new(Rack::MockRequest.env_for(issuer)).rodauth
      row = database[:ciba_requests].order(:id).last
      instance.approve_ciba_request(row[:id], account_id: row[:account_id])
      issued = http.post(metadata.fetch("token_endpoint"), params: authentication.call.merge(grant_type: Rodauth::CibaSupport::GRANT_TYPE, auth_req_id: id))
      raise issued.body unless issued.status == 200
      tokens = JSON.parse(issued.body)
      keys = JSON.parse(http.get(metadata.fetch("jwks_uri")).body)
      claims, = JWT.decode(tokens.fetch("id_token"), nil, true, jwks: keys, algorithms: ["RS256"],
        verify_iss: true, iss: issuer, verify_aud: true, aud: "support")
      raise "wrong subject" unless claims.fetch("sub") == row[:account_id].to_s
      raise "missing access token" unless tokens.fetch("access_token").is_a?(String)
      puts "PASS: installed #{algorithm} client authentication at both endpoints, replay rejected, #{jwt ? 'JWT' : 'opaque'} access token, verified ID Token"
    end
  ensure
    database.disconnect
  end
end
