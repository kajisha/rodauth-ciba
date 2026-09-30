# frozen_string_literal: true
require "rack/mock"
require "json"
require_relative "demo_app"

[false, true].each do |jwt|
  database = Sequel.sqlite
  begin
    CibaDemo.create_schema(database)
    Rodauth::CibaSupport::Schema.create_refresh_tokens(database)
    database.alter_table(:oauth_applications) do
      add_column :id_token_signed_response_alg, String
      add_column :id_token_encrypted_response_alg, String
      add_column :id_token_encrypted_response_enc, String
      add_column :jwks, String, text: true
    end
    recipient = OpenSSL::PKey::RSA.generate(2048)
    edwards = OpenSSL::PKey.generate_key("ED25519")
    public_recipient = JWT::JWK.new(recipient.public_key).export.merge(use: "enc", alg: "RSA-OAEP-256", kid: "recipient")
    database[:oauth_applications].update(scopes: "openid offline_access",
      grant_types: "#{Rodauth::CibaSupport::GRANT_TYPE} refresh_token",
      id_token_encrypted_response_alg: "RSA-OAEP-256", id_token_encrypted_response_enc: "A256GCM",
      jwks: JSON.generate(keys: [public_recipient]))
    application = CibaDemo.build(database)
    application.plugin(:rodauth) do
      base_url "https://op.example.test"
      authorization_server_url "https://op.example.test"
      ciba_require_tls true
      oauth_jwt_access_tokens jwt
      ciba_refresh_tokens_enabled true
      oauth_application_scopes %w[openid offline_access]
      ciba_id_token_encryption_enabled true
      ciba_id_token_signing_keys("Ed25519" => edwards, "EdDSA" => edwards)
    end
    http = Rack::MockRequest.new(application)
    issuer = "https://op.example.test"
    metadata = JSON.parse(http.get("#{issuer}/.well-known/openid-configuration").body)
    headers = {"HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64('demo-client:demo-secret')}"}
    post = lambda do |endpoint, params|
      response = http.post(endpoint, headers.merge(params: params))
      raise response.body unless response.status == 200
      JSON.parse(response.body)
    end
    %w[RS256 Ed25519 EdDSA].each do |algorithm|
      database[:oauth_applications].update(id_token_signed_response_alg: algorithm)
      started = post.call(metadata.fetch("backchannel_authentication_endpoint"), scope: "openid offline_access", login_hint: "customer@example.test")
      row = database[:ciba_requests].order(:id).last
      application.new(Rack::MockRequest.env_for(issuer)).rodauth.approve_ciba_request(row[:id], account_id: row[:account_id])
      issued = post.call(metadata.fetch("token_endpoint"), grant_type: Rodauth::CibaSupport::GRANT_TYPE, auth_req_id: started.fetch("auth_req_id"))
      renewed = post.call(metadata.fetch("token_endpoint"), grant_type: "refresh_token", refresh_token: issued.fetch("refresh_token"))
      [issued, renewed].each do |tokens|
        token = tokens.fetch("id_token")
        raise "unencrypted response" unless token.split(".").length == 5
        signed = JWE.decrypt(token, recipient)
        if algorithm == "RS256"
          jwks = JSON.parse(http.get(metadata.fetch("jwks_uri")).body)
          claims, = JWT.decode(signed, nil, true, jwks: jwks, algorithms: [algorithm],
            verify_iss: true, iss: issuer, verify_aud: true, aud: "demo-client")
        else
          parts = signed.split(".")
          raise "invalid signature" unless edwards.verify(nil, Base64.urlsafe_decode64(parts.last), parts.first(2).join("."))
          claims, header = JWT.decode(signed, nil, false)
          raise "wrong algorithm" unless header.fetch("alg") == algorithm
          raise "wrong issuer/audience" unless claims.fetch("iss") == issuer && claims.fetch("aud") == "demo-client"
        end
        raise "wrong subject" unless claims.fetch("sub") == row[:account_id].to_s
      end
      puts "PASS: installed #{algorithm} encrypted ID Token issuance/refresh, #{jwt ? 'JWT' : 'opaque'} access token, recipient decryption and signature verified"
    end
  ensure
    database.disconnect
  end
end
