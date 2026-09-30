# frozen_string_literal: true
# Synthetic credentials and ephemeral keys only. Optional export contains no private keys.
require "rack/mock"
require "json"
require_relative "demo_app"

vectors = []
[false, true].each do |jwt|
  database = Sequel.sqlite
  begin
    CibaDemo.create_schema(database)
    database.alter_table(:oauth_applications) { add_column :id_token_signed_response_alg, String }
    signing_keys = %w[Ed25519 EdDSA].to_h { |algorithm| [algorithm, OpenSSL::PKey.generate_key("ED25519")] }
    application = CibaDemo.build(database)
    application.plugin(:rodauth) do
      base_url "https://op.example.test"
      authorization_server_url "https://op.example.test"
      ciba_require_tls true
      oauth_jwt_access_tokens jwt
      ciba_id_token_signing_keys signing_keys
    end
    http = Rack::MockRequest.new(application)
    issuer = "https://op.example.test"
    metadata = JSON.parse(http.get("#{issuer}/.well-known/openid-configuration").body)
    headers = {"HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64('demo-client:demo-secret')}"}
    signing_keys.each do |algorithm, key|
      database[:oauth_applications].update(id_token_signed_response_alg: algorithm)
      started = http.post(metadata.fetch("backchannel_authentication_endpoint"), headers.merge(params: {scope: "openid", login_hint: "customer@example.test"}))
      raise started.body unless started.status == 200
      row = database[:ciba_requests].order(:id).last
      application.new(Rack::MockRequest.env_for(issuer)).rodauth.approve_ciba_request(row[:id], account_id: row[:account_id])
      issued = http.post(metadata.fetch("token_endpoint"), headers.merge(params: {
        grant_type: Rodauth::CibaSupport::GRANT_TYPE, auth_req_id: JSON.parse(started.body).fetch("auth_req_id")}))
      raise issued.body unless issued.status == 200
      tokens = JSON.parse(issued.body)
      parts = tokens.fetch("id_token").split(".")
      raise "invalid signature" unless key.verify(nil, Base64.urlsafe_decode64(parts.last), parts.first(2).join("."))
      jwks = JSON.parse(http.get(metadata.fetch("jwks_uri")).body)
      raise "private key exported" if jwks.fetch("keys").any? { |jwk| jwk.key?("d") || jwk.key?("k") }
      vectors << {alg: algorithm, jwt_access_token: jwt, checked_at: Time.now.to_i,
        id_token: tokens.fetch("id_token"), access_token: tokens.fetch("access_token"), jwks: jwks}
      puts "PASS: installed #{algorithm} ID Token, #{jwt ? 'JWT' : 'opaque'} access token, public JWKS"
    end
  ensure
    database.disconnect
  end
end
File.write(ENV.fetch("CIBA_EDWARDS_ID_TOKEN_EXPORT"), JSON.pretty_generate(vectors) + "\n") if ENV["CIBA_EDWARDS_ID_TOKEN_EXPORT"]
