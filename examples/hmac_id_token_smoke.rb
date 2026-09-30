# frozen_string_literal: true
require "rack/mock"
require "json"
require_relative "demo_app"

[false, true].product([false, true]).each do |jwt, hashed|
  database = Sequel.sqlite
  begin
    CibaDemo.create_schema(database)
    Rodauth::CibaSupport::Schema.create_refresh_tokens(database)
    database.alter_table(:oauth_applications) { add_column :id_token_signed_response_alg, String }
    database[:oauth_applications].update(scopes: "openid offline_access", grant_types: "#{Rodauth::CibaSupport::GRANT_TYPE} refresh_token")
    op_key = OpenSSL::PKey::RSA.generate(2048)
    op_secret = "o" * 64
    app = CibaDemo.build(database)
    app.plugin(:rodauth) do
      base_url "https://op.example.test"
      authorization_server_url "https://op.example.test"
      ciba_require_tls true
      oauth_jwt_access_tokens jwt
      oauth_jwt_keys("RS256" => op_key, "HS256" => op_secret, "HS384" => op_secret, "HS512" => op_secret)
      oauth_jwt_public_keys("RS256" => op_key.public_key)
      oauth_applications_client_secret_hash_column(hashed ? :client_secret : nil)
      ciba_refresh_tokens_enabled true
      oauth_application_scopes %w[openid offline_access]
      ciba_id_token_hint_enabled true
      resolve_ciba_id_token_subject { |subject, oauth_application:| db[:accounts].where(id: subject.to_i).get(:id) }
    end
    http = Rack::MockRequest.new(app)
    issuer = "https://op.example.test"
    metadata = JSON.parse(http.get("#{issuer}/.well-known/openid-configuration").body)
    authenticate = ->(secret) { {"HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64("demo-client:#{secret}")}"} }
    %w[HS256 HS384 HS512].each do |algorithm|
      secret = "c" * 64
      store = ->(value) { hashed ? BCrypt::Password.create(value, cost: 4).to_s : value }
      database[:oauth_applications].update(client_secret: store.call(secret), id_token_signed_response_alg: algorithm)
      post = lambda do |endpoint, params|
        response = http.post(endpoint, authenticate.call(secret).merge(params: params))
        raise response.body unless response.status == 200
        JSON.parse(response.body)
      end
      verify = lambda do |tokens|
        claims, = JWT.decode(tokens.fetch("id_token"), secret, true, algorithms: [algorithm],
          verify_iss: true, iss: issuer, verify_aud: true, aud: "demo-client")
        raise "wrong subject" unless claims.fetch("sub") == "1"
        begin
          JWT.decode(tokens.fetch("id_token"), op_secret, true, algorithms: [algorithm])
          raise "OP key unexpectedly verifies ID Token"
        rescue JWT::VerificationError
        end
      end
      started = post.call(metadata.fetch("backchannel_authentication_endpoint"), scope: "openid offline_access", login_hint: "customer@example.test")
      row = database[:ciba_requests].order(:id).last
      app.new(Rack::MockRequest.env_for(issuer)).rodauth.approve_ciba_request(row[:id], account_id: row[:account_id])
      initial = post.call(metadata.fetch("token_endpoint"), grant_type: Rodauth::CibaSupport::GRANT_TYPE, auth_req_id: started.fetch("auth_req_id"))
      verify.call(initial)
      verify.call(post.call(metadata.fetch("token_endpoint"), grant_type: "refresh_token", refresh_token: initial.fetch("refresh_token")))
      post.call(metadata.fetch("backchannel_authentication_endpoint"), scope: "openid", id_token_hint: initial.fetch("id_token"))
      previous_secret = secret
      secret = "r" * 64
      database[:oauth_applications].update(client_secret: store.call(secret))
      unauthorized = http.post(metadata.fetch("token_endpoint"), authenticate.call(previous_secret).merge(params: {grant_type: "refresh_token", refresh_token: initial.fetch("refresh_token")}))
      raise "old secret authenticated" unless unauthorized.status == 401
      old_hint = http.post(metadata.fetch("backchannel_authentication_endpoint"), authenticate.call(secret).merge(params: {scope: "openid", id_token_hint: initial.fetch("id_token")}))
      raise "old HMAC hint accepted" unless old_hint.status == 400 && JSON.parse(old_hint.body)["error"] == "invalid_request"
      verify.call(post.call(metadata.fetch("token_endpoint"), grant_type: "refresh_token", refresh_token: initial.fetch("refresh_token")))
      puts "PASS: installed #{algorithm}, #{hashed ? 'hashed' : 'plaintext'} secret, #{jwt ? 'JWT' : 'opaque'} access token; issuance/refresh/hint and client-secret rotation"
    end
  ensure
    database.disconnect
  end
end
