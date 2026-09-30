# frozen_string_literal: true
require "rack/mock"
require "json"
require_relative "demo_app"

[false, true].product([false, true]).each do |jwt, hashed|
  database = Sequel.sqlite
  begin
    CibaDemo.create_schema(database)
    Rodauth::CibaSupport::Schema.create_refresh_tokens(database)
    database.alter_table(:oauth_applications) do
      add_column :id_token_encrypted_response_alg, String
      add_column :id_token_encrypted_response_enc, String
      add_column :jwks_uri, String
    end
    secret = "c" * 64
    database[:oauth_applications].update(scopes: "openid offline_access",
      grant_types: "#{Rodauth::CibaSupport::GRANT_TYPE} refresh_token",
      token_endpoint_auth_method: hashed ? "client_secret_basic" : "client_secret_post",
      client_secret: hashed ? BCrypt::Password.create(secret, cost: 4).to_s : secret,
      jwks_uri: "https://unused.invalid/jwks")
    app = CibaDemo.build(database)
    app.plugin(:rodauth) do
      base_url "https://op.example.test"
      authorization_server_url "https://op.example.test"
      ciba_require_tls true
      oauth_jwt_access_tokens jwt
      ciba_refresh_tokens_enabled true
      oauth_application_scopes %w[openid offline_access]
      ciba_id_token_encryption_enabled true
      oauth_applications_client_secret_hash_column(hashed ? :client_secret : nil)
      http_request { |*| raise "unexpected recipient HTTP request" }
    end
    http = Rack::MockRequest.new(app)
    issuer = "https://op.example.test"
    metadata = JSON.parse(http.get("#{issuer}/.well-known/openid-configuration").body)
    keys = JSON.parse(http.get(metadata.fetch("jwks_uri")).body)
    post = lambda do |endpoint, params|
      headers = hashed ? {"HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64("demo-client:#{secret}")}"} : {}
      params = params.merge(client_id: "demo-client", client_secret: secret) unless hashed
      response = http.post(endpoint, headers.merge(params: params))
      raise response.body unless response.status == 200
      JSON.parse(response.body)
    end
    %w[dir A128KW A192KW A256KW A128GCMKW A192GCMKW A256GCMKW].each do |algorithm|
      raise "missing Discovery algorithm" unless metadata.fetch("id_token_encryption_alg_values_supported").include?(algorithm)
      method = "A256CBC-HS512"
      database[:oauth_applications].update(id_token_encrypted_response_alg: algorithm, id_token_encrypted_response_enc: method)
      started = post.call(metadata.fetch("backchannel_authentication_endpoint"), scope: "openid offline_access", login_hint: "customer@example.test")
      row = database[:ciba_requests].order(:id).last
      app.new(Rack::MockRequest.env_for(issuer)).rodauth.approve_ciba_request(row[:id], account_id: row[:account_id])
      initial = post.call(metadata.fetch("token_endpoint"), grant_type: Rodauth::CibaSupport::GRANT_TYPE, auth_req_id: started.fetch("auth_req_id"))
      renewed = post.call(metadata.fetch("token_endpoint"), grant_type: "refresh_token", refresh_token: initial.fetch("refresh_token"))
      length = algorithm == "dir" ? 64 : algorithm[/\d+/].to_i / 8
      key = OpenSSL::Digest.digest(length > 32 ? "SHA512" : "SHA256", secret)[0, length]
      [initial, renewed].each do |tokens|
        token = tokens.fetch("id_token")
        signed = if algorithm.end_with?("GCMKW")
          parts = token.split(".")
          header = JSON.parse(Base64.urlsafe_decode64(parts[0]))
          raise "wrong key algorithm" unless header.fetch("alg") == algorithm
          wrapper = OpenSSL::Cipher.new("aes-#{length * 8}-gcm")
          wrapper.decrypt
          wrapper.key = key
          wrapper.iv = Base64.urlsafe_decode64(header.fetch("iv"))
          wrapper.auth_tag = Base64.urlsafe_decode64(header.fetch("tag"))
          wrapper.auth_data = ""
          cek = wrapper.update(Base64.urlsafe_decode64(parts[1])) + wrapper.final
          JWE::Enc.for(method, cek, Base64.urlsafe_decode64(parts[2]), Base64.urlsafe_decode64(parts[4]))
            .decrypt(Base64.urlsafe_decode64(parts[3]), parts[0])
        else
          JWE.decrypt(token, key)
        end
        claims, = JWT.decode(signed, nil, true, jwks: keys, algorithms: ["RS256"],
          verify_iss: true, iss: issuer, verify_aud: true, aud: "demo-client")
        raise "wrong subject" unless claims.fetch("sub") == row[:account_id].to_s
      end
      puts "PASS: installed #{algorithm}/#{method}, #{hashed ? 'hashed Basic' : 'plaintext POST'}, #{jwt ? 'JWT' : 'opaque'}; initial/refresh decrypted and signatures verified; no remote recipient lookup"
    end
  ensure
    database.disconnect
  end
end
