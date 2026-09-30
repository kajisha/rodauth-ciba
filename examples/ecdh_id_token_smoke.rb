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
    database[:oauth_applications].update(scopes: "openid offline_access",
      grant_types: "#{Rodauth::CibaSupport::GRANT_TYPE} refresh_token",
      id_token_encrypted_response_enc: "A256CBC-HS512")
    application = CibaDemo.build(database)
    application.plugin(:rodauth) do
      base_url "https://op.example.test"
      authorization_server_url "https://op.example.test"
      ciba_require_tls true
      oauth_jwt_access_tokens jwt
      ciba_refresh_tokens_enabled true
      oauth_application_scopes %w[openid offline_access]
      ciba_id_token_encryption_enabled true
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
    {"P-256" => "prime256v1", "P-384" => "secp384r1", "P-521" => "secp521r1", "X25519" => nil}.each do |curve, group|
      recipient = group ? OpenSSL::PKey::EC.generate(group) : OpenSSL::PKey.generate_key("X25519")
      public_recipient = group ? JWT::JWK.new(recipient).export :
        {kty: "OKP", crv: curve, x: Base64.urlsafe_encode64(OpenSSL::ASN1.decode(recipient.public_to_der).value.last.value, padding: false)}
      %w[ECDH-ES ECDH-ES+A128KW ECDH-ES+A192KW ECDH-ES+A256KW].each do |algorithm|
        database[:oauth_applications].update(id_token_encrypted_response_alg: algorithm,
          jwks: JSON.generate(keys: [public_recipient.merge(alg: algorithm, use: "enc", kid: "recipient")]))
        started = post.call(metadata.fetch("backchannel_authentication_endpoint"), scope: "openid offline_access", login_hint: "customer@example.test")
        row = database[:ciba_requests].order(:id).last
        application.new(Rack::MockRequest.env_for(issuer)).rodauth.approve_ciba_request(row[:id], account_id: row[:account_id])
        issued = post.call(metadata.fetch("token_endpoint"), grant_type: Rodauth::CibaSupport::GRANT_TYPE, auth_req_id: started.fetch("auth_req_id"))
        renewed = post.call(metadata.fetch("token_endpoint"), grant_type: "refresh_token", refresh_token: issued.fetch("refresh_token"))
        [issued, renewed].each do |tokens|
          token = tokens.fetch("id_token")
          raise "unencrypted response" unless token.split(".").length == 5
          parts = token.split(".", -1)
          header = JSON.parse(Base64.urlsafe_decode64(parts[0]))
          epk = header.fetch("epk")
          raise "wrong curve or private ephemeral key" unless epk.fetch("crv") == curve && !epk.key?("d")
          public_key = if group
            JWT::JWK.import(epk).keypair
          else
            identifier = OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new("1.3.101.110")])
            OpenSSL::PKey.read(OpenSSL::ASN1::Sequence.new([identifier,
              OpenSSL::ASN1::BitString.new(Base64.urlsafe_decode64(epk.fetch("x")))]).to_der)
          end
          bits = algorithm == "ECDH-ES" ? 512 : algorithm[/A(\d+)KW$/, 1].to_i
          name = algorithm == "ECDH-ES" ? "A256CBC-HS512" : algorithm
          info = [name.bytesize].pack("N") + name + [0, 0, bits].pack("N3")
          shared = recipient.derive(public_key)
          derived = (1..((bits + 255) / 256)).map { |counter| OpenSSL::Digest.digest("SHA256", [counter].pack("N") + shared + info) }.join.byteslice(0, bits / 8)
          cek = algorithm == "ECDH-ES" ? derived : JWE::Alg.decrypt_cek(algorithm.split("+").last, derived, Base64.urlsafe_decode64(parts[1]))
          signed = JWE::Enc.for("A256CBC-HS512", cek, Base64.urlsafe_decode64(parts[2]), Base64.urlsafe_decode64(parts[4]))
            .decrypt(Base64.urlsafe_decode64(parts[3]), parts[0])
          jwks = JSON.parse(http.get(metadata.fetch("jwks_uri")).body)
          claims, = JWT.decode(signed, nil, true, jwks: jwks, algorithms: ["RS256"],
            verify_iss: true, iss: issuer, verify_aud: true, aud: "demo-client")
          raise "wrong subject" unless claims.fetch("sub") == row[:account_id].to_s
        end
        puts "PASS: installed #{curve}/#{algorithm} encrypted ID Token issuance/refresh, #{jwt ? 'JWT' : 'opaque'} access token, recipient decryption and signature verified"
      end
    end
  ensure
    database.disconnect
  end
end
