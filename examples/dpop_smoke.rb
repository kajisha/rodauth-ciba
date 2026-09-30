# frozen_string_literal: true
# Local synthetic credentials only. Exercises the installed gem, not test helpers.
require "rack/mock"
require "json"
require "base64"
require "digest"
require_relative "demo_app"

[false, true].each do |jwt|
  database = Sequel.sqlite
  begin
    CibaDemo.create_schema(database)
    Rodauth::CibaSupport::Schema.create_client_assertions(database)
    Rodauth::CibaSupport::Schema.create_refresh_tokens(database)
    Rodauth::CibaSupport::Schema.add_registration_token_digest(database)
    database.alter_table(:oauth_grants) { add_column :dpop_jkt, String }
    database.alter_table(:oauth_applications) do
      add_column :dpop_bound_access_tokens, TrueClass
      add_column :name, String
      add_column :redirect_uri, String, text: true
      add_column :response_types, String
      add_column :registration_access_token, String
    end
    application = CibaDemo.build(database)
    nonce_secret = SecureRandom.random_bytes(32)
    application.plugin(:rodauth) do
      enable :oauth_dpop, :oauth_dynamic_client_registration, :oauth_token_introspection
      ciba_dynamic_client_registration_enabled true
      ciba_refresh_tokens_enabled true
      oauth_application_scopes %w[openid offline_access]
      oauth_jwt_access_tokens jwt
      ciba_dpop_nonce_secret nonce_secret
      oauth_dpop_use_nonce true
      before_register do
        authorization_required unless request.env["HTTP_AUTHORIZATION"] == "Bearer local-dpop-registration"
      end
    end
    application.route do |r|
      rodauth.load_openid_configuration_route
      rodauth.load_oauth_server_metadata_route
      r.rodauth
    end
    http = Rack::MockRequest.new(application)
    issuer = "http://127.0.0.1:9292"
    metadata = JSON.parse(http.get("#{issuer}/.well-known/openid-configuration").body)
    oauth_metadata = JSON.parse(http.get("#{issuer}/.well-known/oauth-authorization-server").body)
    %w[introspection_endpoint introspection_endpoint_auth_methods_supported dpop_signing_alg_values_supported].each do |name|
      raise "Discovery mismatch: #{name}" unless metadata.fetch(name) == oauth_metadata.fetch(name)
    end
    check = lambda do |response, status, error = nil|
      raise "unexpected status #{response.status}: #{response.body}" unless response.status == status
      body = JSON.parse(response.body)
      raise "unexpected error: #{body}" if error && body["error"] != error
      body
    end
    client = check.call(http.post(metadata.fetch("registration_endpoint"),
      "HTTP_AUTHORIZATION" => "Bearer local-dpop-registration", "CONTENT_TYPE" => "application/json",
      input: JSON.generate(grant_types: [Rodauth::CibaSupport::GRANT_TYPE, "refresh_token"],
        response_types: [], scope: "openid offline_access", token_endpoint_auth_method: "client_secret_basic",
        backchannel_token_delivery_mode: "poll", dpop_bound_access_tokens: true)), 201)
    raise "DPoP policy missing" unless client.fetch("dpop_bound_access_tokens")
    credentials = {"HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64("#{client.fetch('client_id')}:#{client.fetch('client_secret')}")}"}
    instance = application.new(Rack::MockRequest.env_for(issuer)).rodauth
    approve = lambda do
      started = check.call(http.post(metadata.fetch("backchannel_authentication_endpoint"),
        credentials.merge(params: {scope: "openid offline_access", login_hint: "customer@example.test"})), 200)
      request = instance.ciba_request(database[:ciba_requests].order(:id).last.fetch(:id))
      grant = instance.create_ciba_grant(account_id: request[:account_id],
        oauth_application_id: request[:oauth_application_id], scopes: request[:scopes])
      instance.backchannel_result(request[:id], grant)
      {grant_type: Rodauth::CibaSupport::GRANT_TYPE, auth_req_id: started.fetch("auth_req_id")}
    end
    key = OpenSSL::PKey::EC.generate("prime256v1")
    proof = lambda do |target, method, signing_key, claims = {}|
      JWT.encode({jti: SecureRandom.uuid, iat: Time.now.to_i, htm: method, htu: target}.merge(claims),
        signing_key, "ES256", typ: "dpop+jwt", jwk: JWT::JWK.new(signing_key).export)
    end
    poll = lambda do |params, signed = nil|
      headers = credentials.merge(params: params)
      headers["HTTP_DPOP"] = signed if signed
      http.post(metadata.fetch("token_endpoint"), headers)
    end
    params = approve.call
    check.call(poll.call(params), 400, "invalid_grant")
    challenge = poll.call(params, proof.call(metadata.fetch("token_endpoint"), "POST", key))
    check.call(challenge, 400, "use_dpop_nonce")
    nonce = challenge["DPoP-Nonce"]
    raise "missing nonce" unless nonce.is_a?(String) && nonce.bytesize == 43
    signed = proof.call(metadata.fetch("token_endpoint"), "POST", key, nonce: nonce, iat: 1)
    tokens = check.call(poll.call(params, signed), 200)
    raise "wrong token type" unless tokens.fetch("token_type") == "DPoP"
    keys = JSON.parse(http.get(metadata.fetch("jwks_uri")).body)
    identity, = JWT.decode(tokens.fetch("id_token"), nil, true, jwks: keys, algorithms: ["RS256"],
      verify_iss: true, iss: issuer, verify_aud: true, aud: client.fetch("client_id"))
    raise "ID Token inherited DPoP binding" if identity.key?("cnf")
    raise "wrong subject" unless identity.fetch("sub") == database[:accounts].get(:id).to_s
    verify_binding = lambda do |issued, signing_key|
      expected = JWT::JWK::Thumbprint.new(JWT::JWK.new(signing_key)).generate
      if jwt
        payload, = JWT.decode(issued.fetch("access_token"), nil, true, jwks: keys,
          algorithms: ["RS256"], verify_iss: true, iss: issuer)
        raise "JWT binding missing" unless payload.fetch("cnf").fetch("jkt") == expected
      end
      raise "stored binding missing" unless database[:oauth_grants].order(:id).last.fetch(:dpop_jkt) == expected
    end
    verify_binding.call(tokens, key)
    unless jwt
      introspected = check.call(http.post(metadata.fetch("introspection_endpoint"),
        credentials.merge(params: {token: tokens.fetch("access_token")})), 200)
      raise "bound token inactive" unless introspected.fetch("active")
      raise "introspection lost type" unless introspected.fetch("token_type") == "DPoP"
      expected = JWT::JWK::Thumbprint.new(JWT::JWK.new(key)).generate
      raise "introspection lost binding" unless introspected.fetch("cnf").fetch("jkt") == expected
    end
    raise "live proof removed" unless instance.cleanup_ciba_client_assertions == 0
    second = approve.call
    check.call(poll.call(second, signed), 400, "invalid_grant")
    raise "replay consumed approval" unless database[:ciba_requests].order(:id).last.fetch(:status) == "approved"
    userinfo = metadata.fetch("userinfo_endpoint")
    token = tokens.fetch("access_token")
    check.call(http.get(userinfo, "HTTP_AUTHORIZATION" => "Bearer #{token}"), 401, "invalid_token")
    ath = Base64.urlsafe_encode64(Digest::SHA256.digest(token), padding: false)
    get = ->(signed_proof) { http.get(userinfo, "HTTP_AUTHORIZATION" => "DPoP #{token}", "HTTP_DPOP" => signed_proof) }
    check.call(get.call(proof.call(userinfo, "GET", key, ath: ath)), 401, "use_dpop_nonce")
    check.call(get.call(proof.call(userinfo, "GET", key, ath: "wrong", nonce: nonce)), 401, "invalid_token")
    user_proof = proof.call(userinfo, "GET", key, ath: ath, nonce: nonce, iat: 1)
    info = check.call(get.call(user_proof), 200)
    raise "UserInfo subject mismatch" unless info.fetch("sub") == identity.fetch("sub")
    check.call(get.call(user_proof), 401, "invalid_token")
    replacement_key = OpenSSL::PKey::EC.generate("prime256v1")
    check.call(get.call(proof.call(userinfo, "GET", replacement_key, ath: ath, nonce: nonce)), 401, "invalid_token")
    refresh_params = {grant_type: "refresh_token", refresh_token: tokens.fetch("refresh_token")}
    refresh_proof = proof.call(metadata.fetch("token_endpoint"), "POST", replacement_key, nonce: nonce)
    refreshed = check.call(poll.call(refresh_params, refresh_proof), 200)
    raise "refresh lost token type" unless refreshed.fetch("token_type") == "DPoP"
    verify_binding.call(refreshed, replacement_key)
    renewed_identity, = JWT.decode(refreshed.fetch("id_token"), nil, true, jwks: keys, algorithms: ["RS256"],
      verify_iss: true, iss: issuer, verify_aud: true, aud: client.fetch("client_id"))
    raise "refreshed ID Token inherited DPoP binding" if renewed_identity.key?("cnf")
    refreshed_token = refreshed.fetch("access_token")
    refreshed_ath = Base64.urlsafe_encode64(Digest::SHA256.digest(refreshed_token), padding: false)
    refreshed_info = check.call(http.get(userinfo, "HTTP_AUTHORIZATION" => "DPoP #{refreshed_token}",
      "HTTP_DPOP" => proof.call(userinfo, "GET", replacement_key, ath: refreshed_ath, nonce: nonce)), 200)
    raise "refresh changed subject" unless refreshed_info.fetch("sub") == identity.fetch("sub")
    check.call(poll.call(refresh_params, refresh_proof), 400, "invalid_grant")
    alias_userinfo = URI(userinfo)
    alias_userinfo.port += 1
    alias_userinfo = alias_userinfo.to_s
    check.call(http.get(alias_userinfo, "HTTP_AUTHORIZATION" => "DPoP #{refreshed_token}",
      "HTTP_DPOP" => proof.call(userinfo, "GET", replacement_key, ath: refreshed_ath, nonce: nonce)), 401, "invalid_dpop_proof")
    alias_info = check.call(http.get(alias_userinfo, "HTTP_AUTHORIZATION" => "DPoP #{refreshed_token}",
      "HTTP_DPOP" => proof.call(alias_userinfo, "GET", replacement_key, ath: refreshed_ath, nonce: nonce)), 200)
    raise "alias subject changed" unless alias_info.fetch("sub") == identity.fetch("sub")
    alias_token = URI(metadata.fetch("token_endpoint"))
    alias_token.port += 1
    alias_token = alias_token.to_s
    check.call(http.post(alias_token, credentials.merge(params: second,
      "HTTP_DPOP" => proof.call(metadata.fetch("token_endpoint"), "POST", key, nonce: nonce))), 400, "invalid_dpop_proof")
    alias_tokens = check.call(http.post(alias_token, credentials.merge(params: second,
      "HTTP_DPOP" => proof.call(alias_token, "POST", key, nonce: nonce))), 200)
    JWT.decode(alias_tokens.fetch("id_token"), nil, true, jwks: keys,
      algorithms: ["RS256"], verify_iss: true, iss: issuer,
      verify_aud: true, aud: client.fetch("client_id"))
    puts "PASS: installed-gem #{jwt ? 'JWT' : 'opaque'} DPoP alias port binding with canonical issuer (Rack transport)"
    puts "PASS: installed-gem #{jwt ? 'JWT' : 'opaque'} DPoP DCR, nonce/old-iat issuance, binding, UserInfo, replay and confidential refresh with new key"
  ensure
    database.disconnect
  end
end
