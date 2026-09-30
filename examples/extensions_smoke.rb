# frozen_string_literal: true
# Installed-gem integration check for the optional migrations and consent APIs.
require "rack/mock"
require "json"
require "digest"
require_relative "demo_app"

[false, true].each do |jwt|
  database = Sequel.sqlite
  begin
    CibaDemo.create_schema(database)
    Rodauth::CibaSupport::Schema.add_claims(database)
    Rodauth::CibaSupport::Schema.add_resources(database)
    Rodauth::CibaSupport::Schema.add_authorization_details(database)
    Rodauth::CibaSupport::Schema.add_signed_requests(database)
    Rodauth::CibaSupport::Schema.add_user_code(database)
    Rodauth::CibaSupport::Schema.create_refresh_tokens(database)
    Rodauth::CibaSupport::Schema.add_request_context(database)
    database[:oauth_applications].update(backchannel_user_code_parameter: true)
    database.alter_table(:oauth_applications) { add_column :jwks, String, text: true }
    request_key = OpenSSL::PKey::RSA.generate(2048)
    database[:oauth_applications].update(backchannel_authentication_request_signing_alg: "RS256",
      jwks: JSON.generate(keys: [JWT::JWK.new(request_key.public_key).export.merge(alg: "RS256", use: "sig")]))
    database[:oauth_applications].update(scopes: "openid offline_access read delete",
      grant_types: "#{Rodauth::CibaSupport::GRANT_TYPE} refresh_token", authorization_details_types: JSON.generate(["support_data"]))
    application = CibaDemo.build(database)
    resource = "https://api.example.test/data"
    application.plugin(:rodauth) do
      enable :oauth_token_introspection, :oauth_token_revocation
      ciba_refresh_tokens_enabled true
      ciba_request_context_enabled true
      validate_ciba_request_context do |context, oauth_application:|
        unless context.nil? || (context == "demo-operation-reference" && oauth_application[:client_id] == "demo-client")
          raise Rodauth::CibaSupport::ProtocolError, "invalid_request"
        end
      end
      ciba_claims_enabled true
      ciba_authentication_claims_by_scope("openid" => %w[auth_time])
      ciba_request_signing_algorithms ["RS256"]
      ciba_user_code_enabled true
      # Demo policy only; production applications own user-code registration and checks.
      verify_ciba_user_code do |code, account_id:, oauth_application:|
        raise Rodauth::CibaSupport::ProtocolError, "missing_user_code" if code.nil?
        code == "demo-user-code" && database[:accounts].where(id: account_id, email: "customer@example.test").count == 1
      end
      ciba_resources_enabled true
      ciba_login_hint_token_enabled true
      ciba_id_token_hint_enabled true
      resolve_ciba_id_token_subject do |subject, oauth_application:|
        database[:accounts].where(id: subject.to_i).get(:id) if subject.match?(/\A[0-9]+\z/)
      end
      resolve_ciba_login_hint_token do |hint, oauth_application:|
        if hint == "demo-customer-reference" && oauth_application[:client_id] == "demo-client"
          database[:accounts].where(email: "customer@example.test").get(:id)
        end
      end
      ciba_authorization_details_enabled true
      ciba_authorization_details_types ["support_data"]
      # This fixture defines only a fixed read/delete type, not generic RAR policy.
      ciba_validate_authorization_details do |details, oauth_application:|
        details.all? { |detail| (detail.keys - %w[type actions]).empty? &&
          detail["actions"].is_a?(Array) && (detail["actions"] - %w[read delete]).empty? }
      end
      ciba_authorization_details_for_token do |requested:, approved:, narrowing:, resource:, oauth_application:|
        approved.filter_map do |detail|
          actions = detail["actions"] & requested.flat_map { |value| value["actions"] }
          actions &= narrowing.flat_map { |value| value["actions"] } if narrowing
          detail.merge("actions" => actions) unless actions.empty?
        end
      end
      ciba_resource_servers(resource => {scopes: %w[read delete], audience: "customer-data"})
      oauth_application_scopes %w[openid offline_access read delete]
      oauth_jwt_access_tokens jwt
      get_oidc_param { |account, name| name == :email ? account[:email] : nil }
    end
    http = Rack::MockRequest.new(application)
    issuer = "http://127.0.0.1:9292"
    headers = {"HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64('demo-client:demo-secret')}"}
    metadata = JSON.parse(http.get("#{issuer}/.well-known/openid-configuration").body)
    raise "missing signing metadata" unless metadata["backchannel_authentication_request_signing_alg_values_supported"] == ["RS256"]
    start_signed = lambda do |parameters|
      now = Time.now.to_i
      payload = {iss: "demo-client", aud: issuer, iat: now, nbf: now, exp: now + 60, jti: SecureRandom.hex(16), user_code: "demo-user-code"}.merge(parameters)
      request_jwt = JWT.encode(payload, request_key, "RS256", kid: JWT::JWK.new(request_key).kid)
      http.post(metadata.fetch("backchannel_authentication_endpoint"), headers.merge(params: {request: request_jwt}))
    end
    initial_parameters = {
      scope: "openid offline_access read delete", login_hint_token: "demo-customer-reference", resource: resource,
      claims: JSON.generate(id_token: {email: nil, email_verified: nil}), nonce: "installed-extension-check",
      request_context: "demo-operation-reference",
      authorization_details: JSON.generate([{type: "support_data", actions: %w[read delete]}])
    }
    response = start_signed.call(initial_parameters)
    raise response.body unless response.status == 200
    request_id = JSON.parse(response.body).fetch("auth_req_id")
    instance = application.new(Rack::MockRequest.env_for(issuer)).rodauth
    request = instance.ciba_request(database[:ciba_requests].get(:id))
    raise "raw hint persisted" if JSON.generate(request).include?("demo-customer-reference")
    raise "raw user code persisted" if JSON.generate(request).include?("demo-user-code")
    raise "missing validated request context" unless request[:request_context] == "demo-operation-reference"
    grant = instance.create_ciba_grant(account_id: request[:account_id],
      oauth_application_id: request[:oauth_application_id], scopes: "openid offline_access",
      resources: {resource => "read"}, claims: ["email"],
      authorization_details: [{type: "support_data", actions: ["read"]}])
    instance.backchannel_result(request[:id], grant, auth_time: 1)
    token_params = {grant_type: Rodauth::CibaSupport::GRANT_TYPE, auth_req_id: request_id, resource: resource}
    response = http.post(metadata.fetch("token_endpoint"), headers.merge(params: token_params))
    raise response.body unless response.status == 200
    tokens = JSON.parse(response.body)
    keys = JSON.parse(http.get(metadata.fetch("jwks_uri")).body)
    identity, = JWT.decode(tokens.fetch("id_token"), nil, true, jwks: keys, algorithms: ["RS256"],
      verify_iss: true, iss: issuer, verify_aud: true, aud: "demo-client")
    raise "unapproved API scope" unless tokens.fetch("scope") == "read"
    expected_details = [{"type" => "support_data", "actions" => ["read"]}]
    raise "wrong RAR permission" unless tokens["authorization_details"] == expected_details
    raise "RAR in ID Token" if identity.key?("authorization_details")
    raise "request context in ID Token" if identity.key?("request_context")
    raise "missing approved identity claim" unless identity["email"] == "customer@example.test"
    raise "unapproved identity claim" if identity.key?("email_verified")
    raise "wrong authentication context" unless identity["nonce"] == "installed-extension-check" && identity["auth_time"] == 1
    expected_hash = Base64.urlsafe_encode64(Digest::SHA256.digest(tokens.fetch("access_token"))[0, 16], padding: false)
    raise "wrong access-token binding" unless identity["at_hash"] == expected_hash
    raise "private resource marker in ID Token" if identity.key?("urn:rodauth:ciba:resource")
    hinted = start_signed.call({
      scope: "openid", id_token_hint: tokens.fetch("id_token")
    })
    raise hinted.body unless hinted.status == 200
    hinted_id = JSON.parse(hinted.body).fetch("auth_req_id")
    pending = http.post(metadata.fetch("token_endpoint"), headers.merge(params: {
      grant_type: Rodauth::CibaSupport::GRANT_TYPE, auth_req_id: hinted_id
    }))
    raise "hint inherited approval" unless pending.status == 400 && JSON.parse(pending.body)["error"] == "authorization_pending"
    hint_claims = identity.reject { |name, _| %w[iat exp].include?(name) }.merge("azp" => "another-party")
    hint_input = [{alg: "RS256", typ: "at+jwt", b64: true, crit: ["b64"]}, hint_claims].map do |part|
      Base64.urlsafe_encode64(JSON.generate(part), padding: false)
    end.join(".")
    hint_signature = instance.oauth_jwt_keys.fetch("RS256").sign("SHA256", hint_input)
    profile_hint = hint_input + "." + Base64.urlsafe_encode64(hint_signature, padding: false)
    profile = start_signed.call(scope: "openid", id_token_hint: profile_hint)
    raise profile.body unless profile.status == 200
    profile_pending = http.post(metadata.fetch("token_endpoint"), headers.merge(params: {
      grant_type: Rodauth::CibaSupport::GRANT_TYPE, auth_req_id: JSON.parse(profile.body).fetch("auth_req_id")
    }))
    raise "profile hint inherited approval" unless profile_pending.status == 400 && JSON.parse(profile_pending.body)["error"] == "authorization_pending"
    puts "PASS: installed-gem reference ID hint validation profile remains pending"
    introspect = -> { http.post("#{issuer}/introspect", headers.merge(params: {token: tokens.fetch("access_token")})) }
    if jwt
      access, = JWT.decode(tokens.fetch("access_token"), nil, true, jwks: keys, algorithms: ["RS256"],
        verify_iss: true, iss: issuer, verify_aud: true, aud: "customer-data")
      raise "wrong resource scope" unless access["scope"] == "read"
      raise "wrong JWT RAR permission" unless access["authorization_details"] == expected_details
      raise "identity claim in API token" if access.key?("email")
      info = introspect.call
      raise "structured JWT accepted" unless info.status == 400 && JSON.parse(info.body)["error"] == "unsupported_token_type"
      refused = http.post(metadata.fetch("revocation_endpoint"), headers.merge(params: {token: tokens.fetch("access_token")}))
      raise "structured JWT revocation accepted" unless refused.status == 400 && JSON.parse(refused.body)["error"] == "unsupported_token_type"
    else
      info = introspect.call
      data = JSON.parse(info.body)
      raise "wrong introspected RAR permission" unless data["authorization_details"] == expected_details
      unless info.status == 200 && data["active"] && data["aud"] == "customer-data" && data["scope"] == "read"
        raise "opaque token restrictions missing: #{info.body}"
      end
    end
    userinfo = http.get("#{issuer}/userinfo", "HTTP_AUTHORIZATION" => "Bearer #{tokens.fetch('access_token')}")
    raise "resource token accepted at UserInfo" unless userinfo.status == 401

    refresh = tokens.fetch("refresh_token")
    source = database[:ciba_refresh_tokens].first
    raise "raw refresh persisted" if JSON.generate(database[:ciba_refresh_tokens].all).include?(refresh)
    raise "wrong refresh digest" unless source[:token_digest] == Digest::SHA256.hexdigest(refresh)
    now = Time.now.to_i
    database[:ciba_refresh_tokens].update(issued_at: now - 800, expires_at: now + 200)
    refreshed = http.post(metadata.fetch("token_endpoint"), headers.merge(params: {
      grant_type: "refresh_token", refresh_token: refresh, resource: resource
    }))
    raise refreshed.body unless refreshed.status == 200
    renewed = JSON.parse(refreshed.body)
    raise "no refresh rotation" if renewed.fetch("refresh_token") == refresh
    raise "lost RAR permission" unless renewed["authorization_details"] == expected_details
    renewed_identity, = JWT.decode(renewed.fetch("id_token"), nil, true, jwks: keys, algorithms: ["RS256"],
      verify_iss: true, iss: issuer, verify_aud: true, aud: "demo-client")
    unless renewed_identity["auth_time"] == 1 && renewed_identity["nonce"] == "installed-extension-check" &&
           renewed_identity["email"] == "customer@example.test" && !renewed_identity.key?("email_verified")
      raise "refresh changed authenticated identity or permission"
    end
    replay = http.post(metadata.fetch("token_endpoint"), headers.merge(params: token_params))
    raise "replay accepted" unless replay.status == 400 && JSON.parse(replay.body)["error"] == "invalid_grant"
    raise "saved token not revoked" unless database[:oauth_grants].get(:revoked_at)
    unless jwt
      raise "revoked opaque token remains active" unless JSON.parse(introspect.call.body)["active"] == false
    end
    denied_refresh = http.post(metadata.fetch("token_endpoint"), headers.merge(params: {
      grant_type: "refresh_token", refresh_token: renewed.fetch("refresh_token"), resource: resource
    }))
    raise "successor survived grant revocation" unless denied_refresh.status == 400 && JSON.parse(denied_refresh.body)["error"] == "invalid_grant"

    # A separate consent exercises the advertised revocation endpoint, not replay.
    second = start_signed.call(initial_parameters)
    raise second.body unless second.status == 200
    second_id = JSON.parse(second.body).fetch("auth_req_id")
    second_grant = instance.create_ciba_grant(account_id: request[:account_id],
      oauth_application_id: request[:oauth_application_id], scopes: "openid offline_access",
      resources: {resource => "read"}, claims: ["email"],
      authorization_details: [{type: "support_data", actions: ["read"]}])
    instance.backchannel_result(database[:ciba_requests].max(:id), second_grant, auth_time: 1)
    second_issued = http.post(metadata.fetch("token_endpoint"), headers.merge(params: token_params.merge(auth_req_id: second_id)))
    raise second_issued.body unless second_issued.status == 200
    second_tokens = JSON.parse(second_issued.body)
    revocation_token = second_tokens.fetch(jwt ? "refresh_token" : "access_token")
    revoked = http.post(metadata.fetch("revocation_endpoint"), headers.merge(params: {token: revocation_token}))
    raise "refresh revocation failed" unless revoked.status == 200 && revoked.body.empty?
    raise "active access token survived revocation" unless database[:oauth_grants].where(revoked_at: nil).empty?
    unless jwt
      raise "AT revocation removed consent" if instance.ciba_grant(second_grant[:id])[:revoked_at]
      raise "old request survived AT revocation" unless database[:ciba_requests].where(grant_id: second_grant[:id]).empty?
    end
    raise "premature refresh cleanup" unless instance.cleanup_ciba_refresh_tokens == 0
    database[:ciba_refresh_tokens].update(expires_at: Time.now.to_i - 1)
    raise "refresh cleanup failed" unless instance.cleanup_ciba_refresh_tokens == (jwt ? 3 : 2) && database[:ciba_refresh_tokens].empty?
    puts "PASS: installed-gem #{jwt ? 'JWT' : 'opaque'} refresh migration, rotation, claims/RAR, original identity, grant revocation, advertised revocation endpoint and cleanup"
    puts "PASS: installed-gem #{jwt ? 'JWT' : 'opaque'} signed CIBA requests, validated request context, resource/claims/RAR migrations, consent, signed ID Token hint requiring new approval, nonce, at_hash, audience, UserInfo isolation and replay"
  ensure
    database.disconnect
  end
end
