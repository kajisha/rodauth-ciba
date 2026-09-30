# frozen_string_literal: true
require_relative "test_helper"

class CibaIntegrationTest
  def test_ciba_private_key_assertion_refresh_accepts_issuer_audience
    assert_ciba_assertion_refresh("private_key_jwt")
  end

  def test_ciba_secret_assertion_refresh_accepts_issuer_audience
    assert_ciba_assertion_refresh("client_secret_jwt")
  end

  def assert_ciba_assertion_refresh(method)
    Rodauth::CibaSupport::Schema.create_refresh_tokens(@db)
    @db.alter_table(:oauth_applications) { add_column :jwks, String, text: true }
    secret = "s" * 32
    @db[:oauth_applications].update(token_endpoint_auth_method: method, client_secret: secret,
      jwks: JSON.generate(keys: [JWT::JWK.new(KEY.public_key).export]),
      scopes: "openid offline_access", grant_types: "#{GRANT} refresh_token authorization_code")
    @app.plugin(:rodauth) do
      enable :oauth_jwt_bearer_grant
      ciba_refresh_tokens_enabled true
      oauth_application_scopes %w[openid offline_access]
    end
    assertion = lambda do |audience = "https://op.example.test"|
      header = method == "private_key_jwt" ? {kid: JWT::JWK.new(KEY).kid} : {}
      {client_id: "support", client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: JWT.encode({iss: "support", sub: "support", aud: audience,
          iat: Time.now.to_i, exp: Time.now.to_i + 60, jti: SecureRandom.uuid},
          method == "private_key_jwt" ? KEY : secret, method == "private_key_jwt" ? "RS256" : "HS256", header)}
    end
    response = post("/backchannel-authentication", assertion.call.merge(
      scope: "openid offline_access", login_hint: "customer@example.test"), "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, response.status, response.body
    id = JSON.parse(response.body).fetch("auth_req_id")
    approve(id)
    issued = post("/token", assertion.call.merge(grant_type: GRANT, auth_req_id: id), "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, issued.status, issued.body
    refresh = JSON.parse(issued.body).fetch("refresh_token")
    params = {grant_type: "refresh_token", refresh_token: refresh}
    rows = @db[:ciba_refresh_tokens].all
    wrong = post("/token", assertion.call("https://wrong.example.test").merge(params), "HTTP_AUTHORIZATION" => nil)
    assert_equal 401, wrong.status
    assert_equal rows, @db[:ciba_refresh_tokens].all
    signed = assertion.call
    result = post("/token", signed.merge(params), "HTTP_AUTHORIZATION" => nil)
    assert_equal 200, result.status, result.body
    payload, claims = decode_id_token(result)
    assert payload.fetch("access_token")
    assert_equal @account_id.to_s, claims.fetch("sub")
    replay = post("/token", signed.merge(params), "HTTP_AUTHORIZATION" => nil)
    assert_equal 401, replay.status
    assert_equal 2, @db[:oauth_grants].count
    # The CIBA refresh exception must not widen unrelated token requests.
    unrelated = post("/token", assertion.call.merge(grant_type: "authorization_code", code: "unknown"), "HTTP_AUTHORIZATION" => nil)
    assert_equal 401, unrelated.status
  end
end
