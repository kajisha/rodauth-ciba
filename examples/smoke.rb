# frozen_string_literal: true
# Runs from an installed gem without loading the repository's lib directory.
require "rack/mock"
require "json"
require_relative "demo_app"
db = Sequel.sqlite
CibaDemo.create_schema(db)
app = CibaDemo.build(db)
http = Rack::MockRequest.new(app)
issuer = "http://127.0.0.1:9292"
headers = {"HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64('demo-client:demo-secret')}"}
metadata = JSON.parse(http.get("#{issuer}/.well-known/openid-configuration").body)
response = http.post(metadata.fetch("backchannel_authentication_endpoint"), headers.merge(params: {scope: "openid", login_hint: "customer@example.test"}))
raise response.body unless response.status == 200
id = JSON.parse(response.body).fetch("auth_req_id")
instance = app.new(Rack::MockRequest.env_for(issuer)).rodauth
request = instance.ciba_request(db[:ciba_requests].get(:id))
consent = instance.create_ciba_grant(account_id: request[:account_id],
  oauth_application_id: request[:oauth_application_id], scopes: request[:scopes])
instance.backchannel_result(request[:id], consent)
response = http.post(metadata.fetch("token_endpoint"), headers.merge(params: {grant_type: Rodauth::CibaSupport::GRANT_TYPE, auth_req_id: id}))
raise response.body unless response.status == 200
tokens = JSON.parse(response.body)
keys = JSON.parse(http.get(metadata.fetch("jwks_uri")).body)
claims, = JWT.decode(tokens.fetch("id_token"), nil, true, jwks: keys, algorithms: ["RS256"], verify_iss: true, iss: issuer, verify_aud: true, aud: "demo-client")
raise "wrong subject" unless claims["sub"] == db[:accounts].get(:id).to_s
raise "unexpected refresh token" if tokens.key?("refresh_token")
raise "wrong consent reference" unless db[:oauth_grants].get(:ciba_grant_id) == consent[:id]
replay = http.post(metadata.fetch("token_endpoint"), headers.merge(params: {grant_type: Rodauth::CibaSupport::GRANT_TYPE, auth_req_id: id}))
raise "request reused" unless replay.status == 400 && JSON.parse(replay.body)["error"] == "invalid_grant"
raise "replay did not revoke token" unless db[:oauth_grants].get(:revoked_at)
instance.revoke_ciba_grant(consent[:id])
raise "token not revoked" unless db[:oauth_grants].get(:revoked_at)
puts "PASS: installed-gem discovery, acceptance, saved consent/result API, poll, verified ID Token, replay rejection and revocation"
response = http.post(metadata.fetch("backchannel_authentication_endpoint"), headers.merge(params: {scope: "openid", login_hint: "customer@example.test"}))
raise response.body unless response.status == 200
failed_id = JSON.parse(response.body).fetch("auth_req_id")
instance.backchannel_result(db[:ciba_requests].order(:id).last[:id],
  Rodauth::CibaSupport::ProtocolError.new("application_failure"))
%w[application_failure invalid_grant].each do |expected|
  result = http.post(metadata.fetch("token_endpoint"), headers.merge(params: {grant_type: Rodauth::CibaSupport::GRANT_TYPE, auth_req_id: failed_id}))
  raise result.body unless result.status == 400 && JSON.parse(result.body)["error"] == expected
end
raise "failure issued a token" unless db[:oauth_grants].count == 1
puts "PASS: installed-gem custom completion error returned once without token issuance"
db.disconnect
