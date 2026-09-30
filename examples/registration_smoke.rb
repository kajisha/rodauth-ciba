# frozen_string_literal: true
# Installed-artifact check, using only local synthetic identities/credentials.
require "rack/mock"
require "json"
require "base64"
require_relative "demo_app"

db = Sequel.sqlite
CibaDemo.create_schema(db)
db.alter_table(:oauth_applications) do
  add_column :name, String
  add_column :redirect_uri, String, text: true
  add_column :response_types, String
  add_column :registration_access_token, String
end
Rodauth::CibaSupport::Schema.add_registration_token_digest(db)
app = CibaDemo.build(db)
app.plugin(:rodauth) do
  enable :oauth_dynamic_client_registration
  ciba_dynamic_client_registration_enabled true
  before_register do
    authorization_required unless request.env["HTTP_AUTHORIZATION"] == "Bearer local-registration-fixture"
  end
end
app.route do |r|
  rodauth.load_openid_configuration_route
  r.rodauth
  rodauth.load_registration_client_uri_routes
end
http = Rack::MockRequest.new(app)
issuer = "http://127.0.0.1:9292"
metadata = JSON.parse(http.get("#{issuer}/.well-known/openid-configuration").body)
params = {grant_types: [Rodauth::CibaSupport::GRANT_TYPE], response_types: [],
  scope: "openid", token_endpoint_auth_method: "client_secret_basic",
  backchannel_token_delivery_mode: "poll"}
response = http.post(metadata.fetch("registration_endpoint"),
  "HTTP_AUTHORIZATION" => "Bearer local-registration-fixture",
  "CONTENT_TYPE" => "application/json", input: JSON.generate(params))
raise response.body unless response.status == 201
client = JSON.parse(response.body)
credentials = {"HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64("#{client.fetch('client_id')}:#{client.fetch('client_secret')}")}"}
response = http.post(metadata.fetch("backchannel_authentication_endpoint"),
  credentials.merge(params: {scope: "openid", login_hint: "customer@example.test"}))
raise response.body unless response.status == 200
id = JSON.parse(response.body).fetch("auth_req_id")
instance = app.new(Rack::MockRequest.env_for(issuer)).rodauth
request = instance.ciba_request(db[:ciba_requests].get(:id))
grant = instance.create_ciba_grant(account_id: request[:account_id],
  oauth_application_id: request[:oauth_application_id], scopes: request[:scopes])
instance.backchannel_result(request[:id], grant)
response = http.post(metadata.fetch("token_endpoint"), credentials.merge(
  params: {grant_type: Rodauth::CibaSupport::GRANT_TYPE, auth_req_id: id}))
raise response.body unless response.status == 200
keys = JSON.parse(http.get(metadata.fetch("jwks_uri")).body)
JWT.decode(JSON.parse(response.body).fetch("id_token"), nil, true, jwks: keys,
  algorithms: ["RS256"], verify_iss: true, iss: issuer, verify_aud: true, aud: client.fetch("client_id"))

uri = client.fetch("registration_client_uri")
bearer = {"HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}"}
raise "management read failed" unless http.get(uri, bearer).status == 200
response = http.put(uri, bearer.merge("CONTENT_TYPE" => "application/json",
  input: JSON.generate(params.merge(client_id: client.fetch("client_id"), client_name: "Updated fixture"))))
raise response.body unless response.status == 200
updated = JSON.parse(response.body)
raise "credential not rotated" if updated.fetch("registration_access_token") == client.fetch("registration_access_token")
raise "old credential accepted" unless http.get(uri, bearer).status == 401
bearer = {"HTTP_AUTHORIZATION" => "Bearer #{updated.fetch('registration_access_token')}"}
raise "delete failed" unless http.delete(uri, bearer).status == 204
raise "client retained" if db[:oauth_applications].where(client_id: client.fetch("client_id")).first
raise "issued grant retained" unless db[:oauth_grants].empty?
raise "unrelated client removed" unless db[:oauth_applications].where(client_id: "demo-client").first
puts "PASS: installed-gem dynamic registration, verified CIBA issuance, management rotation and dependent deletion"
db.disconnect
