# frozen_string_literal: true
require "net/http"
require "json"
require "jwt"

issuer = "http://127.0.0.1:9292"
metadata = JSON.parse(Net::HTTP.get(URI("#{issuer}/.well-known/openid-configuration")))
def post_form(url, params)
  uri = URI(url)
  request = Net::HTTP::Post.new(uri)
  request.basic_auth("demo-client", "demo-secret")
  request.set_form_data(params)
  response = Net::HTTP.start(uri.host, uri.port) { |http| http.request(request) }
  [response.code.to_i, JSON.parse(response.body)]
end
status, request = post_form(metadata.fetch("backchannel_authentication_endpoint"),
  scope: "openid", login_hint: "customer@example.test", binding_message: "LOCAL-DEMO")
abort request.inspect unless status == 200
puts "Open #{issuer}/ and approve LOCAL-DEMO as the simulated customer."
interval = request.fetch("interval")
deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + request.fetch("expires_in")
loop do
  sleep interval
  abort "Request expired" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
  status, result = post_form(metadata.fetch("token_endpoint"),
    grant_type: "urn:openid:params:grant-type:ciba", auth_req_id: request.fetch("auth_req_id"))
  if status == 200
    keys = JSON.parse(Net::HTTP.get(URI(metadata.fetch("jwks_uri"))))
    claims, = JWT.decode(result.fetch("id_token"), nil, true, jwks: keys, algorithms: ["RS256"],
      verify_iss: true, iss: issuer, verify_aud: true, aud: "demo-client")
    puts "Verified ID Token for customer sub=#{claims.fetch('sub')}; received access token."
    break
  end
  case result["error"]
  when "authorization_pending" then next
  when "slow_down" then interval += 5
  else abort result.inspect
  end
end
