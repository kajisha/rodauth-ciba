# frozen_string_literal: true
require_relative "ciba_registration_test"
require "webrick"

class CibaIntegrationTest
  def test_registered_remote_assertion_keys_obey_outbound_policy_and_uri_replacement
    configure_dynamic_registration
    @db.alter_table(:oauth_applications) { add_column :jwks_uri, String, text: true }
    @app.plugin(:rodauth) { enable :oauth_jwt_bearer_grant }
    replacement = OpenSSL::PKey::RSA.generate(2048)
    hits = Hash.new(0)
    fault = nil
    served_keys = {"/old" => KEY, "/new" => replacement}
    server = WEBrick::HTTPServer.new(BindAddress: "127.0.0.1", Port: 0,
      Logger: WEBrick::Log.new(File::NULL), AccessLog: [])
    served_keys.each_key do |path|
      server.mount_proc(path) do |_request, response|
        hits[path] += 1
        response["Content-Type"] = "application/json"
        response["Cache-Control"] = "max-age=3600"
        response.body = JSON.generate(keys: [JWT::JWK.new(served_keys.fetch(path).public_key).export])
        if fault
          response["Cache-Control"] = "no-cache"
          response.body = fault
        end
      end
    end
    thread = Thread.new { server.start }
    base = "http://127.0.0.1:#{server.config[:Port]}"
    # Test-only URI policy permits this exact loopback fixture. The outbound
    # address policy remains at its default for the first authentication.
    @app.plugin(:rodauth) do
      auth_class_eval do
        define_method(:check_valid_uri?) { |uri| ["#{base}/old", "#{base}/new"].include?(uri) || super(uri) }
      end
    end
    params = registration_params.merge("token_endpoint_auth_method" => "private_key_jwt", "jwks_uri" => "#{base}/old")
    response = register(params)
    assert_equal 201, response.status, response.body
    client = JSON.parse(response.body)
    start = lambda do |key|
      assertion = JWT.encode({iss: client.fetch("client_id"), sub: client.fetch("client_id"),
        aud: "https://op.example.test", exp: Time.now.to_i + 60, jti: SecureRandom.uuid}, key, "RS256", kid: JWT::JWK.new(key).kid)
      post("/backchannel-authentication", {scope: "openid", login_hint: "customer@example.test",
        client_id: client.fetch("client_id"), client_assertion: assertion,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "HTTP_AUTHORIZATION" => nil)
    end
    response = start.call(KEY)
    assert_equal 401, response.status, response.body
    assert_equal 0, hits.values.sum
    @app.plugin(:rodauth) { ciba_http_address_allowed? { |address| address == "127.0.0.1" } }
    ["not json", " " * 65_537].each do |body|
      fault = body
      response = start.call(KEY)
      assert_equal 401, response.status, response.body
      assert_equal 0, @db[:ciba_requests].count
    end
    fault = nil
    hits.clear
    response = start.call(KEY)
    assert_equal 200, response.status, response.body
    assert_equal 200, start.call(KEY).status
    assert_equal 1, hits["/old"]
    served_keys["/old"] = replacement
    assert_equal 401, start.call(replacement).status
    assert_equal 200, start.call(KEY).status
    assert_equal 1, hits["/old"]
    response = Rack::MockRequest.new(@app).put(client.fetch("registration_client_uri"),
      "HTTP_AUTHORIZATION" => "Bearer #{client.fetch('registration_access_token')}",
      "CONTENT_TYPE" => "application/json", input: JSON.generate(params.merge(
        "client_id" => client.fetch("client_id"), "jwks_uri" => "#{base}/new")))
    assert_equal 200, response.status, response.body
    assert_equal 401, start.call(KEY).status
    response = start.call(replacement)
    assert_equal 200, response.status, response.body
    assert_equal 1, hits["/old"]
    assert_equal 1, hits["/new"]
  ensure
    server&.shutdown
    thread&.join(5)
    thread&.kill if thread&.alive?
    %w[old new].each { |path| auth.send(:http_request_cache).uncache(URI("#{base}/#{path}")) } if base
  end
end
