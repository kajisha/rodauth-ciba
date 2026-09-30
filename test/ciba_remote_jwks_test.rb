# frozen_string_literal: true
require_relative "ciba_signed_request_test"
require "webrick"

class CibaIntegrationTest
  def with_client_jwks_server
    enable_signed_requests
    @db.alter_table(:oauth_applications) { add_column :jwks_uri, String, text: true }
    state = {keys: [JWT::JWK.new(REQUEST_KEY.public_key).export], requests: 0, status: 200, cache: "no-cache"}
    server = WEBrick::HTTPServer.new(BindAddress: "127.0.0.1", Port: 0,
      Logger: WEBrick::Log.new(File::NULL), AccessLog: [])
    server.mount_proc("/jwks") do |_request, response|
      state[:requests] += 1
      response.status = state[:status]
      response["Content-Type"] = "application/json"
      response["Cache-Control"] = state[:cache]
      response["Expires"] = state[:expires] if state[:expires]
      response.body = state[:body] || JSON.generate(keys: state[:keys])
    end
    uri = "http://127.0.0.1:#{server.config[:Port]}/jwks"
    @db[:oauth_applications].update(jwks: nil, jwks_uri: uri)
    @app.plugin(:rodauth) { ciba_http_address_allowed? { |address| address == "127.0.0.1" } }
    thread = Thread.new { server.start }
    yield state, uri, server
  ensure
    server&.shutdown
    thread&.join(5)
    thread&.kill if thread&.alive?
    auth.send(:http_request_cache).uncache(URI(uri)) if uri
  end

  def test_signed_request_remote_jwks_rotation_cache_and_untrusted_header_url
    with_client_jwks_server do |state, uri, _server|
      state[:cache] = "max-age=3600"
      token = signed_ciba_request(header: {jku: "http://127.0.0.1:1/attacker", jwk: JWT::JWK.new(KEY.public_key).export})
      assert_equal 200, post("/backchannel-authentication", request: token).status
      assert_equal 1, state[:requests]
      state[:keys] = [JWT::JWK.new(KEY.public_key).export]
      # A new kid does not force upstream's cache to refresh.
      assert_error post("/backchannel-authentication", request: signed_ciba_request(key: KEY)), "invalid_request"
      assert_equal 200, post("/backchannel-authentication", request: token).status
      assert_equal 1, state[:requests]
      auth.send(:http_request_cache).uncache(URI(uri))
      state[:cache] = "no-cache"
      assert_equal 200, post("/backchannel-authentication", request: signed_ciba_request(key: KEY)).status
      assert_error post("/backchannel-authentication", request: token), "invalid_request"
      assert_equal 3, state[:requests]
    end
  end

  def test_signed_request_remote_jwks_failures_never_create_pending_requests
    with_client_jwks_server do |state, uri, server|
      ["not json", '{"keys":[]}', '{"keys":{}}'].each do |body|
        auth.send(:http_request_cache).uncache(URI(uri))
        state[:body] = body
        assert_error post("/backchannel-authentication", request: signed_ciba_request), "invalid_request"
      end
      auth.send(:http_request_cache).uncache(URI(uri))
      state[:status] = 503
      assert_error post("/backchannel-authentication", request: signed_ciba_request), "invalid_request"
      server.shutdown
      reports = []
      response = post("/backchannel-authentication", {request: signed_ciba_request}, "test.processing_error" => ->(error) { reports << error })
      assert_error response, "invalid_request"
      assert_empty reports
      assert_equal 0, @db[:ciba_requests].count
      response = post("/backchannel-authentication", {request: signed_ciba_request}, "HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64('support:wrong')}")
      assert_equal 401, response.status
    end
  end

  def test_signed_request_remote_jwks_default_denial_and_response_limit
    with_client_jwks_server do |state, _uri, _server|
      @app.plugin(:rodauth) { ciba_http_address_allowed? { |address| Rodauth::CibaSupport::HTTP.public_address?(address) } }
      assert_error post("/backchannel-authentication", request: signed_ciba_request), "invalid_request"
      assert_equal 0, state[:requests]
      @app.plugin(:rodauth) { ciba_http_address_allowed? { |address| address == "127.0.0.1" } }
      state[:body] = " " * 65_537
      assert_error post("/backchannel-authentication", request: signed_ciba_request), "invalid_request"
      assert_equal 1, state[:requests]
      assert_equal 0, @db[:ciba_requests].count
    end
  end
end
