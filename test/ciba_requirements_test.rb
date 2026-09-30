# frozen_string_literal: true
require_relative "test_helper"

class CibaIntegrationTest
  def ciba_requirements_request(overrides = {}, env = {})
    post("/backchannel-authentication", {login_hint: "customer@example.test", scope: "openid"}.merge(overrides), env)
  end

  def test_auth_req_id_has_required_entropy_and_restricted_characters
    ids = 2.times.map do
      response = ciba_requirements_request
      assert_equal 200, response.status, response.body
      JSON.parse(response.body).fetch("auth_req_id")
    end

    ids.each do |id|
      # 32 random bytes provide 256 bits; unpadded base64url encodes them in 43 chars.
      assert_equal 43, id.length
      assert_match(/\A[A-Za-z0-9._-]+\z/, id)
      refute_includes id, "="
    end
    refute_equal ids.first, ids.last
  end

  def test_acknowledgement_numeric_fields_and_configuration_limits
    [1, 5, 2_147_483_647].each do |interval|
      @app.plugin(:rodauth) { ciba_poll_interval interval }
      response = ciba_requirements_request
      assert_equal 200, response.status, response.body
      payload = JSON.parse(response.body)
      assert_kind_of Integer, payload.fetch("interval")
      assert_equal interval, payload.fetch("interval")
      assert_kind_of Integer, payload.fetch("expires_in")
      assert_operator payload.fetch("expires_in"), :>, 0
      assert_equal "no-store", response["cache-control"]
    end
    [0, -1, 1.5, "5", 2_147_483_648].each do |invalid|
      assert_raises(ArgumentError) { @app.plugin(:rodauth) { ciba_poll_interval invalid } }
    end
  end

  def test_acknowledgement_time_origin_matches_reference_application_delays
    now = 1_800_000_000
    clock = -> { now }
    @app.plugin(:rodauth) do
      resolve_ciba_login_hint do |hint, oauth_application:|
        scope.env.fetch("test.resolve_delay").call
        db[:accounts].where(email: hint).get(:id)
      end
    end
    [3, 25].each do |dispatch_delay|
      started = now
      response = ciba_requirements_request({requested_expiry: "20"},
        "test.now" => clock, "test.resolve_delay" => -> { now += 7 },
        "test.device" => ->(_row, _auth) { now += dispatch_delay })
      assert_equal 200, response.status, response.body
      payload = JSON.parse(response.body)
      row = @db[:ciba_requests].order(:id).last
      assert_equal started + 7, row[:created_at]
      assert_equal started + 27, row[:expires_at]
      assert_equal 20, payload.fetch("expires_in")
      assert_error poll(payload.fetch("auth_req_id"), "test.now" => clock),
        dispatch_delay < 20 ? "authorization_pending" : "expired_token"
    end
  end

  def test_requested_expiry_expires_at_the_exact_boundary
    now = 1_800_000_000
    clock = -> { now }
    response = ciba_requirements_request({requested_expiry: "2"}, "test.now" => clock)
    assert_equal 200, response.status, response.body
    payload = JSON.parse(response.body)
    assert_equal 2, payload.fetch("expires_in")

    now += 1
    assert_error poll(payload.fetch("auth_req_id"), "test.now" => clock), "authorization_pending"
    now += 1
    assert_error poll(payload.fetch("auth_req_id"), "test.now" => clock), "expired_token"
  end

  def test_authentication_error_envelopes_do_not_expose_tokens_or_internal_errors
    cases = [
      [{scope: nil}, {}, 400, "invalid_request"],
      [{scope: "not-allowed"}, {}, 400, "invalid_scope"],
      [{login_hint: "unknown"}, {}, 400, "unknown_user_id"],
      [{binding_message: "x" * 129}, {}, 400, "invalid_binding_message"],
      [{}, {"HTTP_AUTHORIZATION" => nil}, 401, "invalid_client"],
      [{}, {"test.before_request" => ->(_) { raise "private credential value" },
             "test.processing_error" => ->(_) {}}, 500, "server_error"]
    ]
    cases.each do |params, env, status, error|
      response = ciba_requirements_request(params, env)
      assert_equal status, response.status, response.body
      assert_match(/application\/json/, response["content-type"])
      assert_equal "no-store", response["cache-control"]
      assert_equal "no-cache", response["pragma"]
      payload = JSON.parse(response.body)
      assert_equal error, payload.fetch("error")
      assert_match(/\A[\x20-\x21\x23-\x5B\x5D-\x7E]+\z/, payload.fetch("error"))
      %w[access_token id_token refresh_token auth_req_id error_uri].each { |key| refute payload.key?(key) }
      refute_includes response.body, "private credential value"
    end
    assert_equal 0, @db[:ciba_requests].count
  end

  def test_application_can_reject_start_with_explicit_403_before_dispatch
    @app.plugin(:rodauth) do
      resolve_ciba_login_hint do |_hint, oauth_application:|
        ciba_error("access_denied", 403)
      end
    end
    dispatched = false
    response = ciba_requirements_request({}, "test.device" => ->(*) { dispatched = true })
    assert_equal 403, response.status, response.body
    assert_equal "access_denied", JSON.parse(response.body).fetch("error")
    assert_equal "no-store", response["cache-control"]
    refute JSON.parse(response.body).key?("auth_req_id")
    refute dispatched
    assert_equal 0, @db[:ciba_requests].count
  end

  def test_authentication_errors_use_invalid_client_and_http_401
    bad_credentials = "Basic #{Base64.strict_encode64('support:wrong-secret')}"
    response = ciba_requirements_request({}, "HTTP_AUTHORIZATION" => bad_credentials)
    assert_equal 401, response.status, response.body
    assert_equal "invalid_client", JSON.parse(response.body).fetch("error")
    assert_match(/\ABasic/, response["www-authenticate"])

    response = ciba_requirements_request({}, "HTTP_AUTHORIZATION" => nil)
    assert_equal 401, response.status, response.body
    assert_equal "invalid_client", JSON.parse(response.body).fetch("error")
    assert_match(/\ABasic/, response["www-authenticate"])
  end

  def test_scope_syntax_errors_are_invalid_scope
    # A missing required parameter is invalid_request; a present malformed scope is invalid_scope.
    assert_error ciba_requirements_request(scope: nil), "invalid_request"
    assert_error ciba_requirements_request(scope: "openid\tprofile"), "invalid_scope"
    assert_error ciba_requirements_request(scope: "openid\u00e9"), "invalid_scope"
    duplicate = post("/backchannel-authentication", {}, input: "scope=openid&scope=openid&login_hint=customer%40example.test",
      "CONTENT_TYPE" => "application/x-www-form-urlencoded")
    assert_error duplicate, "invalid_request"
  end

  def test_authentication_error_description_keeps_allowed_ascii_and_omits_unsafe_text
    {
      "Plain ASCII: allowed!" => "Plain ASCII: allowed!",
      "double \"quote\"" => nil,
      "back\\slash" => nil,
      "line\nbreak" => nil,
      "non-ASCII 日本語" => nil
    }.each do |message, expected|
      @app.plugin(:rodauth) do
        auth_class_eval do
          define_method(:oauth_invalid_scope_message) { message }
        end
      end

      response = ciba_requirements_request(scope: "not-a-permitted-scope")
      assert_equal 400, response.status, response.body
      payload = JSON.parse(response.body)
      assert_equal "invalid_scope", payload.fetch("error")
      refute payload.key?("error_uri")
      if expected
        assert_equal expected, payload.fetch("error_description")
      else
        refute payload.key?("error_description"), "unsafe message was returned: #{message.inspect}"
      end
    end
  end
end
