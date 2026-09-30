# frozen_string_literal: true
require_relative "test_helper"
require "rodauth/oauth/ttl_store"
require_relative "ciba_mtls_remote_test"
require_relative "ciba_ecdh_remote_test"

class CibaJwksCacheTest < Minitest::Test
  Cache = Rodauth::CibaSupport::JwksCache
  def setup
    @clock = 100.0
    @cache = Cache.new(Rodauth::OAuth::TtlStore.new)
    owner = self
    @cache.define_singleton_method(:now) { owner.instance_variable_get(:@clock) }
    @key = URI("https://keys.example.test/jwks")
  end

  def response(control = "max-age=10, stale-if-error=60", keys: [1], code: 200, headers: {})
    result = Net::HTTPResponse.new("1.1", code.to_s, "fixture")
    result["cache-control"] = control if control
    headers.each { |name, value| result[name] = value }
    result.body = JSON.generate(keys: keys.map { |id| {kid: id.to_s} })
    result.instance_variable_set(:@read, true)
    result
  end

  def fetch(result = response, &block)
    @cache.fetch(@key, &(block || -> { result }))
  end

  def test_grace_is_capped_fixed_and_checked_after_network
    first = fetch(response("max-age=10, stale-if-error=600"))
    @clock = 110
    assert_equal first, fetch(response(code: 503))
    @clock = 169.9
    assert_equal first, fetch(response(code: 502))
    assert_raises(Cache::StatusError) do
      fetch { @clock = 170; response(code: 504) }
    end
    assert_equal "2", fetch(response(keys: [2]))[:keys][0][:kid]
  end

  def test_publisher_shorter_grace_and_timeout
    first = fetch(response("max-age=2, stale-if-error=3"))
    @clock = 104.9
    assert_equal first, fetch { raise Timeout::Error }
    @clock = 105
    assert_raises(Timeout::Error) { fetch { raise Timeout::Error } }
    @cache.uncache(@key)
    assert_raises(Cache::StatusError) { fetch(response(code: 503)) }
  end

  def test_restrictive_absent_ambiguous_and_variant_directives
    [nil, "", "no-cache, max-age=10, stale-if-error=60", "no-store, max-age=10",
      "max-age=10, max-age=20", "max-age=oops", "max-age=10, stale-if-error=oops"].each do |control|
      @cache.uncache(@key)
      fetch(response(control))
      assert_equal "2", fetch(response(control, keys: [2]))[:keys][0][:kid], control.inspect
    end
    ["max-age=10", "max-age=10, must-revalidate, stale-if-error=60",
      "max-age=10, proxy-revalidate, stale-if-error=60", "max-age=10, s-maxage=5, stale-if-error=60"].each do |control|
      @cache.uncache(@key)
      fetch(response(control))
      @clock += 10
      assert_raises(Cache::StatusError) { fetch(response(code: 503)) }
    end
    fetch(response(headers: {"Vary" => "Accept"}))
    assert_equal "2", fetch(response(keys: [2]))[:keys][0][:kid]
  end

  def test_freshness_precedence_age_delay_and_invalid_dates
    first = fetch(response('MAX-AGE="10", stale-if-error=5', headers: {"Expires" => (Time.now + 500).httpdate, "Age" => "9"}))
    @clock += 0.9
    assert_equal first, fetch { flunk "fresh keys should not fetch" }
    @clock += 0.1
    assert_equal first, fetch(response(code: 503))
    @clock += 5
    assert_raises(Cache::StatusError) { fetch(response(code: 503)) }
    @cache.uncache(@key)
    fetch { @clock += 8; response("max-age=10", headers: {"Age" => "2"}) }
    assert_equal "2", fetch(response(keys: [2]))[:keys][0][:kid]
    @cache.uncache(@key)
    first = fetch(response(nil, headers: {"Date" => Time.now.httpdate, "Expires" => (Time.now + 20).httpdate}))
    @clock += 18
    assert_equal first, fetch { flunk "Expires should retain keys" }
    @clock += 2
    assert_equal "2", fetch(response(keys: [2]))[:keys][0][:kid]
    @cache.uncache(@key)
    fetch(response(nil, headers: {"Expires" => "invalid"}))
    assert_equal "2", fetch(response(keys: [2]))[:keys][0][:kid]
  end

  def test_nontransient_failures_disable_later_fallback
    [response(code: 404), response(code: 501), response(code: 302),
      -> { raise OpenSSL::SSL::SSLError }, -> { raise Rodauth::CibaSupport::HTTP::Error },
      -> { r = response; r.body = "invalid JSON"; r },
      -> { r = response; r.body = '{"keys":{}}'; r }].each do |failure|
      @cache.uncache(@key)
      fetch
      @clock += 10
      assert_raises(StandardError) { failure.respond_to?(:call) ? fetch(&failure) : fetch(failure) }
      assert_raises(Cache::StatusError) { fetch(response(code: 503)) }
    end
  end

  def test_successful_removal_and_eviction_never_restore_old_keys
    fetch
    @clock += 10
    assert_equal [], fetch(response(keys: []))[:keys]
    @clock += 10
    assert_equal [], fetch(response(code: 503))[:keys]
    @cache.uncache(@key)
    assert_raises(Cache::StatusError) { fetch(response(code: 503)) }
  end

  def test_concurrent_eviction_or_replacement_wins_over_old_snapshot
    [false, true].each do |replace|
      @cache.uncache(@key)
      fetch
      @clock += 10
      entered, resume = Queue.new, Queue.new
      thread = Thread.new do
        fetch { entered << true; resume.pop; response(code: 503) }
      rescue Cache::StatusError => error
        error
      end
      entered.pop
      @cache.uncache(@key)
      fetch(response(keys: [2])) if replace
      resume << true
      result = thread.value
      replace ? assert_equal("2", result[:keys][0][:kid]) : assert_kind_of(Cache::StatusError, result)
    ensure
      resume << true if resume
      thread&.join
    end
  end
end

class CibaIntegrationTest
  def test_signed_request_uses_only_explicit_stale_allowance
    with_client_jwks_server do |state, _uri, _server|
      cache = auth.send(:http_request_cache)
      clock = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      cache.define_singleton_method(:now) { clock }
      state[:cache] = "max-age=10, stale-if-error=3"
      assert_equal 200, post("/backchannel-authentication", request: signed_ciba_request).status
      clock += 10
      state[:status] = 503
      assert_equal 200, post("/backchannel-authentication", request: signed_ciba_request).status
      clock += 3
      count = @db[:ciba_requests].count
      assert_error post("/backchannel-authentication", request: signed_ciba_request), "invalid_request"
      assert_equal count, @db[:ciba_requests].count
    ensure
      cache&.singleton_class&.remove_method(:now)
    end
  end
end

class CibaIntegrationTest
  def test_mtls_publisher_authorized_stale_authentication
    with_client_jwks_server do |state, _uri, _server|
      key = REQUEST_KEY
      certificate = mtls_certificate(key, 1)
      @db.alter_table(:oauth_grants) { add_column :certificate_thumbprint, String }
      @db[:oauth_applications].update(token_endpoint_auth_method: "self_signed_tls_client_auth",
        backchannel_authentication_request_signing_alg: nil)
      @app.plugin(:rodauth) do
        enable :oauth_tls_client_auth
        ciba_tls_client_certificate { scope.env["test.tls_certificate"] }
      end
      cache = auth.send(:http_request_cache)
      clock = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      cache.define_singleton_method(:now) { clock }
      state[:keys] = [JWT::JWK.new(key.public_key).export.merge(x5c: [Base64.strict_encode64(certificate.to_der)])]
      state[:cache] = "max-age=10, stale-if-error=2"
      start = -> { post("/backchannel-authentication", {client_id: "support", scope: "openid", login_hint: "customer@example.test"},
        "HTTP_AUTHORIZATION" => nil, "test.tls_certificate" => certificate) }
      assert_equal 200, start.call.status
      clock += 10
      state[:status] = 503
      assert_equal 200, start.call.status
      clock += 2
      count = @db[:ciba_requests].count
      assert_equal 400, start.call.status
      assert_equal count, @db[:ciba_requests].count
    ensure
      cache&.singleton_class&.remove_method(:now)
    end
  end
end
