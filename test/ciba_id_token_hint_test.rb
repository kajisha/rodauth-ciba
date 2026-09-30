# frozen_string_literal: true
require_relative "test_helper"

class CibaIntegrationTest
  def enable_id_hint
    calls = @id_hint_calls = []
    @app.plugin(:rodauth) do
      ciba_id_token_hint_enabled true
      resolve_ciba_id_token_subject do |subject, oauth_application:|
        calls << [subject, oauth_application[:client_id]]
        db[:accounts].where(id: subject.to_i).get(:id) if subject.match?(/\A[0-9]+\z/)
      end
    end
  end

  def signed_id_hint(changes = {}, key: KEY, algorithm: "RS256", headers: {}, omit: [])
    claims = {"iss" => "https://op.example.test", "aud" => "support", "sub" => @account_id.to_s,
      "iat" => Time.now.to_i - 7200, "exp" => Time.now.to_i - 3600}.merge(changes)
    omit.each { |name| claims.delete(name) }
    if algorithm == "RS256"
      input = [{alg: algorithm}.merge(headers), claims].map { |part| Base64.urlsafe_encode64(JSON.generate(part), padding: false) }.join(".")
      return input + "." + Base64.urlsafe_encode64(key.sign("SHA256", input), padding: false)
    end
    JWT.encode(claims, key, algorithm, headers)
  end

  def request_id_hint(token, extra = {}, env = {})
    post("/backchannel-authentication", {scope: "openid", id_token_hint: token}.merge(extra), env)
  end

  def test_id_hint_expired_token_is_only_an_identity_hint
    enable_id_hint
    token = signed_id_hint
    snapshots = []
    response = request_id_hint(token, {}, "test.device" => ->(row, _) { snapshots << row },
      "test.observe" => ->(event) { snapshots << event })
    assert_equal 200, response.status, response.body
    assert_equal [[@account_id.to_s, "support"]], @id_hint_calls
    refute_includes JSON.generate(snapshots + @db[:ciba_requests].all), token
    id = JSON.parse(response.body).fetch("auth_req_id")
    assert_error poll(id), "authorization_pending"
    approve(id)
    result = poll(id, "test.now" => -> { Time.now.to_i + 10 })
    assert_equal 200, result.status, result.body
    assert_equal @account_id.to_s, decode_id_token(result).last.fetch("sub")
    # The ordinary JWT decoder must continue rejecting this expired token.
    assert_nil auth.send(:jwt_decode, token)
  end

  def test_id_hint_requires_opt_in_subject_mapping_and_exactly_one_hint
    assert_error request_id_hint(signed_id_hint), "invalid_request"
    assert_raises(Rodauth::CibaSupport::ConfigurationError) do
      @app.plugin(:rodauth) { ciba_id_token_hint_enabled true }
    end
    enable_id_hint
    ["", "bad", "x" * 8193, ["x"]].each { |token| assert_error request_id_hint(token), "invalid_request" }
    assert_error request_id_hint(signed_id_hint, login_hint: "customer@example.test"), "invalid_request"
    assert_empty @id_hint_calls
  end

  def test_id_hint_rejects_valid_nested_encryption_before_resolving_identity
    enable_id_hint
    # Construct a real JWE using OpenSSL only in the fixture. Production does
    # not gain a decryption path or a JOSE dependency from this rejection test.
    signed = signed_id_hint
    protected_header = Base64.urlsafe_encode64(JSON.generate(
      alg: "RSA-OAEP-256", enc: "A256GCM", cty: "JWT"), padding: false)
    content_key = SecureRandom.random_bytes(32)
    iv = SecureRandom.random_bytes(12)
    cipher = OpenSSL::Cipher.new("aes-256-gcm")
    cipher.encrypt
    cipher.key = content_key
    cipher.iv = iv
    cipher.auth_data = protected_header
    encrypted = cipher.update(signed) + cipher.final
    tag = cipher.auth_tag
    options = {"rsa_padding_mode" => "oaep", "rsa_oaep_md" => "sha256", "rsa_mgf1_md" => "sha256"}
    wrapped_key = KEY.public_key.encrypt(content_key, options)
    token = ([protected_header] + [wrapped_key, iv, encrypted, tag].map do |part|
      Base64.urlsafe_encode64(part, padding: false)
    end).join(".")
    # Prove the fixture is authenticated encryption of the valid signed hint.
    cipher = OpenSSL::Cipher.new("aes-256-gcm")
    cipher.decrypt
    cipher.key = KEY.decrypt(wrapped_key, options)
    cipher.iv = iv
    cipher.auth_tag = tag
    cipher.auth_data = protected_header
    assert_equal signed, cipher.update(encrypted) + cipher.final
    @app.plugin(:rodauth) { oauth_jwt_jwe_keys(["RSA-OAEP-256", "A256GCM"] => KEY) }
    assert_error request_id_hint(token), "invalid_request"
    assert_empty @id_hint_calls
    assert_equal 0, @db[:ciba_requests].count
    # Removing the JWE envelope leaves an accepted, still-unapproved hint.
    response = request_id_hint(signed)
    assert_equal 200, response.status, response.body
    assert_error poll(JSON.parse(response.body).fetch("auth_req_id")), "authorization_pending"
  end

  def test_id_hint_reference_validation_profile_never_inherits_approval
    enable_id_hint
    now = Time.now.to_i
    hints = [signed_id_hint({"azp" => "other"}),
      signed_id_hint({"iat" => now + 3600}),
      signed_id_hint({"iat" => now - 0.5, "exp" => now - 0.5, "nbf" => now - 0.5}),
      signed_id_hint(omit: %w[iat exp]), signed_id_hint({"exp" => "ignored for hint"}),
      signed_id_hint(headers: {typ: "at+jwt"}),
      signed_id_hint(headers: {b64: true, crit: ["b64"]})]
    hints.each do |hint|
      response = request_id_hint(hint)
      assert_equal 200, response.status, response.body
      id = JSON.parse(response.body).fetch("auth_req_id")
      assert_error poll(id), "authorization_pending"
    end
    assert_equal hints.size, @db[:ciba_requests].where(status: "pending").count
    assert_equal 0, @db[:ciba_grants].count
    assert_equal 0, @db[:oauth_grants].count
    assert_error request_id_hint(signed_id_hint({"iat" => now + 3600}, omit: ["exp"])), "invalid_request"
    assert_error request_id_hint(signed_id_hint({"jti" => 1})), "invalid_request"
    assert_error request_id_hint(signed_id_hint(headers: {crit: ["unknown"], unknown: true})), "invalid_request"
    @app.plugin(:rodauth) { ciba_id_token_hint_max_age 60 }
    assert_error request_id_hint(signed_id_hint(omit: ["iat"])), "invalid_request"
  end

  def test_id_hint_rejects_untrusted_claims_and_signatures_before_subject_resolution
    enable_id_hint
    [{"iss" => "https://other.example"}, {"aud" => "other"}, {"sub" => nil},
      {"sub" => 1}, {"nbf" => Time.now.to_i + 3600}].each do |changes|
      assert_error request_id_hint(signed_id_hint(changes)), "invalid_request"
    end
    assert_error request_id_hint(signed_id_hint(key: OpenSSL::PKey::RSA.generate(2048))), "invalid_request"
    assert_error request_id_hint(signed_id_hint(key: "secret", algorithm: "HS256")), "invalid_request"
    assert_error request_id_hint(signed_id_hint(headers: {kid: "unknown"})), "invalid_request"
    assert_empty @id_hint_calls
    assert_equal 0, @db[:ciba_requests].count
  end

  def test_id_hint_retained_keys_audience_array_age_and_account_policy
    enable_id_hint
    old_key = OpenSSL::PKey::RSA.generate(2048)
    @app.plugin(:rodauth) { oauth_jwt_public_keys("RS256" => [KEY.public_key, old_key.public_key]) }
    token = signed_id_hint({"aud" => ["support", "other"]}, key: old_key,
      headers: {kid: JWT::JWK.new(old_key).kid})
    assert_equal 200, request_id_hint(token).status
    assert_equal 200, request_id_hint(signed_id_hint(key: old_key)).status
    @app.plugin(:rodauth) { oauth_jwt_public_keys("RS256" => KEY.public_key) }
    assert_error request_id_hint(token), "invalid_request"
    @app.plugin(:rodauth) { ciba_id_token_hint_max_age 60 }
    assert_error request_id_hint(signed_id_hint), "invalid_request"
    assert_equal 200, request_id_hint(signed_id_hint({"iat" => Time.now.to_i, "exp" => Time.now.to_i + 60})).status
    @app.plugin(:rodauth) { ciba_id_token_hint_max_age nil }
    assert_error request_id_hint(signed_id_hint({"sub" => "999999"})), "unknown_user_id"
    @db[:accounts].where(id: @account_id).update(status_id: 3)
    assert_error request_id_hint(signed_id_hint), "unknown_user_id"
  end

  def test_id_hint_accepts_actual_op_tokens_with_configured_rsa_ec_and_hmac_keys
    enable_id_hint
    secret = "c" * 64
    @db[:oauth_applications].update(client_secret: secret)
    authentication = {"HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64("support:#{secret}")}"}
    algorithms = %w[RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES384 ES512 HS256 HS384 HS512]
    algorithms.each do |algorithm|
      curve = {"ES256" => "prime256v1", "ES384" => "secp384r1", "ES512" => "secp521r1"}[algorithm]
      key = algorithm.start_with?("HS") ? secret : (curve ? OpenSSL::PKey::EC.generate(curve) : KEY)
      wrong_key = algorithm.start_with?("HS") ? "o" * 64 : (curve ? OpenSSL::PKey::EC.generate(curve) : OpenSSL::PKey::RSA.generate(2048))
      @app.plugin(:rodauth) do
        oauth_jwt_keys(algorithm => (algorithm.start_with?("HS") ? wrong_key : key))
        oauth_jwt_public_keys({})
      end
      accepted = post("/backchannel-authentication", {scope: "openid", login_hint: "customer@example.test"}, authentication)
      assert_equal 200, accepted.status, accepted.body
      id = JSON.parse(accepted.body).fetch("auth_req_id")
      approve(id)
      issued = poll(id, authentication)
      assert_equal 200, issued.status, "#{algorithm}: #{issued.body}"
      token = JSON.parse(issued.body).fetch("id_token")
      claims, header = JWT.decode(token, key, true, algorithms: [algorithm],
        verify_iss: true, iss: "https://op.example.test", verify_aud: true, aud: "support")
      assert_equal @account_id.to_s, claims.fetch("sub")
      before = @db[:ciba_requests].count
      forged = JWT.encode(claims, wrong_key, algorithm, header)
      assert_error request_id_hint(forged, {}, authentication), "invalid_request"
      assert_equal before, @db[:ciba_requests].count
      result = request_id_hint(token, {}, authentication)
      assert_equal 200, result.status, "#{algorithm}: #{result.body}"
      assert_error poll(JSON.parse(result.body).fetch("auth_req_id"), authentication), "authorization_pending"
      expired = JWT.encode(claims.merge("iat" => Time.now.to_i - 7200, "exp" => Time.now.to_i - 3600), key, algorithm, header)
      expired_result = request_id_hint(expired, {}, authentication)
      assert_equal 200, expired_result.status, "#{algorithm}: #{expired_result.body}"
      assert_error poll(JSON.parse(expired_result.body).fetch("auth_req_id"), authentication), "authorization_pending"
    end
    @app.plugin(:rodauth) { oauth_jwt_keys("HS256" => "o" * 64) }
    # The upstream OP signing secret must not replace this client's secret.
    assert_error request_id_hint(signed_id_hint(key: "o" * 64, algorithm: "HS256"), {}, authentication), "invalid_request"
  end

  def test_id_hint_malformed_signed_claims_are_protocol_errors
    enable_id_hint
    payload, = JWT.decode(signed_id_hint, nil, false)
    [{"iat" => nil}, {"nbf" => "tomorrow"}, {"aud" => {}},
      {"sub" => []}].each do |changes|
      parts = [{alg: "RS256"}, payload.merge(changes)].map { |value| Base64.urlsafe_encode64(JSON.generate(value), padding: false) }
      input = parts.join(".")
      token = input + "." + Base64.urlsafe_encode64(KEY.sign("SHA256", input), padding: false)
      assert_error request_id_hint(token), "invalid_request"
    end
    assert_empty @id_hint_calls
  end
end
