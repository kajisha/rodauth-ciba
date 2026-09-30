# frozen_string_literal: true
# Test-only TLS CA, trusted in a child process without disabling verification.
require "openssl"
require "tmpdir"
require "open3"
require "rbconfig"

unless ENV["CIBA_PING_TEST_CERT"]
  Dir.mktmpdir("ciba-ping-tls-") do |directory|
    key = OpenSSL::PKey::RSA.generate(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = cert.issuer = OpenSSL::X509::Name.parse("/CN=127.0.0.1")
    cert.public_key = key.public_key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 3600
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = factory.issuer_certificate = cert
    cert.add_extension(factory.create_extension("basicConstraints", "CA:TRUE", true))
    cert.add_extension(factory.create_extension("subjectAltName", "IP:127.0.0.1"))
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    cert_path = File.join(directory, "cert.pem")
    key_path = File.join(directory, "key.pem")
    File.write(cert_path, cert.to_pem)
    File.write(key_path, key.to_pem, perm: 0o600)
    env = {"CIBA_PING_TEST_CERT" => cert_path, "CIBA_PING_TEST_KEY" => key_path, "SSL_CERT_FILE" => cert_path}
    [env, env.merge("SSL_CERT_FILE" => nil, "CIBA_PING_UNTRUSTED" => "1")].each do |child_env|
      output, errors, status = Open3.capture3(child_env, RbConfig.ruby, __FILE__)
      print output
      warn errors unless errors.empty?
      raise "ping TLS smoke failed" unless status.success?
    end
  end
else
  require "webrick"
  require "webrick/https"
  require "rack/mock"
  require "json"
  require_relative "demo_app"
  received = []
  release_response = Queue.new
  untrusted = ENV["CIBA_PING_UNTRUSTED"]
  receiver_status = 204
  sector_status = 200
  sector_body = "[]"
  sector_location = "/sector-target"
  sector_redirect_body = "[]"
  sector_requests = []
  pairwise_client_key = OpenSSL::PKey::RSA.generate(2048)
  server = WEBrick::HTTPServer.new(BindAddress: "127.0.0.1", Port: 0, SSLEnable: true,
    SSLCertificate: OpenSSL::X509::Certificate.new(File.read(ENV.fetch("CIBA_PING_TEST_CERT"))),
    SSLPrivateKey: OpenSSL::PKey.read(File.read(ENV.fetch("CIBA_PING_TEST_KEY"))),
    Logger: WEBrick::Log.new(File::NULL), AccessLog: [])
  server.mount_proc("/notify") do |request, response|
    received << [request["authorization"], request["content-type"], JSON.parse(request.body)]
    release_response.pop if receiver_status == :timeout
    response.status = receiver_status == :timeout ? 204 : receiver_status
    response.body = "ignored" * 20_000 if receiver_status == 200
    response["Location"] = "/redirect-target" if receiver_status == 302
  end
  server.mount_proc("/sector") do |request, response|
    sector_requests << request["authorization"]
    response.status = sector_status
    response["Content-Type"] = "application/json"
    response["Location"] = sector_location if sector_status == 302
    response.body = sector_body
  end
  server.mount_proc("/sector-target") do |request, response|
    sector_requests << request["authorization"]
    response["Content-Type"] = "application/json"
    response.body = sector_redirect_body
  end
  server.mount_proc("/jwks") do |_request, response|
    response["Content-Type"] = "application/json"
    response.body = JSON.generate(keys: [JWT::JWK.new(pairwise_client_key.public_key).export])
  end
  thread = Thread.new { server.start }
  db = Sequel.sqlite
  begin
    CibaDemo.create_schema(db)
    Rodauth::CibaSupport::Schema.add_ping(db)
    db[:oauth_applications].update(backchannel_token_delivery_mode: "ping",
      backchannel_client_notification_endpoint: "https://127.0.0.1:#{server.config[:Port]}/notify")
    app = CibaDemo.build(db)
    app.plugin(:rodauth) do
      ciba_ping_enabled true
      # Exact local test receiver only; production default rejects loopback.
      ciba_http_address_allowed? { |address| address == "127.0.0.1" }
    end
    issuer = "http://127.0.0.1:9292"
    http = Rack::MockRequest.new(app)
    headers = {"HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64('demo-client:demo-secret')}"}
    auth = app.new(Rack::MockRequest.env_for(issuer)).rodauth
    account_id = db[:accounts].get(:id)
    (untrusted ? [204] : [204, 200, 503, 302, :timeout]).each do |code|
      response = http.post("#{issuer}/backchannel-authentication", headers.merge(params: {
        scope: "openid", login_hint: "customer@example.test", client_notification_token: "test-notification-token"
      }))
      raise response.body unless response.status == 200
      id = JSON.parse(response.body).fetch("auth_req_id")
      row_id = db[:ciba_requests].max(:id)
      receiver_status = code
      begin
        Timeout.timeout(8) { auth.approve_ciba_request(row_id, account_id: account_id) }
        raise "failure response accepted" if untrusted || ![200, 204].include?(code)
      rescue Rodauth::CibaSupport::PingDeliveryError => error
        raise if !untrusted && [200, 204].include?(code)
        raise "approval rolled back" unless auth.ciba_request(row_id)[:status] == "approved"
        if untrusted
          raise "wrong TLS rejection" unless error.cause.is_a?(OpenSSL::SSL::SSLError) && received.empty?
        else
          if code == :timeout
            raise "wrong timeout failure" unless error.cause.is_a?(Timeout::Error)
            release_response << true
          end
          receiver_status = 204
          raise "retry failed" unless auth.retry_ciba_ping(row_id) == :delivered
        end
      end
      unless untrusted
        raise "wrong notification" unless received.last == ["Bearer test-notification-token", "application/json", {"auth_req_id" => id}]
      end
      token = http.post("#{issuer}/token", headers.merge(params: {grant_type: Rodauth::CibaSupport::GRANT_TYPE, auth_req_id: id}))
      raise token.body unless token.status == 200
    end
    raise "unexpected automatic retry" unless received.size == (untrusted ? 0 : 8)
    puts(untrusted ? "PASS: installed-gem ping rejects untrusted TLS before sending credentials, retains approval and allows token collection" :
      "PASS: installed-gem ping over verified TLS, Bearer/JSON, 200/204, 503/302/timeout retain approval, explicit retry, token collection")

    # Reuse this process's trusted/untrusted TLS fixture for actual sector DCR.
    db.alter_table(:oauth_applications) do
      %i[name redirect_uri response_types registration_access_token jwks_uri sector_identifier_uri].each do |column|
        add_column column, String
      end
    end
    Rodauth::CibaSupport::Schema.add_registration_token_digest(db)
    Rodauth::CibaSupport::Schema.add_pairwise_subject(db)
    Rodauth::CibaSupport::Schema.create_client_assertions(db)
    pairwise_app = CibaDemo.build(db)
    pairwise_app.plugin(:rodauth) do
      enable :oauth_jwt_bearer_grant, :oauth_dynamic_client_registration
      ciba_dynamic_client_registration_enabled true
      ciba_pairwise_identifier do |account, oauth_application:, sector_identifier:|
        OpenSSL::HMAC.hexdigest("SHA256", "local-sector-fixture", JSON.generate([sector_identifier, account]))
      end
      ciba_pairwise_enabled true
      ciba_http_address_allowed? { |address| address == "127.0.0.1" }
      before_register { authorization_required unless request.env["HTTP_AUTHORIZATION"] == "Bearer local-sector-registration" }
    end
    pairwise_app.route do |r|
      rodauth.load_openid_configuration_route
      r.rodauth
    end
    pairwise_http = Rack::MockRequest.new(pairwise_app)
    base = "https://127.0.0.1:#{server.config[:Port]}"
    redirect = "https://rp.example.test/callback"
    sector_redirect_body = JSON.generate(["#{base}/jwks", redirect])
    metadata = {grant_types: [Rodauth::CibaSupport::GRANT_TYPE, "authorization_code"], response_types: ["code"],
      redirect_uris: [redirect], scope: "openid", subject_type: "pairwise", token_endpoint_auth_method: "private_key_jwt",
      backchannel_token_delivery_mode: "poll", jwks_uri: "#{base}/jwks", sector_identifier_uri: "#{base}/sector"}
    cases = untrusted ? [[200, JSON.generate(["#{base}/jwks", redirect]), 400]] : [
      [200, "not json", 400], [200, "{}", 400], [200, JSON.generate([redirect]), 400],
      [200, JSON.generate(["#{base}/jwks"]), 400], [302, "[]", 201], [503, "[]", 400],
      [302, "[]", 400, "/sector"], [302, "[]", 400, "file:///private/invalid"],
      [302, "[]", 400, "https://127.0.0.2/blocked"],
      [200, " " * 65_537, 400], [200, JSON.generate(["#{base}/jwks", redirect]), 201]]
    cases.each do |status, body, expected, location|
      sector_status, sector_body = status, body
      sector_location = location || "/sector-target"
      before = db[:oauth_applications].count
      response = pairwise_http.post("#{issuer}/register", "CONTENT_TYPE" => "application/json",
        "HTTP_AUTHORIZATION" => "Bearer local-sector-registration", input: JSON.generate(metadata))
      raise "sector registration #{response.status}: #{response.body}" unless response.status == expected
      if expected == 400
        raise "wrong sector error" unless JSON.parse(response.body)["error"] == "invalid_client_metadata"
        raise "failed registration persisted" unless db[:oauth_applications].count == before
      else
        client = JSON.parse(response.body)
        raise "pairwise metadata lost" unless client["subject_type"] == "pairwise"
        authenticate = lambda do
          {client_id: client.fetch("client_id"),
            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            client_assertion: JWT.encode({iss: client.fetch("client_id"), sub: client.fetch("client_id"),
              aud: issuer, exp: Time.now.to_i + 60, jti: SecureRandom.uuid}, pairwise_client_key, "RS256",
              kid: JWT::JWK.new(pairwise_client_key).kid)}
        end
        discovery = JSON.parse(pairwise_http.get("#{issuer}/.well-known/openid-configuration").body)
        begun = pairwise_http.post(discovery.fetch("backchannel_authentication_endpoint"), params: authenticate.call.merge(
          scope: "openid", login_hint: "customer@example.test"))
        raise begun.body unless begun.status == 200
        pending = JSON.parse(begun.body).fetch("auth_req_id")
        instance = pairwise_app.new(Rack::MockRequest.env_for(issuer)).rodauth
        instance.approve_ciba_request(db[:ciba_requests].max(:id), account_id: account_id)
        issued = pairwise_http.post(discovery.fetch("token_endpoint"), params: authenticate.call.merge(
          grant_type: Rodauth::CibaSupport::GRANT_TYPE, auth_req_id: pending))
        raise issued.body unless issued.status == 200
        tokens = JSON.parse(issued.body)
        keys = JSON.parse(pairwise_http.get(discovery.fetch("jwks_uri")).body)
        claims, = JWT.decode(tokens.fetch("id_token"), nil, true, jwks: keys, algorithms: ["RS256"],
          verify_iss: true, iss: issuer, verify_aud: true, aud: client.fetch("client_id"))
        expected_sub = OpenSSL::HMAC.hexdigest("SHA256", "local-sector-fixture", JSON.generate(["127.0.0.1:#{server.config[:Port]}", account_id]))
        raise "wrong pairwise subject" unless claims["sub"] == expected_sub
        raise "issuance subject not saved" unless db[:oauth_grants].where(oauth_application_id: db[:oauth_applications].where(client_id: client.fetch("client_id")).get(:id)).get(:ciba_subject) == expected_sub
        info = pairwise_http.get(discovery.fetch("userinfo_endpoint"), "HTTP_AUTHORIZATION" => "Bearer #{tokens.fetch('access_token')}")
        raise "wrong pairwise UserInfo" unless info.status == 200 && JSON.parse(info.body)["sub"] == expected_sub
      end
    end
    raise "credentials sent to sector endpoint" unless sector_requests.compact.empty?
    raise "untrusted TLS reached sector handler" if untrusted && !sector_requests.empty?
    raise "sector handler not reached" if !untrusted && sector_requests.empty?
    puts(untrusted ? "PASS: installed-gem sector registration rejects untrusted TLS without persistence" :
      "PASS: installed-gem hybrid pairwise sector DCR over verified TLS, safe redirect success, loop/invalid/blocked-target refusal, URI membership and malformed/oversized/HTTP-error refusal without persistence or credential forwarding")
    puts "PASS: installed-gem pairwise private_key_jwt over real TLS JWKS, approval, verified ID Token, saved subject and matching UserInfo" unless untrusted
    require_relative "edwards_tls_smoke"
    CibaEdwardsTlsSmoke.run(server, untrusted: untrusted)
    require_relative "encryption_tls_smoke"
    CibaEncryptionTlsSmoke.run(server, untrusted: untrusted)
  ensure
    release_response << true
    server.shutdown
    thread.join(5)
    thread.kill if thread.alive?
    db.disconnect
  end
end
