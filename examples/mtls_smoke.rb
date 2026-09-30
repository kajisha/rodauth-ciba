# frozen_string_literal: true
# Installed-artifact fixture, with actual TLS peer certificates and local trust.
require "webrick"
require "webrick/https"
require "net/http"
require "rack/mock"
require "timeout"
require "tmpdir"
require "open3"
require "rbconfig"
require "json"
require "base64"
require "digest"
require_relative "demo_app"

module CibaMtlsSmoke
  def self.certificate(key, name, serial, server: false)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = serial
    cert.subject = cert.issuer = OpenSSL::X509::Name.parse("/CN=#{name}")
    cert.public_key = key.public_key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 3600
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = factory.issuer_certificate = cert
    cert.add_extension(factory.create_extension("basicConstraints", "CA:TRUE", true))
    cert.add_extension(factory.create_extension("keyUsage", "digitalSignature,keyEncipherment,keyCertSign", true))
    cert.add_extension(factory.create_extension("extendedKeyUsage", server ? "serverAuth" : "clientAuth"))
    cert.add_extension(factory.create_extension("subjectAltName", "IP:127.0.0.1")) if server
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
  end

  def self.run
    unless ENV["CIBA_MTLS_TEST_CERT"]
      Dir.mktmpdir("ciba-mtls-tls-") do |directory|
        key = OpenSSL::PKey::RSA.generate(2048)
        cert = certificate(key, "localhost", 1, server: true)
        cert_path, key_path = %w[cert.pem key.pem].map { |name| File.join(directory, name) }
        File.write(cert_path, cert.to_pem)
        File.write(key_path, key.to_pem, perm: 0o600)
        env = {"CIBA_MTLS_TEST_CERT" => cert_path, "CIBA_MTLS_TEST_KEY" => key_path, "SSL_CERT_FILE" => cert_path}
        output, errors, status = Open3.capture3(env, RbConfig.ruby, __FILE__)
        print output
        warn errors unless errors.empty?
        raise "mTLS installed smoke failed" unless status.success?
      end
      return
    end
    server_key = OpenSSL::PKey.read(File.read(ENV.fetch("CIBA_MTLS_TEST_KEY")))
    server_cert = OpenSSL::X509::Certificate.new(File.read(ENV.fetch("CIBA_MTLS_TEST_CERT")))
    client_key = OpenSSL::PKey::RSA.generate(2048)
    client_cert = certificate(client_key, "client", 2)
    other_cert = certificate(client_key, "client", 3)
    foreign_key = OpenSSL::PKey::RSA.generate(2048)
    foreign_cert = certificate(foreign_key, "client", 4)
    expected = Base64.urlsafe_encode64(Digest::SHA256.digest(client_cert.to_der), padding: false)
    %w[tls_client_auth self_signed_tls_client_auth].product([false, true]).each do |method, jwt|
      database = Sequel.sqlite(max_connections: 1)
      ready = Queue.new
      server_options = {BindAddress: "127.0.0.1", Port: 0, SSLEnable: true,
        SSLCertificate: server_cert, SSLPrivateKey: server_key,
        SSLVerifyClient: OpenSSL::SSL::VERIFY_PEER,
        # Self-signed clients need to reach the application. PKI verification
        # below separately validates the actual peer against the fixture CA.
        SSLVerifyCallback: ->(_ok, _context) { true },
        StartCallback: -> { ready << true }, Logger: WEBrick::Log.new(File::NULL), AccessLog: []}
      server = WEBrick::HTTPServer.new(server_options)
      alias_server = WEBrick::HTTPServer.new(server_options)
      alias_thread = nil
      publish_aliases = false
      alias_keys = %w[backchannel_authentication_endpoint token_endpoint introspection_endpoint userinfo_endpoint]
      thread = nil
      begin
        issuer = "https://127.0.0.1:#{server.config[:Port]}"
        alias_origin = "https://127.0.0.1:#{alias_server.config[:Port]}"
        CibaDemo.create_schema(database)
        Rodauth::CibaSupport::Schema.create_refresh_tokens(database)
        Rodauth::CibaSupport::Schema.create_client_assertions(database)
        Rodauth::CibaSupport::Schema.add_registration_token_digest(database)
        Rodauth::CibaSupport::Schema.add_pairwise_subject(database)
        database.alter_table(:oauth_grants) do
          add_column :certificate_thumbprint, String
          add_column :dpop_jkt, String
        end
        database.alter_table(:oauth_applications) do
          add_column :jwks, String, text: true
          add_column :jwks_uri, String, text: true
          add_column :tls_client_auth_subject_dn, String
          add_column :tls_client_certificate_bound_access_tokens, TrueClass
          add_column :dpop_bound_access_tokens, TrueClass
          add_column :name, String
          add_column :redirect_uri, String, text: true
          add_column :response_types, String
          add_column :registration_access_token, String
        end
        jwk = JWT::JWK.new(client_key.public_key).export.merge(x5c: [Base64.strict_encode64(client_cert.to_der)])
        remote_keys, remote_status, remote_hits = [jwk], 200, 0
        remote_uri = "#{issuer}/client-jwks"
        app = CibaDemo.build(database)
        app.plugin(:rodauth) do
          enable :oauth_tls_client_auth, :oauth_token_introspection, :oauth_dynamic_client_registration, :oauth_dpop
          # CIBA client policy remains authoritative even when upstream forces
          # certificate binding for its ordinary OAuth grants.
          oauth_tls_client_certificate_bound_access_tokens true
          ciba_dynamic_client_registration_enabled true
          ciba_pairwise_enabled true
          ciba_pairwise_identifier do |account_id, oauth_application:, sector_identifier:|
            OpenSSL::HMAC.hexdigest("SHA256", "local-pairwise-fixture-secret", JSON.generate([sector_identifier, account_id]))
          end
          before_register do
            authorization_required unless request.env["HTTP_AUTHORIZATION"] == "Bearer local-mtls-registration"
          end
          base_url issuer
          authorization_server_url issuer
          ciba_require_tls true
          oauth_jwt_access_tokens jwt
          ciba_refresh_tokens_enabled true
          oauth_application_scopes %w[openid offline_access]
          ciba_http_address_allowed? { |address| address == "127.0.0.1" }
          ciba_tls_client_certificate { request.env["ciba.tls.peer_certificate"] }
          ciba_tls_client_certificate_authorized? do
            store = OpenSSL::X509::Store.new
            store.add_cert(client_cert)
            peer = ciba_tls_client_certificate
            peer && store.verify(peer)
          end
          ciba_tls_client_certificate_subject_matches? do |property, value|
            property == :tls_client_auth_subject_dn &&
              ciba_tls_client_certificate.subject.cmp(OpenSSL::X509::Name.parse(value)).zero?
          end
        end
        app.route do |r|
          rodauth.load_openid_configuration_route
          r.rodauth
          rodauth.load_registration_client_uri_routes
        end
        [server, alias_server].each do |listener|
          listener_origin = "https://127.0.0.1:#{listener.config[:Port]}"
          listener.mount_proc("/") do |incoming, outgoing|
            env = Rack::MockRequest.env_for("#{listener_origin}#{incoming.unparsed_uri}", method: incoming.request_method, input: incoming.body.to_s)
            incoming.header.each do |name, values|
              key = name.upcase.tr("-", "_")
              env[%w[CONTENT_TYPE CONTENT_LENGTH].include?(key) ? key : "HTTP_#{key}"] = values.join(",")
            end
            # This value comes from WEBrick's TLS socket, never request headers.
            env["ciba.tls.peer_certificate"] = incoming.client_cert
            status, headers, body = app.call(env)
            outgoing.status = status
            headers.each { |name, value| outgoing[name] = value }
            outgoing.body = +""
            begin
              body.each { |chunk| outgoing.body << chunk }
            ensure
              body.close if body.respond_to?(:close)
            end
            # Application-owned Discovery middleware; no alternate issuer or
            # certificate assertions are taken from client-provided headers.
            if publish_aliases && incoming.path == "/.well-known/openid-configuration" && status == 200
              document = JSON.parse(outgoing.body)
              document["mtls_endpoint_aliases"] = alias_keys.to_h do |name|
                [name, "#{alias_origin}#{URI(document.fetch(name)).path}"]
              end
              outgoing.body = JSON.generate(document)
              outgoing["Content-Length"] = outgoing.body.bytesize.to_s
            end
          end
        end
        server.mount_proc("/client-jwks") do |_incoming, outgoing|
          remote_hits += 1
          outgoing.status = remote_status
          outgoing["Content-Type"] = "application/json"
          outgoing["Cache-Control"] = "max-age=3600"
          outgoing.body = JSON.generate(keys: remote_keys)
        end
        thread = Thread.new { server.start }
        alias_thread = Thread.new { alias_server.start }
        Timeout.timeout(5) { 2.times { ready.pop } }
        send_request = lambda do |url, params = nil, cert = client_cert, key = client_key, headers = {}, verb = nil|
          uri = URI(url)
          http = Net::HTTP.new(uri.host, uri.port, nil)
          http.use_ssl = true
          trust = OpenSSL::X509::Store.new
          trust.add_cert(server_cert)
          http.cert_store = trust
          http.verify_mode = OpenSSL::SSL::VERIFY_PEER
          http.verify_hostname = true
          http.cert, http.key = cert, key if cert
          http.open_timeout = http.read_timeout = 5
          request_class = verb == "PUT" ? Net::HTTP::Put : (params ? Net::HTTP::Post : Net::HTTP::Get)
          request = request_class.new(uri, headers)
          if params
            if headers["Content-Type"] == "application/json"
              request.body = JSON.generate(params)
            else
              request.set_form_data(params)
            end
          end
          response = http.request(request)
          [response.code.to_i, JSON.parse(response.body)]
        end
        check = lambda do |result, status|
          raise "HTTP #{result[0]}: #{result[1]} (expected #{status})" unless result[0] == status
          result[1]
        end
        baseline = check.call(send_request.call("#{issuer}/.well-known/openid-configuration", nil, nil), 200)
        raise "unexpected automatic aliases" if baseline.key?("mtls_endpoint_aliases")
        publish_aliases = true
        discovered = check.call(send_request.call("#{issuer}/.well-known/openid-configuration", nil, nil), 200)
        raise "alias changed issuer" unless discovered.fetch("issuer") == issuer
        aliases = discovered.fetch("mtls_endpoint_aliases")
        alias_keys.each do |name|
          raise "canonical endpoint changed" unless discovered.fetch(name).start_with?("#{issuer}/")
          raise "alias not on separate listener" unless aliases.fetch(name).start_with?("#{alias_origin}/")
        end
        metadata = discovered.merge(aliases)
        registration_params = {grant_types: [Rodauth::CibaSupport::GRANT_TYPE, "refresh_token"], response_types: [],
          scope: "openid offline_access", token_endpoint_auth_method: method, backchannel_token_delivery_mode: "poll",
          tls_client_certificate_bound_access_tokens: true}
        if method == "tls_client_auth"
          registration_params[:tls_client_auth_subject_dn] = "/CN=client"
        else
          registration_params[:jwks_uri] = remote_uri
          registration_params[:subject_type] = "pairwise"
        end
        registration_headers = {"Authorization" => "Bearer local-mtls-registration", "Content-Type" => "application/json"}
        client = check.call(send_request.call(metadata.fetch("registration_endpoint"), registration_params, nil, nil, registration_headers), 201)
        client_id = client.fetch("client_id")
        raise "binding registration lost" unless client.fetch("tls_client_certificate_bound_access_tokens") == true
        start_params = {client_id: client_id, scope: "openid offline_access", login_hint: "customer@example.test"}
        start_url = metadata.fetch("backchannel_authentication_endpoint")
        check.call(send_request.call(start_url, start_params, nil), 401)
        spoof = {"X-SSL-Client-Cert" => CGI.escape(client_cert.to_pem), "X-SSL-Client-Verify" => "SUCCESS"}
        check.call(send_request.call(start_url, start_params, nil, nil, spoof), 401)
        check.call(send_request.call(start_url, start_params, foreign_cert, foreign_key), 401)
        check.call(send_request.call(start_url, start_params, other_cert), 401) if method == "self_signed_tls_client_auth"
        started = check.call(send_request.call(start_url, start_params), 200)
        auth = app.new(Rack::MockRequest.env_for(issuer)).rodauth
        pending = auth.ciba_request(database[:ciba_requests].get(:id))
        consent = auth.create_ciba_grant(account_id: pending[:account_id], oauth_application_id: pending[:oauth_application_id], scopes: pending[:scopes])
        auth.backchannel_result(pending[:id], consent)
        params = {client_id: client_id, grant_type: Rodauth::CibaSupport::GRANT_TYPE, auth_req_id: started.fetch("auth_req_id")}
        check.call(send_request.call(metadata.fetch("token_endpoint"), params, nil), 401)
        tokens = check.call(send_request.call(metadata.fetch("token_endpoint"), params), 200)
        jwks = check.call(send_request.call(metadata.fetch("jwks_uri"), nil, nil), 200)
        identity, = JWT.decode(tokens.fetch("id_token"), nil, true, jwks: jwks, algorithms: ["RS256"],
          verify_iss: true, iss: issuer, verify_aud: true, aud: client_id)
        raise "ID Token inherited certificate binding" if identity.key?("cnf")
        if method == "self_signed_tls_client_auth"
          sector = "127.0.0.1:#{server.config[:Port]}"
          pairwise_subject = OpenSSL::HMAC.hexdigest("SHA256", "local-pairwise-fixture-secret", JSON.generate([sector, pending[:account_id]]))
          raise "pairwise subject mismatch" unless identity.fetch("sub") == pairwise_subject
          raise "pairwise subject was not stored" unless database[:oauth_grants].order(:id).last[:ciba_subject] == pairwise_subject
        end
        if jwt
          access, = JWT.decode(tokens.fetch("access_token"), nil, true, jwks: jwks, algorithms: ["RS256"], verify_iss: true, iss: issuer)
          raise "wrong JWT certificate digest" unless access.fetch("cnf").fetch("x5t#S256") == expected
        else
          info = check.call(send_request.call(metadata.fetch("introspection_endpoint"), {client_id: client_id, token: tokens.fetch("access_token")}), 200)
          raise "inactive bound token" unless info.fetch("active")
          raise "wrong introspection digest" unless info.fetch("cnf").fetch("x5t#S256") == expected
        end
        authorization = {"Authorization" => "Bearer #{tokens.fetch('access_token')}"}
        userinfo = metadata.fetch("userinfo_endpoint")
        check.call(send_request.call(userinfo, nil, nil, nil, authorization), 401)
        check.call(send_request.call(userinfo, nil, other_cert, client_key, authorization), 401)
        info = check.call(send_request.call(userinfo, nil, client_cert, client_key, authorization), 200)
        raise "wrong UserInfo subject" unless info.fetch("sub") == identity.fetch("sub")
        refresh_params = {client_id: client_id, grant_type: "refresh_token", refresh_token: tokens.fetch("refresh_token")}
        check.call(send_request.call(metadata.fetch("token_endpoint"), refresh_params, nil), 401)
        refreshed = check.call(send_request.call(metadata.fetch("token_endpoint"), refresh_params), 200)
        renewed_identity, = JWT.decode(refreshed.fetch("id_token"), nil, true, jwks: jwks, algorithms: ["RS256"],
          verify_iss: true, iss: issuer, verify_aud: true, aud: client_id)
        raise "refreshed ID Token inherited certificate binding" if renewed_identity.key?("cnf")
        fresh_auth = {"Authorization" => "Bearer #{refreshed.fetch('access_token')}"}
        check.call(send_request.call(userinfo, nil, nil, nil, fresh_auth), 401)
        check.call(send_request.call(userinfo, nil, client_cert, client_key, fresh_auth), 200)
        management_headers = {"Authorization" => "Bearer #{client.fetch('registration_access_token')}", "Content-Type" => "application/json"}
        replacement = registration_params.merge(client_id: client_id)
        check.call(send_request.call(client.fetch("registration_client_uri"),
          replacement.merge(tls_client_certificate_bound_access_tokens: "false"), nil, nil, management_headers, "PUT"), 400)
        retained = check.call(send_request.call(client.fetch("registration_client_uri"), nil, nil, nil, management_headers), 200)
        raise "failed update changed policy" unless retained.fetch("tls_client_certificate_bound_access_tokens") == true
        replacement.delete(:tls_client_certificate_bound_access_tokens)
        updated = check.call(send_request.call(client.fetch("registration_client_uri"), replacement, nil, nil, management_headers, "PUT"), 200)
        raise "omitted binding not reset" unless updated.fetch("tls_client_certificate_bound_access_tokens") == false
        check.call(send_request.call(client.fetch("registration_client_uri"), nil, nil, nil, management_headers), 401)
        new_headers = management_headers.merge("Authorization" => "Bearer #{updated.fetch('registration_access_token')}")
        check.call(send_request.call(client.fetch("registration_client_uri"), nil, nil, nil, new_headers), 200)
        # Management changes future issuance, never already-issued credentials.
        check.call(send_request.call(userinfo, nil, nil, nil, fresh_auth), 401)
        unbound = check.call(send_request.call(metadata.fetch("token_endpoint"), refresh_params), 200)
        unbound_auth = {"Authorization" => "Bearer #{unbound.fetch('access_token')}"}
        check.call(send_request.call(userinfo, nil, nil, nil, unbound_auth), 200)
        if method == "self_signed_tls_client_auth"
          raise "remote JWKS not cached" unless remote_hits == 1
          remote_keys = [JWT::JWK.new(client_key.public_key).export.merge(x5c: [Base64.strict_encode64(other_cert.to_der)])]
          check.call(send_request.call(start_url, start_params, other_cert), 401)
          raise "certificate miss forced refetch" unless remote_hits == 1
          # Re-enable binding before issuing with the newly published certificate.
          check.call(send_request.call(client.fetch("registration_client_uri"),
            replacement.merge(tls_client_certificate_bound_access_tokens: true), nil, nil, new_headers, "PUT"), 200)
          auth.send(:http_request_cache).uncache(URI(remote_uri))
          check.call(send_request.call(start_url, start_params, client_cert), 401)
          rotated_refresh = {client_id: client_id, grant_type: "refresh_token", refresh_token: unbound.fetch("refresh_token")}
          rotated = check.call(send_request.call(metadata.fetch("token_endpoint"), rotated_refresh, other_cert), 200)
          raise "rotation did not fetch once" unless remote_hits == 2
          rotated_auth = {"Authorization" => "Bearer #{rotated.fetch('access_token')}"}
          check.call(send_request.call(userinfo, nil, other_cert, client_key, rotated_auth), 200)
          check.call(send_request.call(userinfo, nil, client_cert, client_key, rotated_auth), 401)
          check.call(send_request.call(userinfo, nil, client_cert, client_key, authorization), 200)
          check.call(send_request.call(userinfo, nil, other_cert, client_key, authorization), 401)
          expected_new = Base64.urlsafe_encode64(Digest::SHA256.digest(other_cert.to_der), padding: false)
          inspected = check.call(send_request.call(metadata.fetch("introspection_endpoint"),
            {client_id: client_id, token: rotated.fetch("access_token")}, other_cert), 200)
          raise "rotated binding digest mismatch" unless inspected.fetch("cnf").fetch("x5t#S256") == expected_new
          auth.send(:http_request_cache).uncache(URI(remote_uri))
          remote_status = 503
          pending_count = database[:ciba_requests].count
          2.times do
            failure = check.call(send_request.call(start_url, start_params, other_cert), 400)
            raise "wrong lookup error" unless failure.fetch("error") == "invalid_client_metadata"
          end
          raise "failed retrieval created request" unless database[:ciba_requests].count == pending_count
          remote_status = 200
          check.call(send_request.call(start_url, start_params, other_cert), 200)
          puts "PASS: installed-gem #{jwt ? 'JWT' : 'opaque'} remote x5c over verified HTTPS, cache expiry, same-key certificate rotation, refresh/new binding, old binding retained, failed fetch/recovery"
        end
        # Independent client: certificate authenticates the client; DPoP binds the token.
        dpop_registration = registration_params.reject { |name, _| %i[jwks_uri subject_type].include?(name) }.merge(
          tls_client_certificate_bound_access_tokens: false, dpop_bound_access_tokens: true)
        dpop_registration[:jwks] = {keys: [jwk]} if method == "self_signed_tls_client_auth"
        dpop_client = check.call(send_request.call(metadata.fetch("registration_endpoint"), dpop_registration,
          nil, nil, registration_headers), 201)
        dpop_id = dpop_client.fetch("client_id")
        dpop_started = check.call(send_request.call(start_url,
          {client_id: dpop_id, scope: "openid offline_access", login_hint: "customer@example.test"}), 200)
        dpop_pending = auth.ciba_request(database[:ciba_requests].order(:id).last.fetch(:id))
        dpop_consent = auth.create_ciba_grant(account_id: dpop_pending[:account_id],
          oauth_application_id: dpop_pending[:oauth_application_id], scopes: dpop_pending[:scopes])
        auth.backchannel_result(dpop_pending[:id], dpop_consent)
        proof_key = OpenSSL::PKey::EC.generate("prime256v1")
        proof = lambda do |target, verb, token = nil|
          claims = {jti: SecureRandom.uuid, iat: Time.now.to_i, htu: target, htm: verb}
          claims[:ath] = Base64.urlsafe_encode64(Digest::SHA256.digest(token), padding: false) if token
          JWT.encode(claims, proof_key, "ES256", typ: "dpop+jwt", jwk: JWT::JWK.new(proof_key).export)
        end
        token_url = metadata.fetch("token_endpoint")
        dpop_params = {client_id: dpop_id, grant_type: Rodauth::CibaSupport::GRANT_TYPE,
          auth_req_id: dpop_started.fetch("auth_req_id")}
        check.call(send_request.call(token_url, dpop_params, nil, nil,
          {"DPoP" => proof.call(token_url, "POST")}), 401)
        check.call(send_request.call(token_url, dpop_params), 400)
        check.call(send_request.call(token_url, dpop_params, client_cert, client_key,
          {"DPoP" => proof.call(discovered.fetch("token_endpoint"), "POST")}), 400)
        raise "rejected proof consumed approval" unless auth.ciba_request(dpop_pending[:id])[:status] == "approved"
        dpop_tokens = check.call(send_request.call(token_url, dpop_params, client_cert, client_key,
          {"DPoP" => proof.call(token_url, "POST")}), 200)
        dpop_identity, = JWT.decode(dpop_tokens.fetch("id_token"), nil, true, jwks: jwks, algorithms: ["RS256"],
          verify_iss: true, iss: issuer, verify_aud: true, aud: dpop_id)
        raise "ID Token inherited sender binding" if dpop_identity.key?("cnf")
        bound_token = dpop_tokens.fetch("access_token")
        binding = check.call(send_request.call(metadata.fetch("introspection_endpoint"),
          {client_id: dpop_id, token: bound_token}), 200).fetch("cnf")
        raise "wrong combined binding" unless binding == {"jkt" => JWT::JWK::Thumbprint.new(JWT::JWK.new(proof_key)).generate}
        check.call(send_request.call(userinfo, nil, client_cert, client_key,
          {"Authorization" => "Bearer #{bound_token}"}), 401)
        dpop_info = check.call(send_request.call(userinfo, nil, nil, nil,
          {"Authorization" => "DPoP #{bound_token}", "DPoP" => proof.call(userinfo, "GET", bound_token)}), 200)
        raise "combined flow subject mismatch" unless dpop_info.fetch("sub") == dpop_identity.fetch("sub")
        dpop_refresh = {client_id: dpop_id, grant_type: "refresh_token", refresh_token: dpop_tokens.fetch("refresh_token")}
        check.call(send_request.call(token_url, dpop_refresh, nil, nil,
          {"DPoP" => proof.call(token_url, "POST")}), 401)
        check.call(send_request.call(token_url, dpop_refresh), 400)
        renewed = check.call(send_request.call(token_url, dpop_refresh, client_cert, client_key,
          {"DPoP" => proof.call(token_url, "POST")}), 200)
        raise "combined refresh lost DPoP" unless renewed.fetch("token_type") == "DPoP"
        renewed_binding = check.call(send_request.call(metadata.fetch("introspection_endpoint"),
          {client_id: dpop_id, token: renewed.fetch("access_token")}), 200).fetch("cnf")
        raise "combined refresh changed binding" unless renewed_binding == binding
        puts "PASS: installed real TLS alias #{method}/#{jwt ? 'JWT' : 'opaque'} authentication plus DPoP issuance, UserInfo and refresh"
        puts "PASS: installed-gem real TLS DCR #{method}/#{jwt ? 'JWT' : 'opaque'} CIBA, binding, UserInfo, refresh and management via discovered aliases; canonical issuer and old binding retained, new policy applied"
      ensure
        server.shutdown
        alias_server.shutdown
        thread&.join(5)
        alias_thread&.join(5)
        raise "TLS server did not stop" if thread&.alive? || alias_thread&.alive?
        database.disconnect
      end
    end
  end
end

CibaMtlsSmoke.run
