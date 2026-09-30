# frozen_string_literal: true
require "roda"
require "sequel"
require "openssl"
require "cgi"
require "rodauth/ciba"

# Local demonstration only: the customer is a simulated, fixed identity.
module CibaDemo
  def self.create_schema(db)
    db.create_table(:accounts) do
      primary_key :id
      String :email
      Integer :status_id, default: 2
    end
    db.create_table(:oauth_applications) do
      primary_key :id
      String :client_id
      String :client_secret
      String :scopes
      String :grant_types
      String :token_endpoint_auth_method
      String :subject_type
    end
    Rodauth::CibaSupport::Schema.add_client_metadata(db)
    db.create_table(:oauth_grants) do
      primary_key :id
      foreign_key :account_id, :accounts
      foreign_key :oauth_application_id, :oauth_applications
      %i[type code scopes token refresh_token redirect_uri nonce acr claims].each { |name| String name }
      DateTime :expires_in
      DateTime :revoked_at
    end
    Rodauth::CibaSupport::Schema.create_grants(db)
    Rodauth::CibaSupport::Schema.add_grant_reference(db)
    Rodauth::CibaSupport::Schema.create(db)
    db[:accounts].insert(email: "customer@example.test")
    db[:oauth_applications].insert(client_id: "demo-client", client_secret: "demo-secret",
      scopes: "openid", grant_types: Rodauth::CibaSupport::GRANT_TYPE, subject_type: "public",
      token_endpoint_auth_method: "client_secret_basic", backchannel_token_delivery_mode: "poll")
  end

  def self.build(db)
    key = OpenSSL::PKey::RSA.generate(2048)
    Class.new(Roda) do
      plugin :sessions, secret: SecureRandom.hex(64)
      plugin :json_parser, content_type_regexp: %r{\Aapplication/json\b}i
      plugin :rodauth, json: :only do
        enable :ciba
        db db
        ciba_request_lifetime 300
        ciba_max_request_lifetime 600
        ciba_require_tls false # Local HTTP demo only. Production defaults to true.
        base_url "http://127.0.0.1:9292"
        authorization_server_url "http://127.0.0.1:9292"
        oauth_jwt_keys("RS256" => key)
        oauth_jwt_public_keys("RS256" => key.public_key)
        oauth_jwt_access_tokens false
        oauth_applications_client_secret_hash_column nil # Test-only plaintext fixture.
        hmac_secret SecureRandom.hex(64)
        # This demo displays pending requests on its local approval page.
        trigger_ciba_authentication_device { |_request| }
        resolve_ciba_login_hint { |hint, oauth_application:| db[:accounts].where(email: hint).get(:id) }
      end
      route do |r|
        rodauth.load_openid_configuration_route
        r.rodauth
        response["content-type"] = "text/html; charset=utf-8"
        session["csrf"] ||= SecureRandom.hex(32)
        r.get do
          rows = rodauth.pending_ciba_requests
          forms = rows.map do |row|
            message = CGI.escapeHTML(row[:binding_message].to_s)
            <<~HTML
              <form method="post" action="/decision">
                <input type="hidden" name="csrf" value="#{session['csrf']}">
                <input type="hidden" name="id" value="#{row[:id]}">
                <p>Request #{row[:id]} — binding message: #{message}</p>
                <button name="decision" value="approve">Approve</button>
                <button name="decision" value="deny">Deny</button>
              </form>
            HTML
          end.join
          "<!doctype html><html><meta charset=utf-8><title>CIBA local demo</title><h1>CIBA local demo</h1>" \
            "<p>Simulated customer: customer@example.test. No real identity verification. Local testing only.</p>#{forms}</html>"
        end
        r.post "decision" do
          csrf = r.params["csrf"]
          unless csrf.is_a?(String) && Rack::Utils.secure_compare(session["csrf"], csrf)
            response.status = 403
            next "Invalid CSRF token"
          end
          customer = db[:accounts].where(email: "customer@example.test").get(:id)
          id = Integer(r.params["id"], 10)
          case r.params["decision"]
          when "approve"
            db.transaction(mode: :immediate) do
              request = rodauth.ciba_request(id)
              raise Rodauth::CibaSupport::IdentityMismatch unless request[:account_id] == customer
              # Reuse the saved consent when the browser repeats the decision.
              grant = request[:grant_id] || rodauth.create_ciba_grant(account_id: customer,
                oauth_application_id: request[:oauth_application_id], scopes: request[:scopes])
              rodauth.backchannel_result(id, grant)
            end
          when "deny"
            request = rodauth.ciba_request(id)
            raise Rodauth::CibaSupport::IdentityMismatch unless request[:account_id] == customer
            rodauth.backchannel_result(id, Rodauth::CibaSupport::ProtocolError.new("access_denied"))
          else
            response.status = 400
            next "Unknown decision"
          end
          r.redirect "/"
        rescue ArgumentError, Rodauth::CibaSupport::CompletionError
          response.status = 409
          "Request unavailable"
        end
      end
    end
  end
end
