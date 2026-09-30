# frozen_string_literal: true
require "bundler/setup"
require "minitest/autorun"
require "roda"
require "sequel"
require "sqlite3"
require "jwt"
require "openssl"
require "rack/mock"
require "tmpdir"
require "timeout"
$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "rodauth/features/ciba"
require "rodauth/ciba/schema"

class CibaIntegrationTest < Minitest::Test
  GRANT = "urn:openid:params:grant-type:ciba"
  KEY = OpenSSL::PKey::RSA.generate(2048)

  def setup
    connect_test_database
    @db.create_table(:accounts) do
      primary_key :id
      String :email, null: false
      Integer :status_id, default: 2, null: false
    end
    @db.create_table(:oauth_applications) do
      primary_key :id
      String :client_id, unique: true, null: false
      String :client_secret, null: false
      String :scopes
      String :grant_types
      String :token_endpoint_auth_method
      String :subject_type
      String :backchannel_token_delivery_mode
    end
    @db.create_table(:oauth_grants) do
      primary_key :id
      foreign_key :account_id, :accounts
      foreign_key :oauth_application_id, :oauth_applications
      String :type
      String :code, unique: true
      String :redirect_uri
      String :scopes
      String :token, unique: true
      String :refresh_token, unique: true
      DateTime :expires_in
      DateTime :revoked_at
      String :nonce
      String :acr
      String :claims
    end
    Rodauth::CibaSupport::Schema.create_grants(@db)
    Rodauth::CibaSupport::Schema.add_grant_reference(@db)
    Rodauth::CibaSupport::Schema.create(@db)
    Rodauth::CibaSupport::Schema.create_client_assertions(@db)
    @account_id = @db[:accounts].insert(email: "customer@example.test")
    @client_id = @db[:oauth_applications].insert(client_id: "support", client_secret: "test-secret",
      scopes: "openid", grant_types: "#{GRANT} authorization_code", token_endpoint_auth_method: "client_secret_basic",
      subject_type: "public", backchannel_token_delivery_mode: "poll")
    database = @db
    @app = Class.new(Roda) do
      plugin :json_parser, content_type_regexp: %r{\Aapplication/json\b}i
      plugin :rodauth, json: :only do
        enable :ciba
        db database
        ciba_request_lifetime 300
        ciba_max_request_lifetime 600
        oauth_jwt_keys("RS256" => KEY)
        oauth_jwt_public_keys("RS256" => KEY.public_key)
        oauth_jwt_access_tokens false
        oauth_applications_client_secret_hash_column nil
        hmac_secret "test-hmac-secret-not-for-production"
        get_oidc_account_last_login_at { |_id| Time.at(1) }
        before_token_route { scope.env["test.token_gate"]&.call }
        auth_class_eval do
          def resolve_ciba_login_hint(hint, oauth_application:)
            db[:accounts].where(email: hint).get(:id)
          end
          def before_ciba_request
            scope.env["test.before_request"]&.call(ciba_current_request)
          end
          def after_ciba_request
            scope.env["test.after_request"]&.call(ciba_current_request)
          end
          def before_ciba_approve
            scope.env["test.before_approve"]&.call(ciba_current_request)
          end
          def after_ciba_approve
            scope.env["test.after_approve"]&.call(ciba_current_request)
          end
          def after_ciba_deny
            scope.env["test.after_deny"]&.call(ciba_current_request)
          end
          def ciba_request_accepted(row)
            scope.env["test.accepted"]&.call(row)
          end
          def trigger_ciba_authentication_device(row)
            return super if scope.env["test.unconfigured_device"]
            scope.env["test.device"]&.call(row, self)
          end
          def before_ciba_issue
            scope.env["test.before_issue"]&.call
          end
          def after_ciba_issue
            scope.env["test.after_issue"]&.call
          end
          def observe_ciba_event(event)
            scope.env["test.observe"]&.call(event)
          end
          def report_ciba_observer_error(error)
            scope.env["test.report"]&.call(error)
          end
          def report_ciba_processing_error(error)
            scope.env["test.processing_error"]&.call(error)
          end
          def ciba_now
            scope.env["test.now"] ? scope.env["test.now"].call : super
          end
          def jwt_encode(*args, **kwargs)
            if kwargs.dig(:headers, :typ) == "id_token+jwt"
              scope.env["test.signing_probe"]&.call
              raise "injected signing failure" if scope.env["test.fail_signing"]
            end
            super
          end
        end
      end
      route do |r|
        rodauth.load_openid_configuration_route
        rodauth.load_oauth_server_metadata_route
        r.rodauth
      end
    end
  end

  def teardown
    @db&.disconnect
    if @admin && @database_created
      @admin.run("DROP DATABASE #{@admin.literal(Sequel.identifier(@database_name))}")
    end
    @admin&.disconnect
    FileUtils.remove_entry(@dir) if @dir
  end

  def connect_test_database
    backend = ENV.fetch("CIBA_TEST_DB", "sqlite")
    if backend == "sqlite"
      @dir = Dir.mktmpdir("ciba-ruby-")
      @db = Sequel.sqlite(File.join(@dir, "test.db"), max_connections: 4, timeout: 3000)
      @db.run("PRAGMA journal_mode=WAL")
      return
    end
    # These hosts are only provided by compose.yaml. Each test owns a fresh DB.
    options = case backend
              when "postgres"
                {adapter: "postgres", host: "postgres", user: "ciba_test", database: "postgres"}
              when "mysql"
                {adapter: "mysql2", host: "mysql", user: "root", database: "mysql", encoding: "utf8mb4"}
              else
                raise ArgumentError, "unknown CIBA_TEST_DB: #{backend}"
              end
    options[:password] = "ciba-test-only"
    @database_name = "ciba_test_#{Process.pid}_#{SecureRandom.hex(6)}"
    @admin = Sequel.connect(options.merge(max_connections: 1))
    @admin.run("CREATE DATABASE #{@admin.literal(Sequel.identifier(@database_name))}")
    @database_created = true
    @db = Sequel.connect(options.merge(database: @database_name, max_connections: 4))
  end

  def auth(env = {})
    @app.new(Rack::MockRequest.env_for("https://op.example.test/").merge(env)).rodauth
  end

  def post(path, params, env = {})
    Rack::MockRequest.new(@app).post("https://op.example.test#{path}", {
      "HTTP_AUTHORIZATION" => "Basic #{Base64.strict_encode64('support:test-secret')}",
      params: params
    }.merge(env))
  end

  def accept_request
    response = post("/backchannel-authentication", login_hint: "customer@example.test", scope: "openid")
    assert_equal 200, response.status, response.body
    JSON.parse(response.body).fetch("auth_req_id")
  end

  def approve(id, **context)
    row = @db[:ciba_requests].where(auth_req_id_digest: Digest::SHA256.hexdigest(id)).first
    auth.approve_ciba_request(row.fetch(:id), account_id: @account_id, **context)
  end

  def poll(id, env = {})
    post("/token", {grant_type: GRANT, auth_req_id: id}, env)
  end

  def assert_error(response, error)
    assert_equal 400, response.status, response.body
    assert_equal error, JSON.parse(response.body)["error"]
  end

  def decode_id_token(response)
    payload = JSON.parse(response.body)
    claims, = JWT.decode(payload.fetch("id_token"), KEY.public_key, true,
      algorithms: ["RS256"], verify_iss: true, iss: "https://op.example.test",
      verify_aud: true, aud: "support")
    [payload, claims]
  end

  def parallel_decisions
    ready, start = Queue.new, Queue.new
    workers = 2.times.map do |index|
      Thread.new do
        @db.synchronize do
          ready << true
          Timeout.timeout(10) { start.pop }
          yield index
        end
      end
    end
    begin
      Timeout.timeout(10) { 2.times { ready.pop } }
      2.times { start << true }
      workers.map { |t| Timeout.timeout(10) { t.value } }
    ensure
      workers.each { |t| t.kill if t.alive? }
      workers.each(&:join)
    end
  end
end
