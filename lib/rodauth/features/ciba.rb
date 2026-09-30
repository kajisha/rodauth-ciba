# frozen_string_literal: true
require "jwt"
require "rodauth/oauth"
require "rodauth/features/oidc"
require "json"
require "digest"
require "securerandom"
require "uri"
require "stringio"
require "rodauth/ciba/authorization_details"
require "rodauth/ciba/http"
require "rodauth/ciba/jwks_cache"
require "rodauth/ciba/registration"
require "rodauth/ciba/pairwise"
require "rodauth/ciba/dpop"
require "rodauth/ciba/mtls"
require "rodauth/ciba/id_token_encryption"

module Rodauth
  module CibaSupport
    GRANT_TYPE = "urn:openid:params:grant-type:ciba"
    class CompletionError < StandardError; end
    class PingDeliveryError < CompletionError; end
    class NotFound < CompletionError; end
    class IdentityMismatch < CompletionError; end
    class Conflict < CompletionError; end
    class Expired < CompletionError; end
    class Ineligible < CompletionError; end
    class ReentrantMutation < CompletionError; end
    class ConfigurationError < StandardError; end
    module ResourceTokens
      private

      def jwt_claims(grant)
        super.tap do |claims|
          if grant[oauth_grants_type_column] == GRANT_TYPE && grant[:ciba_resource]
            claims[:aud] = grant[:ciba_resource_audience]
            claims[:"urn:rodauth:ciba:resource"] = grant[:ciba_resource]
            claims[:authorization_details] = JSON.parse(grant[:ciba_authorization_details]) if grant[:ciba_authorization_details]
          end
        end
      end

      def jwt_decode(token, verify_aud: true, **options)
        userinfo = request.path == userinfo_path
        introspection = features.include?(:oauth_token_introspection) && request.path == introspect_path
        if userinfo || introspection
          # These OP endpoints are not the API audience. Authenticate the CIBA
          # marker before enforcing its endpoint restrictions. Other OAuth tokens
          # retain upstream behavior.
          claims = super(token, verify_aud: false, **options)
          return unless claims
          if claims["urn:rodauth:ciba:resource"]
            return if userinfo
            throw_json_response_error(oauth_invalid_response_status, "unsupported_token_type")
          end
        end
        super
      end

      def json_token_introspect_payload(grant)
        super.tap do |payload|
          if grant && grant[oauth_grants_type_column] == GRANT_TYPE && grant[:ciba_resource]
            payload[:aud] = grant[:ciba_resource_audience]
            payload[:authorization_details] = JSON.parse(grant[:ciba_authorization_details]) if grant[:ciba_authorization_details]
          end
        end
      end
    end
    # This boundary is prepended so enabling an upstream feature later cannot bypass it.
    module ClientAuthentication
      def over_max_bytesize_param_value(key, value)
        if key == "token" && features.include?(:oauth_token_introspection) && request.path == introspect_path &&
            value.bytesize <= 8192 && ciba_dpop_userinfo_candidate?(value)
          return value
        end
        super
      end

      def logged_in?
        # This protocol operation always authenticates the OAuth client and
        # never derives revocation authority from a browser account session.
        ciba_token_revocation_request? ? false : super
      end

      def check_csrf?
        ciba_token_revocation_request? ? false : super
      end

      def validate_revoke_params(*args)
        return super unless ciba_token_revocation_request?
        validate_ciba_transport!
        token = ciba_parameter("token", required: true, max: @ciba_revocation_jwt_candidate ? 8192 : 1024)
        ciba_parameter("token_type_hint") if request.params.key?("token_type_hint")
        if @ciba_revocation_jwt_candidate
          ciba_error(ciba_signed_access_token?(token) ? "unsupported_token_type" : "invalid_request")
        end
        @ciba_token_revocation_response = true
      end

      def authorization_required
        # Recipient lookup happens after approval/refresh mutation. Raise so
        # upstream HTTP errors cannot halt and commit a consumed source.
        raise ConfigurationError, "CIBA ID Token recipient lookup failed" if @ciba_authentication
        raise ProtocolError, "invalid_client_metadata" if @ciba_tls_key_lookup
        # A client already authenticated before this distinct signature-key lookup.
        raise ProtocolError, "invalid_request" if @ciba_request_key_lookup
        super
      end

      private

      def revoke_oauth_grant
        return super unless ciba_token_revocation_request?
        if @ciba_revocation_access_id
          ciba_revoke_access_artifacts
        elsif param("token").start_with?("ciba_rt_") && db.table_exists?(ciba_refresh_tokens_table)
          ds = db[ciba_refresh_tokens_table].where(token_digest: Digest::SHA256.hexdigest(param("token")))
          row = ciba_lock_source_after_grant(ds)
          if row && row[:expires_at] > ciba_now
            consent = ciba_locked_grant(row[:grant_id])
            if consent && !consent[:revoked_at]
              ciba_error("invalid_request") unless row[:oauth_application_id] == oauth_application[oauth_applications_id_column]
              revoke_ciba_grant(row[:grant_id])
            end
          end
        end
        # Upstream builds its success payload after the standard transactional
        # before/after hooks; suppress that payload for this CIBA endpoint result.
        {oauth_grants_revoked_at_column => Time.now}
      end

      def json_response_success(*args)
        return super unless @ciba_token_revocation_response
        response["Cache-Control"] = "no-store"
        response["Pragma"] = "no-cache"
        request.halt [200, response.headers, []]
      end

      def oauth_application_jwks(application)
        previous = @ciba_jwks_cache_lookup
        @ciba_jwks_cache_lookup = @ciba_request_key_lookup || @ciba_verifying_client_assertion || @ciba_tls_key_lookup || @ciba_authentication
        super
      ensure
        @ciba_jwks_cache_lookup = previous
      end

      def http_request_cache
        self.class.instance_variable_get(:@ciba_jwks_cache) || super
      end

      def http_request_with_cache(uri, *args)
        return super unless @ciba_jwks_cache_lookup
        http_request_cache.fetch(URI(uri.to_s)) { http_request(uri, *args) }
      rescue CibaSupport::JwksCache::StatusError
        authorization_required
      end

      def http_request(uri, form_data = nil, &block)
        return super unless @ciba_request_key_lookup || @ciba_verifying_client_assertion || @ciba_tls_key_lookup || @ciba_authentication
        raise CibaSupport::HTTP::Error, "unexpected JWKS request body" if form_data
        uri = URI(uri.to_s)
        outgoing = Net::HTTP::Get.new(uri.request_uri)
        outgoing["accept"] = json_response_content_type
        block&.call(outgoing)
        result = CibaSupport::HTTP.request(uri, outgoing, address_allowed: method(:ciba_http_address_allowed?))
        authorization_required unless @ciba_jwks_cache_lookup || (200..299).include?(result.code.to_i)
        result
      end

      def require_oauth_application
        return super unless ciba_protocol_request?
        ciba_http do
          validate_ciba_transport!
          if request.params.key?("client_assertion") || request.params.key?("client_assertion_type")
            authorization_required unless features.include?(:oauth_jwt_bearer_grant) &&
              param("client_assertion_type") == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" &&
              request.params["client_assertion"].is_a?(String)
          end
          # Missing identity is a malformed CIBA request, distinct from failed
          # authentication. Assertion subjects may identify clients without client_id.
          if (request.path == backchannel_authentication_path ||
              (request.path == token_path && request.params["grant_type"] == CibaSupport::GRANT_TYPE)) &&
             !request.env["HTTP_AUTHORIZATION"] && !request.params.key?("client_id") &&
             !request.params.key?("client_assertion")
            ciba_error("invalid_request")
          end
          super
        end
      end

      # grant_type/assertion are not Backchannel authentication parameters. They must
      # not select upstream's JWT authorization-grant path instead of client auth.
      def assertion_grant_type?(*args)
        request.path == backchannel_authentication_path ? false : super
      end

      def require_oauth_application_from_jwt_bearer_assertion_subject(assertion)
        begin
          claims, header = JWT.decode(assertion, nil, false)
        rescue JWT::DecodeError, ArgumentError, TypeError
          authorization_required if ciba_protocol_request?
          return super
        end
        client = claims.is_a?(Hash) && claims["sub"]
        application = client.is_a?(String) && db[oauth_applications_table].where(oauth_applications_client_id_column => client).first
        # Protect assertion reuse across other grant flows for the same CIBA client,
        # while preserving upstream behavior for unrelated clients.
        protected_client = application && application[oauth_applications_grant_types_column].to_s.split.include?(GRANT_TYPE)
        return super unless ciba_protocol_request? || protected_client
        authorization_required unless claims.is_a?(Hash) && header.is_a?(Hash) &&
          client.is_a?(String) && !client.empty? && claims["iss"] == client &&
          claims["exp"].is_a?(Numeric) && claims["exp"].finite? &&
          claims["exp"] > Time.now.to_f && claims["exp"] < 9_223_372_036_854_775_807 &&
          claims["jti"].is_a?(String) && !claims["jti"].empty? && claims["jti"].bytesize <= 1024
        if request.params.key?("client_id") && request.params["client_id"] != client
          authorization_required
        end
        configured = ciba_client_assertion_signing_algorithms
        authorization_required if configured && !configured.include?(header["alg"])
        registered_algorithm = application && application[oauth_applications_token_endpoint_auth_signing_alg_column]
        authorization_required if registered_algorithm && registered_algorithm != header["alg"]
        if claims.key?("iat")
          issued = claims["iat"]
          authorization_required unless issued.is_a?(Numeric) && issued.finite? &&
            issued >= 0 && issued <= Time.now.to_f + oauth_jwt_iat_leeway
        end
        @ciba_verifying_client_assertion = true
        application = super
        ciba_consume_client_assertion!(application, claims)
        application
      ensure
        @ciba_verifying_client_assertion = false
      end

      def require_oauth_application_from_private_key_jwt(client_id, assertion)
        return super unless @ciba_verifying_client_assertion
        application = db[oauth_applications_table].where(oauth_applications_client_id_column => client_id).first
        authorization_required unless supports_auth_method?(application, "private_key_jwt")
        begin
          jwks = oauth_application_jwks(application)
        rescue CibaSupport::HTTP::Error, JSON::ParserError, IOError, SystemCallError, Timeout::Error,
               SocketError, OpenSSL::SSL::SSLError, Net::HTTPBadResponse
          authorization_required
        end
        keys = jwks.is_a?(Hash) ? jwks[:keys] : jwks
        # Without client keys the upstream generic JWT decoder can fall back to OP keys.
        authorization_required unless keys.is_a?(Array) && !keys.empty?
        options = {jwks: jwks}
        algorithm = application[oauth_applications_token_endpoint_auth_signing_alg_column]
        options[:jws_algorithm] = algorithm if algorithm
        authorization_required unless jwt_assertion(assertion, **options)
        application
      end

      def require_oauth_application_from_client_secret_jwt(client_id, assertion, algorithm)
        return super unless @ciba_verifying_client_assertion
        application = db[oauth_applications_table].where(oauth_applications_client_id_column => client_id).first
        minimum = {"HS256" => 32, "HS384" => 48, "HS512" => 64}[algorithm]
        secret = application && application[oauth_applications_client_secret_column]
        authorization_required unless minimum && secret.is_a?(String) && secret.bytesize >= minimum
        super
      end

      def jwt_assertion(assertion, **kwargs)
        return super unless @ciba_verifying_client_assertion
        _payload, header = JWT.decode(assertion, nil, false)
        claims = if %w[Ed25519 EdDSA].include?(header["alg"])
                   ciba_decode_edwards_client_assertion(assertion, kwargs[:jwks])
                 else
                   jwt_decode(assertion, verify_iss: false, verify_aud: false, verify_jti: false, **kwargs)
                 end
        return unless claims.is_a?(Hash)
        audiences = claims["aud"].is_a?(String) ? [claims["aud"]] : claims["aud"]
        return unless audiences.is_a?(Array) && audiences.all? { |aud| aud.is_a?(String) }
        expected = request.path == backchannel_authentication_path ?
          [oauth_jwt_issuer, token_url, backchannel_authentication_url] : [request.url]
        if request.path == token_path && (request.params["grant_type"] == GRANT_TYPE || ciba_refresh_request?)
          expected << oauth_jwt_issuer
        end
        return if (expected & audiences).empty?
        claims
      end
    end
    class ProtocolError < StandardError
      attr_reader :code
      def initialize(code)
        @code = code
        super(code)
      end
    end
  end

  Feature.define(:ciba, :Ciba) do
    depends :oidc
    %w[ciba_request ciba_approve ciba_deny ciba_issue ciba_refresh].each do |action|
      before action
      after action
    end

    auth_value_method :ciba_client_assertions_table, :ciba_client_assertions
    auth_value_method :ciba_dpop_nonce_secret, nil
    auth_value_method :ciba_pairwise_enabled, false
    auth_value_method :ciba_token_subject_column, :ciba_subject
    auth_methods :ciba_pairwise_identifier
    auth_value_method :oauth_applications_token_endpoint_auth_signing_alg_column, :token_endpoint_auth_signing_alg
    auth_value_method :oauth_applications_default_max_age_column, :default_max_age
    auth_value_method :oauth_applications_require_auth_time_column, :require_auth_time
    auth_value_method :oauth_applications_default_acr_values_column, :default_acr_values
    auth_value_method :ciba_grants_table, :ciba_grants
    auth_value_method :ciba_grant_lifetime, 14 * 24 * 60 * 60
    auth_value_method :ciba_refresh_tokens_enabled, false
    auth_value_method :ciba_refresh_tokens_table, :ciba_refresh_tokens
    auth_value_method :ciba_refresh_token_lifetime, 14 * 24 * 60 * 60
    auth_value_method :ciba_claims_enabled, false
    auth_value_method :ciba_authentication_claims_by_scope, {}.freeze
    auth_value_method :ciba_request_context_enabled, false
    auth_value_method :ciba_dynamic_client_registration_enabled, false
    auth_value_method :ciba_issue_registration_access_token, true
    auth_value_method :ciba_rotate_registration_access_token, true
    auth_value_method :ciba_registration_token_digest_column, :ciba_registration_token_digest
    auth_value_method :ciba_login_hint_token_enabled, false
    auth_value_method :ciba_id_token_hint_enabled, false
    auth_value_method :ciba_id_token_encryption_enabled, false
    auth_value_method :ciba_user_code_enabled, false
    auth_value_method :ciba_ping_enabled, false
    auth_value_method :ciba_ping_deliveries_table, :ciba_ping_deliveries
    auth_value_method :oauth_applications_backchannel_client_notification_endpoint_column, :backchannel_client_notification_endpoint
    auth_value_method :oauth_applications_backchannel_user_code_parameter_column, :backchannel_user_code_parameter
    auth_value_method :ciba_id_token_hint_max_age, nil
    auth_value_method :ciba_request_signing_algorithms, [].freeze
    auth_value_method :ciba_client_assertion_signing_algorithms, nil
    auth_value_method :ciba_id_token_signing_keys, {}.freeze
    auth_value_method :oauth_applications_backchannel_authentication_request_signing_alg_column, :backchannel_authentication_request_signing_alg
    auth_value_method :ciba_resources_enabled, false
    auth_value_method :ciba_authorization_details_enabled, false
    auth_value_method :ciba_authorization_details_types, [].freeze
    auth_value_method :ciba_resource_servers, {}.freeze
    auth_value_method :ciba_supported_claims, (OIDC_SCOPES_MAP.reject { |scope, _| scope == "address" }.values.flatten.map(&:to_s) + ["address"]).uniq.freeze
    auth_value_method :oauth_grants_ciba_grant_id_column, :ciba_grant_id
    auth_value_method :ciba_requests_table, :ciba_requests
    auth_value_method :ciba_request_columns, {}.freeze
    auth_value_method :ciba_request_lifetime, 600
    auth_value_method :ciba_max_request_lifetime, 600
    auth_value_method :ciba_poll_interval, 5
    auth_value_method :ciba_max_request_bytes, 16_384
    auth_value_method :ciba_require_tls, true
    auth_value_method :oauth_applications_backchannel_token_delivery_mode_column, :backchannel_token_delivery_mode
    auth_methods :ciba_tls_client_certificate, :ciba_tls_client_certificate_authorized?, :ciba_tls_client_certificate_subject_matches?,
                 :ciba_id_token_hmac_secret, :ciba_id_token_encryption_secret, :ciba_dpop_endpoint_uri,
                 :resolve_ciba_login_hint, :resolve_ciba_login_hint_token, :resolve_ciba_id_token_subject, :verify_ciba_user_code, :ciba_http_address_allowed?, :approve_ciba_request, :deny_ciba_request,
                 :ciba_request, :pending_ciba_requests, :cleanup_ciba_requests,
                 :ciba_current_request, :ciba_current_refresh, :ciba_request_accepted, :observe_ciba_event,
                 :report_ciba_observer_error, :report_ciba_processing_error, :ciba_now,
                 :ciba_account_eligible?, :cleanup_ciba_client_assertions, :cleanup_ciba_refresh_tokens,
                 :validate_ciba_binding_message, :validate_ciba_request_context, :create_ciba_grant, :ciba_grant,
                 :revoke_ciba_grant, :backchannel_result, :trigger_ciba_authentication_device,
                 :ciba_resource_server, :ciba_use_granted_resource, :ciba_default_resource,
                 :retry_ciba_ping,
                 :ciba_validate_authorization_details, :ciba_authorization_details_for_token

    def ciba_dpop_endpoint_uri
      # Proxy headers are not a trust decision. An application behind a trusted
      # proxy can override this callback with its validated external URL.
      env = request.env.reject { |key, _| key == "HTTP_FORWARDED" || key.start_with?("HTTP_X_FORWARDED_") }
      Rack::Request.new(env).url
    end

    def ciba_validate_authorization_details(details, oauth_application:)
      raise CibaSupport::ConfigurationError, "configure authorization-details validation"
    end

    def ciba_tls_client_certificate
      nil
    end

    def ciba_id_token_hmac_secret(oauth_application:)
      if @ciba_verified_client_secret && @ciba_verified_client_secret.first == oauth_application[oauth_applications_id_column]
        @ciba_verified_client_secret.last
      elsif !oauth_applications_client_secret_hash_column
        oauth_application[oauth_applications_client_secret_column]
      end
    end

    def ciba_id_token_encryption_secret(oauth_application:)
      ciba_id_token_hmac_secret(oauth_application: oauth_application)
    end

    def ciba_tls_client_certificate_authorized?
      false
    end

    def ciba_tls_client_certificate_subject_matches?(property, expected)
      false
    end

    def validate_ciba_request_context(context, oauth_application:)
      raise CibaSupport::ConfigurationError, "configure validate_ciba_request_context"
    end

    def ciba_authorization_details_for_token(requested:, approved:, narrowing:, resource:, oauth_application:)
      raise CibaSupport::ConfigurationError, "configure authorization-details issuance policy"
    end

    # A registry lookup, never an HTTP fetch of the caller-supplied identifier.
    def ciba_resource_server(resource, oauth_application:)
      ciba_resource_servers[resource]
    end

    def ciba_use_granted_resource(request_snapshot)
      false
    end

    def ciba_default_resource(resources, oauth_application:)
      # Like the reference default, leave ambiguity unresolved and reject it.
      resources
    end

    auth_server_route(:backchannel_authentication, "backchannel-authentication") do |r|
      r.post do
        ciba_http do
          validate_ciba_transport!
          require_oauth_application
          ciba_error("unauthorized_client") unless ciba_client_eligible?(oauth_application)
          ciba_process_signed_request!
          requested = validate_ciba_request!
          delivery = ciba_ping_delivery_parameters
          account_id = if requested.key?(:id_token_hint)
                         subject = ciba_id_token_hint_subject(requested.delete(:id_token_hint))
                         resolve_ciba_id_token_subject(subject, oauth_application: oauth_application)
                       elsif requested.key?(:login_hint_token)
                         resolve_ciba_login_hint_token(requested.delete(:login_hint_token), oauth_application: oauth_application)
                       else
                         resolve_ciba_login_hint(requested.delete(:login_hint), oauth_application: oauth_application)
                       end
          ciba_error("unknown_user_id") unless ciba_account_eligible?(account_id)
          if ciba_request_context_enabled
            validate_ciba_request_context(requested[:request_context]&.dup&.freeze, oauth_application: oauth_application)
          end
          if ciba_user_code_enabled
            accepted = verify_ciba_user_code(requested.delete(:user_code), account_id: account_id, oauth_application: oauth_application)
            ciba_error("invalid_user_code") unless accepted == true
          end
          public_id = SecureRandom.urlsafe_base64(32)
          delivery[:auth_req_id] = public_id if delivery
          lifetime = requested.delete(:lifetime)
          now = ciba_now
          row = requested.merge(auth_req_id_digest: Digest::SHA256.hexdigest(public_id),
            account_id: account_id, oauth_application_id: oauth_application[oauth_applications_id_column],
            created_at: now, expires_at: now + lifetime,
            status: "pending", lock_version: 0, interval: ciba_poll_interval)
          ciba_transaction do
            @ciba_current_request = ciba_snapshot(row)
            before_ciba_request
            row[:id] = ciba_ds.insert(ciba_values(row))
            db[ciba_ping_deliveries_table].insert(delivery.merge(request_id: row[:id])) if delivery
            @ciba_current_request = ciba_snapshot(row)
            after_ciba_request
            ciba_emit(row, "request_accepted", nil, "pending")
            snapshot = ciba_snapshot(row)
            db.after_commit(savepoint: true) { ciba_observe { ciba_request_accepted(snapshot) } }
          end
          trigger_ciba_authentication_device(ciba_request(row[:id]))
          json_response_success(auth_req_id: public_id, expires_in: row[:expires_at] - row[:created_at], interval: row[:interval])
        ensure
          @ciba_current_request = nil
        end
      end
    end

    def resolve_ciba_login_hint(_hint, oauth_application:)
      raise NotImplementedError, "configure resolve_ciba_login_hint"
    end

    def resolve_ciba_login_hint_token(_token, oauth_application:)
      raise CibaSupport::ConfigurationError, "configure resolve_ciba_login_hint_token"
    end

    def resolve_ciba_id_token_subject(_subject, oauth_application:)
      raise CibaSupport::ConfigurationError, "configure resolve_ciba_id_token_subject"
    end

    def ciba_pairwise_identifier(_account_id, oauth_application:, sector_identifier:)
      raise CibaSupport::ConfigurationError, "configure ciba_pairwise_identifier"
    end

    def verify_ciba_user_code(_code, account_id:, oauth_application:)
      raise CibaSupport::ConfigurationError, "configure verify_ciba_user_code"
    end

    def ciba_http_address_allowed?(address)
      CibaSupport::HTTP.public_address?(address)
    end

    def validate_ciba_binding_message(message)
      return if message.nil?
      ciba_error("invalid_binding_message") unless message.match?(/\A[a-zA-Z0-9\-._+\/!?#]{1,20}\z/)
    end

    def ciba_now
      Time.now.to_i
    end

    def ciba_current_request
      @ciba_current_request
    end

    def ciba_current_refresh
      @ciba_current_refresh
    end

    def ciba_request_accepted(_request)
    end

    def trigger_ciba_authentication_device(_request)
      raise CibaSupport::ConfigurationError, "configure trigger_ciba_authentication_device"
    end

    def observe_ciba_event(_event)
    end

    def report_ciba_observer_error(error)
      warn "CIBA observer failed (#{error.class})"
    end

    def report_ciba_processing_error(error)
      warn "CIBA processing failed (#{error.class})"
    end

    def ciba_account_eligible?(id)
      id && db[accounts_table].where(account_id_column => id, account_status_column => account_open_status_value).any?
    end

    def create_ciba_grant(account_id:, oauth_application_id:, scopes:, expires_at: ciba_now + ciba_grant_lifetime,
                          claims: [], rejected_claims: [], resources: {}, authorization_details: [])
      claim_consent = ciba_claim_consent(claims, rejected_claims)
      unless scopes.is_a?(String) && scopes.valid_encoding? && scopes.bytesize <= 4096 &&
             scopes.match?(/\A[\x21\x23-\x5B\x5D-\x7E]+(?: [\x21\x23-\x5B\x5D-\x7E]+)*\z/)
        raise ArgumentError, "invalid scopes"
      end
      unless expires_at.nil? || (expires_at.is_a?(Integer) && expires_at > ciba_now)
        raise ArgumentError, "invalid expires_at"
      end
      scopes = scopes.split.uniq
      application = oauth_application_ds(oauth_application_id).first
      unless scopes.include?("openid") && ciba_account_eligible?(account_id) && ciba_client_eligible?(application, scopes)
        raise CibaSupport::Ineligible, "account, client or scopes unavailable"
      end
      row = {account_id: account_id, oauth_application_id: oauth_application_id,
        scopes: scopes.join(oauth_scope_separator), created_at: ciba_now, expires_at: expires_at, revoked_at: nil}
      row[:claims] = claim_consent if ciba_claims_enabled
      resource_consent = ciba_resource_consent(resources, application)
      row[:resources] = resource_consent if ciba_resources_enabled
      if ciba_authorization_details_enabled
        row[:authorization_details] = JSON.generate(ciba_checked_authorization_details(JSON.generate(authorization_details), application))
      elsif authorization_details != []
        raise ArgumentError, "authorization details not enabled"
      end
      row[:id] = db[ciba_grants_table].insert(row)
      ciba_snapshot(row)
    end

    def ciba_grant(id)
      ciba_validate_id!(id)
      row = db[ciba_grants_table].where(id: id).first
      raise CibaSupport::NotFound, "grant not found" unless row
      ciba_snapshot(row)
    end

    def revoke_ciba_grant(id)
      ciba_validate_id!(id)
      ciba_transaction do
        grant = ciba_locked_grant(id)
        raise CibaSupport::NotFound, "grant not found" unless grant
        db[ciba_grants_table].where(id: id, revoked_at: nil).update(revoked_at: ciba_now)
        db[oauth_grants_table].where(oauth_grants_ciba_grant_id_column => id)
          .update(oauth_grants_revoked_at_column => Sequel::CURRENT_TIMESTAMP)
      end
      :revoked
    end

    # Like node-oidc-provider's backchannelResult: trust a saved grant, not caller claims.
    def backchannel_result(id, result, auth_time: nil, acr: nil, amr: nil)
      if result.is_a?(CibaSupport::ProtocolError)
        code = result.code
        unless code.is_a?(String) && code.valid_encoding? && code.bytesize <= 1024 &&
            code.match?(/\A[\x20-\x21\x23-\x5B\x5D-\x7E]+\z/)
          raise ArgumentError, "invalid result error"
        end
        context = {completion_error: code == "access_denied" ? nil : code.dup}
        return ciba_complete(id, ciba_request(id)[:account_id], "denied", context)
      end
      grant_id = result.is_a?(Hash) ? result.fetch(:id) : result
      grant = ciba_grant(grant_id)
      approve_ciba_request(id, account_id: grant[:account_id], grant_id: grant_id,
        auth_time: auth_time, acr: acr, amr: amr)
    end

    def approve_ciba_request(id, account_id:, auth_time: nil, acr: nil, amr: nil, grant_id: nil)
      unless auth_time.nil? || (auth_time.is_a?(Integer) && auth_time >= 0 && auth_time <= ciba_now)
        raise ArgumentError, "invalid auth_time"
      end
      raise ArgumentError, "invalid acr" unless acr.nil? || (acr.is_a?(String) && acr.bytesize <= 1024 && acr.valid_encoding?)
      unless amr.nil? || (amr.is_a?(Array) && amr.size <= 32 && amr.all? { |v| v.is_a?(String) && v.valid_encoding? && v.bytesize <= 128 })
        raise ArgumentError, "invalid amr"
      end
      context = {auth_time: auth_time, acr: acr, amr: amr && JSON.generate(amr.uniq.sort)}
      unless grant_id.nil?
        ciba_validate_id!(grant_id)
        context[:grant_id] = grant_id
      end
      ciba_complete(id, account_id, "approved", context)
    end

    def deny_ciba_request(id, account_id:)
      ciba_complete(id, account_id, "denied", {completion_error: nil})
    end

    def retry_ciba_ping(id)
      ciba_validate_id!(id)
      raise CibaSupport::ConfigurationError, "ping not enabled" unless ciba_ping_enabled
      raise CibaSupport::ConfigurationError, "ping delivery requires a committed transaction" if db.in_transaction?
      row = ciba_read(ciba_ds.where(ciba_values(id: id)).first)
      raise CibaSupport::NotFound, "request not found" unless row
      return :not_deliverable unless %w[approved denied].include?(row[:status]) && row[:expires_at] > ciba_now
      delivery = db[ciba_ping_deliveries_table].where(request_id: id).first
      return :not_deliverable unless delivery
      application = oauth_application_ds(row[:oauth_application_id]).first
      unless ciba_client_eligible?(application) &&
             application[oauth_applications_backchannel_token_delivery_mode_column] == "ping"
        raise CibaSupport::Ineligible, "ping client unavailable"
      end
      # Like Client.backchannelPing, resolve the registered destination at dispatch.
      # A management update does not rewrite an already constructed HTTP request.
      uri = URI(application[oauth_applications_backchannel_client_notification_endpoint_column])
      outgoing = Net::HTTP::Post.new(uri.request_uri)
      outgoing["authorization"] = "Bearer #{delivery[:notification_token]}"
      outgoing["content-type"] = "application/json"
      outgoing.body = JSON.generate(auth_req_id: delivery[:auth_req_id])
      begin
        result = CibaSupport::HTTP.request(uri, outgoing, address_allowed: method(:ciba_http_address_allowed?), read_body: false)
        raise CibaSupport::PingDeliveryError, "ping endpoint did not acknowledge notification" unless %w[200 204].include?(result.code)
      rescue CibaSupport::HTTP::Error, IOError, SystemCallError, Timeout::Error, SocketError, OpenSSL::SSL::SSLError, Net::HTTPBadResponse
        raise CibaSupport::PingDeliveryError, "ping delivery failed"
      end
      :delivered
    end

    def ciba_request(id)
      ciba_validate_id!(id)
      row = ciba_read(ciba_ds.where(ciba_values(id: id)).first)
      raise CibaSupport::NotFound, "request not found" unless row
      ciba_snapshot(row)
    end

    def pending_ciba_requests(after_id: nil, limit: 100)
      ciba_validate_limit!(limit)
      ciba_validate_id!(after_id) if after_id
      ds = ciba_ds.where(ciba_values(status: "pending")).where(Sequel[ciba_column(:expires_at)] > ciba_now)
      ds = ds.where(Sequel[ciba_column(:id)] > after_id) if after_id
      ds.order(ciba_column(:id)).limit(limit).all.map { |row| ciba_snapshot(ciba_read(row)) }.freeze
    end

    def cleanup_ciba_requests(before:, limit: 100)
      raise ArgumentError, "before must be a past epoch second" unless before.is_a?(Integer) && before <= ciba_now
      ciba_validate_limit!(limit)
      expired = Sequel.&(ciba_values(status: %w[pending approved]), Sequel[ciba_column(:expires_at)] < before)
      denied = Sequel.&(ciba_values(status: "denied"), Sequel[ciba_column(:completed_at)] < before)
      consumed = Sequel.&(ciba_values(status: "consumed"), Sequel[ciba_column(:consumed_at)] < before)
      eligible = ciba_ds.where(Sequel.|(expired, denied, consumed))
      ciba_transaction do
        ids = eligible.order(ciba_column(:id)).limit(limit).select_map(ciba_column(:id))
        eligible.where(ciba_values(id: ids)).delete
      end
    end

    def cleanup_ciba_client_assertions(limit: 100)
      ciba_validate_limit!(limit)
      ds = db[ciba_client_assertions_table].where(Sequel[:expires_at] <= ciba_now)
      ciba_transaction do
        ids = ds.order(:expires_at, :digest).limit(limit).select_map(:digest)
        ds.where(digest: ids).delete
      end
    end

    # Never remove an unexpired consumed digest: it is still replay evidence.
    # Expiry is checked before replay detection, matching the reference ordering.
    def cleanup_ciba_refresh_tokens(limit: 100)
      ciba_validate_limit!(limit)
      ds = db[ciba_refresh_tokens_table].where(Sequel[:expires_at] <= ciba_now)
      ciba_transaction do
        ids = ds.order(:expires_at, :id).limit(limit).select_map(:id)
        ds.where(id: ids).delete
      end
    end

    def oauth_grant_types_supported
      super | [CibaSupport::GRANT_TYPE]
    end

    def check_csrf?
      request.path == backchannel_authentication_path ? false : super
    end

    def accepts_json?
      request.path == backchannel_authentication_path || super
    end

    private

    def post_configure
      super
      unless db[ciba_requests_table].columns.include?(ciba_column(:authentication_claims))
        raise CibaSupport::ConfigurationError, "migrate CIBA authentication_claims request storage"
      end
      unless db[ciba_requests_table].columns.include?(ciba_column(:max_age))
        raise CibaSupport::ConfigurationError, "migrate CIBA max_age request storage"
      end
      unless db[ciba_requests_table].columns.include?(ciba_column(:completion_error))
        raise CibaSupport::ConfigurationError, "migrate CIBA completion_error request storage"
      end
      if ciba_refresh_tokens_enabled && !db[ciba_refresh_tokens_table].columns.include?(:authentication_claims)
        raise CibaSupport::ConfigurationError, "migrate CIBA authentication_claims refresh storage"
      end
      if features.include?(:oauth_dpop) && (!ciba_dpop_nonce_secret.nil? || oauth_dpop_use_nonce) &&
          !(ciba_dpop_nonce_secret.is_a?(String) && ciba_dpop_nonce_secret.bytesize == 32)
        raise CibaSupport::ConfigurationError, "configure a 32-byte ciba_dpop_nonce_secret"
      end
      if features.include?(:oauth_dpop) && (!db.table_exists?(ciba_client_assertions_table) ||
          !db[oauth_grants_table].columns.include?(oauth_grants_dpop_jkt_column))
        raise CibaSupport::ConfigurationError, "migrate CIBA assertion ledger and upstream DPoP token thumbprints before enabling oauth_dpop"
      end
      self.class.prepend(CibaSupport::Dpop) unless self.class.ancestors.include?(CibaSupport::Dpop)
      if features.include?(:oauth_tls_client_auth)
        if method(:ciba_tls_client_certificate).owner == Rodauth::Ciba
          raise CibaSupport::ConfigurationError, "configure a trusted ciba_tls_client_certificate callback"
        end
        unless db[oauth_grants_table].columns.include?(oauth_grants_certificate_thumbprint_column)
          raise CibaSupport::ConfigurationError, "migrate certificate thumbprint storage before enabling oauth_tls_client_auth"
        end
      end
      self.class.prepend(CibaSupport::Mtls) unless self.class.ancestors.include?(CibaSupport::Mtls)
      self.class.prepend(CibaSupport::IdTokenEncryption) unless self.class.ancestors.include?(CibaSupport::IdTokenEncryption)
      if ciba_pairwise_enabled && method(:ciba_pairwise_identifier).owner == Rodauth::Ciba
        raise CibaSupport::ConfigurationError, "configure ciba_pairwise_identifier"
      end
      if ciba_pairwise_enabled && !db[oauth_grants_table].columns.include?(ciba_token_subject_column)
        raise CibaSupport::ConfigurationError, "migrate CIBA token subject storage before enabling pairwise"
      end
      self.class.prepend(CibaSupport::PairwiseSubjects) unless self.class.ancestors.include?(CibaSupport::PairwiseSubjects)
      unless self.class.instance_variable_defined?(:@ciba_jwks_cache)
        self.class.instance_variable_set(:@ciba_jwks_cache, CibaSupport::JwksCache.new(http_request_cache))
      end
      unless self.class.instance_variable_defined?(:@ciba_sector_validation_cache)
        self.class.instance_variable_set(:@ciba_sector_validation_cache, [Mutex.new, {}])
      end
      if ciba_request_context_enabled && method(:validate_ciba_request_context).owner == Rodauth::Ciba
        raise CibaSupport::ConfigurationError, "configure validate_ciba_request_context"
      end
      if ciba_user_code_enabled && method(:verify_ciba_user_code).owner == Rodauth::Ciba
        raise CibaSupport::ConfigurationError, "configure verify_ciba_user_code"
      end
      unless ciba_request_signing_algorithms.is_a?(Array) &&
             (ciba_request_signing_algorithms - %w[RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES384 ES512 Ed25519 EdDSA]).empty?
        raise CibaSupport::ConfigurationError, "configure asymmetric CIBA request signing algorithms"
      end
      unless ciba_client_assertion_signing_algorithms.nil? ||
          (ciba_client_assertion_signing_algorithms.is_a?(Array) &&
           (ciba_client_assertion_signing_algorithms - %w[RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES384 ES512 HS256 HS384 HS512 Ed25519 EdDSA]).empty?)
        raise CibaSupport::ConfigurationError, "configure CIBA client assertion signing algorithms"
      end
      unless ciba_id_token_signing_keys.is_a?(Hash) &&
          (ciba_id_token_signing_keys.keys - %w[Ed25519 EdDSA]).empty?
        raise CibaSupport::ConfigurationError, "configure Edwards CIBA ID Token keys"
      end
      ciba_id_token_signing_keys.each_value do |configured|
        keys = Array(configured)
        unless !keys.empty? && keys.all? { |key| key.is_a?(OpenSSL::PKey::PKey) && key.oid == "ED25519" }
          raise CibaSupport::ConfigurationError, "configure Ed25519 keys with an active private key first"
        end
        begin
          keys.first.private_to_der
        rescue OpenSSL::PKey::PKeyError
          raise CibaSupport::ConfigurationError, "configure an active private Ed25519 key first"
        end
      end
      if ciba_id_token_hint_enabled && method(:resolve_ciba_id_token_subject).owner == Rodauth::Ciba
        raise CibaSupport::ConfigurationError, "configure resolve_ciba_id_token_subject"
      end
      unless ciba_id_token_hint_max_age.nil? || (ciba_id_token_hint_max_age.is_a?(Integer) && ciba_id_token_hint_max_age.positive?)
        raise CibaSupport::ConfigurationError, "configure positive ID Token hint maximum age or nil"
      end
      if ciba_login_hint_token_enabled && method(:resolve_ciba_login_hint_token).owner == Rodauth::Ciba
        raise CibaSupport::ConfigurationError, "configure resolve_ciba_login_hint_token"
      end
      if ciba_authorization_details_enabled
        unless ciba_resources_enabled && ciba_authorization_details_types.is_a?(Array) &&
               !ciba_authorization_details_types.empty? && ciba_authorization_details_types.all? { |type| type.is_a?(String) && !type.empty? }
          raise CibaSupport::ConfigurationError, "configure resources and authorization-details types"
        end
        %i[ciba_validate_authorization_details ciba_authorization_details_for_token].each do |name|
          raise CibaSupport::ConfigurationError, "configure #{name}" if method(name).owner == Rodauth::Ciba
        end
      end
      if features.include?(:oauth_dynamic_client_registration) && !self.class.ancestors.include?(CibaSupport::Registration)
        self.class.prepend(CibaSupport::Registration)
      end
      if method(:resolve_ciba_login_hint).owner == Rodauth::Ciba
        raise ArgumentError, "configure resolve_ciba_login_hint"
      end
      if oauth_jwt_keys.empty? || oauth_jwt_keys.key?("none")
        raise ArgumentError, "configure ID Token signing keys"
      end
      unless ciba_grant_lifetime.is_a?(Integer) && ciba_grant_lifetime.positive? && ciba_grant_lifetime <= 2_147_483_647
        raise ArgumentError, "configure positive CIBA grant lifetime (maximum 2^31-1 seconds)"
      end
      unless ciba_refresh_token_lifetime.is_a?(Integer) && ciba_refresh_token_lifetime.positive? && ciba_refresh_token_lifetime <= 2_147_483_647
        raise ArgumentError, "configure positive CIBA refresh lifetime (maximum 2^31-1 seconds)"
      end
      unless [ciba_request_lifetime, ciba_max_request_lifetime, ciba_poll_interval, ciba_max_request_bytes].all? { |v| v.is_a?(Integer) && v.positive? } &&
             ciba_request_lifetime <= ciba_max_request_lifetime && ciba_max_request_lifetime <= 2_147_483_647 && ciba_poll_interval <= 2_147_483_647
        raise ArgumentError, "configure positive CIBA lifetime/maximum/interval/body limit (lifetime <= maximum)"
      end
      self.class.prepend(CibaSupport::ClientAuthentication) unless self.class.ancestors.include?(CibaSupport::ClientAuthentication)
      self.class.prepend(CibaSupport::ResourceTokens) unless self.class.ancestors.include?(CibaSupport::ResourceTokens)
    end

    public :post_configure

    def ciba_metadata
      metadata = {backchannel_authentication_endpoint: backchannel_authentication_url,
       backchannel_token_delivery_modes_supported: ciba_ping_enabled ? %w[poll ping] : ["poll"], backchannel_user_code_parameter_supported: ciba_user_code_enabled}
      metadata[:revocation_endpoint] = revoke_url if features.include?(:oauth_token_revocation)
      metadata[:registration_endpoint] = register_url if features.include?(:oauth_dynamic_client_registration)
      metadata[:authorization_details_types_supported] = ciba_authorization_details_types if ciba_authorization_details_enabled
      unless ciba_request_signing_algorithms.empty?
        metadata[:backchannel_authentication_request_signing_alg_values_supported] = ciba_request_signing_algorithms
      end
      metadata
    end

    def oauth_server_metadata_body(*)
      metadata = super.merge(ciba_metadata)
      # This URN names the assertion format, not a client authentication method.
      # Keep upstream dispatch intact; only correct the shared advertised list.
      if metadata[:token_endpoint_auth_methods_supported]
        metadata[:token_endpoint_auth_methods_supported] =
          metadata[:token_endpoint_auth_methods_supported] - ["urn:ietf:params:oauth:client-assertion-type:jwt-bearer"]
      end
      if features.include?(:oauth_jwt_bearer_grant) && ciba_client_assertion_signing_algorithms
        metadata[:token_endpoint_auth_signing_alg_values_supported] =
          (Array(metadata[:token_endpoint_auth_signing_alg_values_supported]) | ciba_client_assertion_signing_algorithms)
      end
      metadata
    end

    def openid_configuration_body(*)
      # Upstream's OIDC allowlist drops these enabled OAuth extensions. Preserve
      # their actual configured metadata rather than inventing endpoint/auth
      # defaults or advertising disabled features.
      extensions = oauth_server_metadata_body(*).slice(:token_endpoint_auth_signing_alg_values_supported, :introspection_endpoint,
        :introspection_endpoint_auth_methods_supported,
        :introspection_endpoint_auth_signing_alg_values_supported,
        :dpop_signing_alg_values_supported,
        :tls_client_certificate_bound_access_tokens)
      metadata = super.merge(extensions).merge(ciba_metadata)
      unless ciba_id_token_signing_keys.empty?
        metadata[:id_token_signing_alg_values_supported] =
          Array(metadata[:id_token_signing_alg_values_supported]) | ciba_id_token_signing_keys.keys
      end
      if ciba_id_token_encryption_enabled
        metadata[:id_token_encryption_alg_values_supported] =
          Array(metadata[:id_token_encryption_alg_values_supported]) | CibaSupport::IdTokenEncryption::ALGORITHMS
        metadata[:id_token_encryption_enc_values_supported] =
          Array(metadata[:id_token_encryption_enc_values_supported]) | CibaSupport::IdTokenEncryption::METHODS
      end
      metadata
    end

    def ciba_edwards_public_jwk(key, algorithm)
      raw = OpenSSL::ASN1.decode(key.public_to_der).value.last.value
      thumbprint_input = {crv: "Ed25519", kty: "OKP", x: Base64.urlsafe_encode64(raw, padding: false)}
      thumbprint_input.merge(alg: algorithm, use: "sig",
        kid: Base64.urlsafe_encode64(Digest::SHA256.digest(JSON.generate(thumbprint_input)), padding: false))
    end

    def jwks_set
      super + ciba_id_token_signing_keys.flat_map do |algorithm, configured|
        Array(configured).map { |key| ciba_edwards_public_jwk(key, algorithm) }
      end
    end

    def jwt_encode(payload, signing_algorithm: oauth_jwt_keys.keys.first, headers: {}, **options)
      ciba_id_token = @ciba_authentication && headers[:typ] == "id_token+jwt"
      if ciba_id_token && ciba_id_token_encryption_enabled &&
          (options[:encryption_algorithm] || options[:encryption_method])
        signed = jwt_encode(payload, signing_algorithm: signing_algorithm, headers: headers,
          **options.merge(encryption_algorithm: nil, encryption_method: nil))
        return ciba_encrypt_id_token(signed, options)
      end
      if ciba_id_token && %w[HS256 HS384 HS512].include?(signing_algorithm)
        if options[:encryption_algorithm] || options[:encryption_method]
          raise CibaSupport::ConfigurationError, "CIBA ID Token encryption is not enabled"
        end
        return JWT.encode(payload.merge(jti: generate_jti(payload)), ciba_hmac_id_token_secret(signing_algorithm),
          signing_algorithm, headers)
      end
      unless ciba_id_token && ciba_id_token_signing_keys.key?(signing_algorithm)
        token = super
        if ciba_id_token && (options[:encryption_algorithm] || options[:encryption_method])
          # Some upstream backends silently return a JWS if encryption is
          # unavailable or no recipient key matches. Never release that token.
          parts = token.to_s.split(".", -1)
          encrypted_header = begin
            JSON.parse(Base64.urlsafe_decode64(parts.first)) if parts.length == 5
          rescue JSON::ParserError, ArgumentError
            nil
          end
          unless options[:encryption_algorithm] && options[:encryption_method] &&
              encrypted_header.is_a?(Hash) &&
              encrypted_header["alg"] == options[:encryption_algorithm] &&
              encrypted_header["enc"] == options[:encryption_method]
            raise CibaSupport::ConfigurationError, "CIBA ID Token encryption was not applied"
          end
        end
        return token
      end
      if options[:encryption_algorithm] || options[:encryption_method]
        raise CibaSupport::ConfigurationError, "Edwards CIBA ID Token encryption is not configured"
      end
      key = Array(ciba_id_token_signing_keys.fetch(signing_algorithm)).first
      header = headers.merge(alg: signing_algorithm, kid: ciba_edwards_public_jwk(key, signing_algorithm).fetch(:kid))
      payload = payload.merge(jti: generate_jti(payload))
      parts = [header, payload].map { |value| Base64.urlsafe_encode64(JSON.generate(value), padding: false) }
      (parts + [Base64.urlsafe_encode64(key.sign(nil, parts.join(".")), padding: false)]).join(".")
    end

    def id_token_hash(value, algorithm)
      return super unless @ciba_authentication && %w[Ed25519 EdDSA].include?(algorithm)
      Base64.urlsafe_encode64(Digest::SHA512.digest(value)[0, 32], padding: false)
    end

    def ciba_hmac_id_token_secret(algorithm)
      secret = ciba_id_token_hmac_secret(oauth_application: oauth_application)
      unless secret.is_a?(String) && secret.valid_encoding?
        raise CibaSupport::ConfigurationError, "CIBA HMAC ID Token requires the client secret"
      end
      secret = secret.encode(Encoding::UTF_8)
      if secret.bytesize < algorithm.delete_prefix("HS").to_i / 8
        raise CibaSupport::ConfigurationError, "CIBA HMAC ID Token client secret is too short"
      end
      secret
    end

    def ciba_column(name)
      ciba_request_columns.fetch(name, name)
    end

    def ciba_values(values)
      values.to_h { |key, value| [ciba_column(key), value] }
    end

    def ciba_read(row)
      return unless row
      names = ciba_request_columns.invert
      row.to_h { |key, value| [names.fetch(key, key), value] }
    end

    def ciba_ds
      db[ciba_requests_table]
    end

    def ciba_snapshot(row)
      row.reject { |key, _| [:auth_req_id_digest, :token_digest].include?(key) }.to_h do |key, value|
        [key, value.is_a?(String) ? value.dup.freeze : value]
      end.freeze
    end

    def ciba_validate_id!(id)
      raise ArgumentError, "request ID must be a positive integer" unless id.is_a?(Integer) && id.positive?
    end

    def ciba_validate_limit!(limit)
      raise ArgumentError, "limit must be 1..1000" unless limit.is_a?(Integer) && (1..1000).cover?(limit)
    end

    # Locking reads prevent stale REPEATABLE READ snapshots during pending polls.
    # SQLite obtains its write reservation when the transaction starts instead.
    def ciba_locked_row(ds)
      ciba_read((db.database_type == :sqlite ? ds : ds.for_update).first)
    end

    # Grant-scoped revocation must use the same lock order as issuance. The first
    # read only identifies the grant; always re-read the source under its lock.
    # A pending request can become bound in between, so retry rather than acquire
    # the newly attached grant while already holding the source lock.
    def ciba_lock_source_after_grant(ds, request_columns: false, grant_key: :grant_id)
      candidate = ds.first
      candidate = ciba_read(candidate) if request_columns
      return unless candidate
      ciba_locked_grant(candidate[grant_key]) if candidate[grant_key]
      current = (db.database_type == :sqlite ? ds : ds.for_update).first
      current = ciba_read(current) if request_columns
      if current && current[grant_key] != candidate[grant_key]
        raise Sequel::SerializationFailure, "CIBA source binding changed while locking"
      end
      current
    end

    def ciba_claim!(row)
      changed = ciba_ds.where(ciba_values(id: row[:id], status: row[:status], lock_version: row[:lock_version]))
                       .update(ciba_values(lock_version: row[:lock_version] + 1))
      raise CibaSupport::Conflict, "concurrent modification" unless changed == 1
      raise CibaSupport::Expired, "request expired" if row[:expires_at] <= ciba_now
    end

    def ciba_guard(id)
      registry = Thread.current[:rodauth_ciba_mutations] ||= {}
      key = [db.object_id, id]
      raise CibaSupport::ReentrantMutation, "request mutation is already active" if registry[key]
      registry[key] = true
      begin
        yield
      ensure
        registry.delete(key)
      end
    end

    def ciba_complete(id, account_id, outcome, context)
      ciba_validate_id!(id)
      ciba_guard(id) do
        ciba_transaction do
          ciba_locked_grant(context[:grant_id]) if context[:grant_id]
          row = ciba_locked_row(ciba_ds.where(ciba_values(id: id)))
          raise CibaSupport::NotFound, "request not found" unless row
          raise CibaSupport::IdentityMismatch, "account does not match" unless row[:account_id] == account_id
          raise CibaSupport::Expired, "request expired" if row[:expires_at] <= ciba_now
          authorized_scopes = context[:grant_id] ? ciba_authorized_scopes!(row, context[:grant_id]) : row[:scopes].split
          if row[:status] != "pending"
            consumed_outcome = row[:grant_id] ? "approved" : "denied"
            same_outcome = row[:status] == outcome || (row[:status] == "consumed" && outcome == consumed_outcome)
            same_context = context.all? { |key, value| row[key] == value }
            raise CibaSupport::Conflict, "completion conflicts with existing result" unless same_outcome && same_context
            next :already_completed
          end
          application = oauth_application_ds(row[:oauth_application_id]).first
          unless ciba_account_eligible?(account_id) && ciba_client_eligible?(application, authorized_scopes)
            raise CibaSupport::Ineligible, "account or client unavailable"
          end
          ciba_claim!(row)
          action = outcome == "approved" ? "approve" : "deny"
          @ciba_current_request = ciba_snapshot(row)
          send("before_ciba_#{action}")
          raise CibaSupport::Expired, "request expired" if row[:expires_at] <= ciba_now
          ciba_authorized_scopes!(row, context[:grant_id]) if context[:grant_id]
          if outcome == "approved" && !context[:grant_id]
            context[:grant_id] = create_ciba_grant(account_id: account_id,
              oauth_application_id: row[:oauth_application_id], scopes: row[:scopes])[:id]
          end
          updates = context.merge(status: outcome, completed_at: ciba_now)
          ciba_ds.where(ciba_values(id: id)).update(ciba_values(updates))
          row.merge!(updates)
          @ciba_current_request = ciba_snapshot(row)
          send("after_ciba_#{action}")
          ciba_emit(row, row[:completion_error] ? "failed" : outcome, "pending", outcome)
          if ciba_ping_enabled && db[ciba_ping_deliveries_table].where(request_id: id).get(:request_id)
            db.after_commit(savepoint: true) { retry_ciba_ping(id) }
          end
          outcome.to_sym
        end
      end
    ensure
      @ciba_current_request = nil
    end

    def ciba_locked_grant(id)
      ciba_validate_id!(id)
      ds = db[ciba_grants_table].where(id: id)
      (db.database_type == :sqlite ? ds : ds.for_update).first
    end

    def ciba_authorized_scopes!(request, grant_id)
      grant = ciba_locked_grant(grant_id)
      raise CibaSupport::Ineligible, "grant unavailable" unless grant && !grant[:revoked_at] &&
        (!grant[:expires_at] || grant[:expires_at] > ciba_now)
      unless grant[:account_id] == request[:account_id] && grant[:oauth_application_id] == request[:oauth_application_id]
        raise CibaSupport::IdentityMismatch, "grant account or client does not match"
      end
      scopes = request[:scopes].split & grant[:scopes].split
      raise CibaSupport::Ineligible, "openid not authorized" unless scopes.include?("openid")
      scopes
    end

    def ciba_consume_client_assertion!(application, claims)
      digest = Digest::SHA256.hexdigest(JSON.generate([application[oauth_applications_client_id_column], claims["jti"]]))
      ciba_transaction do
        db[ciba_client_assertions_table].insert(digest: digest, expires_at: claims["exp"].ceil)
      end
    rescue Sequel::UniqueConstraintViolation
      authorization_required
    end

    def response_error_params(error_code, message = nil)
      payload = super
      return payload unless ciba_protocol_request?
      payload = payload.dup
      # OIDC/OAuth error descriptions are optional; omit invalid customization
      # rather than echoing characters outside the protocol's ASCII repertoire.
      description = payload["error_description"]
      if description && (!description.is_a?(String) || !description.valid_encoding? ||
                         !description.match?(/\A[\x20-\x21\x23-\x5B\x5D-\x7E]*\z/))
        payload.delete("error_description")
      end
      payload
    end

    def ciba_client_eligible?(application, requested_scopes = ["openid"])
      return false unless application
      algorithm = application[oauth_applications_id_token_signed_response_alg_column] || oauth_jwt_keys.keys.first
      return false unless algorithm != "none" && (oauth_jwt_keys.key?(algorithm) || ciba_id_token_signing_keys.key?(algorithm))
      request_algorithm = application[oauth_applications_backchannel_authentication_request_signing_alg_column]
      return false if request_algorithm && !ciba_request_signing_algorithms.include?(request_algorithm)
      return false if application[oauth_applications_backchannel_user_code_parameter_column] && !ciba_user_code_enabled
      return false unless (requested_scopes - oauth_application_scopes).empty?
      mode = application[oauth_applications_backchannel_token_delivery_mode_column]
      return false unless mode == "poll" || (mode == "ping" && ciba_ping_enabled &&
        ciba_valid_ping_endpoint?(application[oauth_applications_backchannel_client_notification_endpoint_column]))
      methods = application[oauth_applications_token_endpoint_auth_method_column].to_s.split
      methods = oauth_default_token_endpoint_auth_methods if methods.empty?
      # Upstream advertises this legacy assertion-type URN, but JWT verification
      # dispatches only to private_key_jwt or client_secret_jwt authentication.
      return false if methods.include?("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
      subject_type = application[oauth_applications_subject_type_column] || oauth_jwt_subject_type
      subject_valid = subject_type == "public" || (subject_type == "pairwise" &&
        ciba_pairwise_sector(application) && ciba_pairwise_sector_document_valid?(application))
      application[oauth_applications_grant_types_column].to_s.split.include?(CibaSupport::GRANT_TYPE) &&
        subject_valid &&
        !methods.empty? && (methods - (oauth_confidential_token_endpoint_auth_methods & oauth_token_endpoint_auth_methods_supported)).empty? &&
        (requested_scopes - application[oauth_applications_scopes_column].to_s.split).empty?
    end

    def ciba_valid_ping_endpoint?(endpoint)
      return false unless endpoint.is_a?(String) && endpoint.valid_encoding? && endpoint.bytesize <= 2048
      uri = URI(endpoint)
      uri.scheme == "https" && uri.hostname && !uri.hostname.empty? && !uri.userinfo && !uri.fragment
    rescue URI::InvalidURIError
      false
    end

    def ciba_ping_delivery_parameters
      return unless oauth_application[oauth_applications_backchannel_token_delivery_mode_column] == "ping"
      token = ciba_parameter("client_notification_token", required: true, max: 1024)
      ciba_error("invalid_request") unless token.match?(/\A[A-Za-z0-9._~+\/-]+=*\z/)
      {notification_token: token,
        endpoint: oauth_application[oauth_applications_backchannel_client_notification_endpoint_column]}
    end

    def ciba_protocol_request?
      return true if @ciba_invalid_parameters
      ciba_token_revocation_request? || request.path == backchannel_authentication_path ||
        (request.path == token_path && (request.params["grant_type"] == CibaSupport::GRANT_TYPE || ciba_refresh_request?))
    rescue Rack::QueryParser::ParameterTypeError, Rack::QueryParser::InvalidParameterError, Rack::QueryParser::QueryLimitError
      @ciba_invalid_parameters = true
    end

    # RFC 6749 section 2.3.1 encodes each Basic credential as form data.
    # Reuse upstream method registration and secret verification after decoding.
    def require_oauth_application_from_client_secret_basic(token)
      return super unless ciba_protocol_request?
      begin
        encoded = Base64.strict_decode64(token)
        client, secret = encoded.split(":", 2)
        authorization_required unless client && secret
        client = URI.decode_www_form_component(client)
        secret = URI.decode_www_form_component(secret)
        authorization_required unless client.valid_encoding? && secret.valid_encoding?
      rescue ArgumentError
        authorization_required
      end
      application = db[oauth_applications_table].where(oauth_applications_client_id_column => client).first
      authorization_required unless supports_auth_method?(application, "client_secret_basic") && secret_matches?(application, secret)
      @ciba_verified_client_secret = [application[oauth_applications_id_column], secret.dup.freeze].freeze
      application
    end

    def require_oauth_application_from_client_secret_post(client_id, secret)
      application = super
      if ciba_protocol_request?
        @ciba_verified_client_secret = [application[oauth_applications_id_column], secret.dup.freeze].freeze
      end
      application
    end

    def www_authenticate_header(*)
      ciba_protocol_request? ? 'Basic realm="CIBA"' : super
    end

    def validate_ciba_transport!
      ciba_error("invalid_request") if @ciba_invalid_parameters
      ciba_error("invalid_request") if ciba_require_tls && !request.ssl?
      ciba_error("invalid_request") unless request.media_type == "application/x-www-form-urlencoded" && request.query_string.empty?
      # Rack 3 inputs need not support rewind. Reuse Rack's parsed form buffer,
      # or replace an as-yet unread input with our bounded copy for later parsing.
      body = request.env["rack.request.form_vars"]
      unless body
        body = request.body&.read(ciba_max_request_bytes + 1).to_s
        request.env["rack.input"] = StringIO.new(body)
      end
      ciba_error("invalid_request") if body.bytesize > ciba_max_request_bytes || body.match?(/%(?![0-9a-fA-F]{2})/)
      pairs = body.split("&").map do |part|
        part.split("=", 2).map { |value| URI.decode_www_form_component(value, Encoding::UTF_8) }
      end
      ciba_error("invalid_request") if pairs.any? { |pair| pair.any? { |value| !value.valid_encoding? } }
      pairs = URI.decode_www_form(body, Encoding::UTF_8)
      keys = pairs.map(&:first)
      if (keys.include?("client_secret") && request.env["HTTP_AUTHORIZATION"]) ||
         (keys.include?("client_assertion") && (keys.include?("client_secret") || request.env["HTTP_AUTHORIZATION"]))
        ciba_error("invalid_request")
      end
      scalar_keys = ciba_resources_enabled ? keys.reject { |key| key == "resource" } : keys
      ciba_error("invalid_request") unless scalar_keys.uniq.length == scalar_keys.length
      @ciba_form_resources = pairs.select { |key, _| key == "resource" }.map(&:last)
      ciba_error("invalid_request") if pairs.any? { |key, value| !key.valid_encoding? || !value.valid_encoding? }
    rescue ArgumentError
      ciba_error("invalid_request")
    end

    def ciba_parameter(name, required: false, max: 1024, error: "invalid_request")
      value = request.params[name]
      if value.nil?
        ciba_error(error) if required
        return
      end
      ciba_error(error) unless value.is_a?(String) && value.valid_encoding? && !value.empty? && value.bytesize <= max
      value
    end

    def ciba_claim_names(values)
      protected_names = %w[sub iss aud exp iat auth_time acr amr nonce at_hash c_hash sid jti]
      unless values.is_a?(Array) && values.size <= 64 && values.all? { |name|
        name.is_a?(String) && name.bytesize <= 128 && ciba_supported_claims.include?(name) && !protected_names.include?(name)
      }
        raise ArgumentError, "invalid consent claims"
      end
      values.uniq
    end

    def ciba_valid_resource?(value)
      return false unless value.is_a?(String) && value.valid_encoding? && !value.empty? && value.bytesize <= 1024
      uri = URI.parse(value)
      uri.absolute? && uri.fragment.nil?
    rescue URI::InvalidURIError
      false
    end

    def ciba_checked_authorization_details(json, application)
      details = CibaSupport::AuthorizationDetails.parse(json)
      allowed = JSON.parse(application[:authorization_details_types] || "[]")
      unless allowed.is_a?(Array) && details.all? { |detail|
        ciba_authorization_details_types.include?(detail["type"]) && allowed.include?(detail["type"])
      } && ciba_validate_authorization_details(details, oauth_application: ciba_snapshot(application)) == true
        raise CibaSupport::ProtocolError, "invalid_authorization_details"
      end
      details
    rescue CibaSupport::AuthorizationDetails::Invalid, JSON::ParserError
      raise CibaSupport::ProtocolError, "invalid_authorization_details"
    end

    def ciba_compile_authorization_details(row, resource_attributes)
      if !ciba_authorization_details_enabled
        return
      end
      application = oauth_application_ds(row[:oauth_application_id]).first
      requested = ciba_checked_authorization_details(row[:requested_authorization_details] || "[]", application)
      approved = ciba_checked_authorization_details(ciba_locked_grant(row[:grant_id])[:authorization_details] || "[]", application)
      narrowing = request.params.key?("authorization_details") ?
        ciba_checked_authorization_details(request.params["authorization_details"], application) : nil
      return if requested.empty? && approved.empty? && narrowing.nil?
      raise CibaSupport::ProtocolError, "invalid_target" unless resource_attributes
      # The application owns type-specific subset/enrichment semantics. All
      # inputs are reloaded/validated and immutable; no caller grant hash is used.
      effective = ciba_authorization_details_for_token(requested: requested, approved: approved,
        narrowing: narrowing, resource: resource_attributes[:ciba_resource].dup.freeze,
        oauth_application: ciba_snapshot(application))
      effective = ciba_checked_authorization_details(JSON.generate(effective), application)
      JSON.generate(effective) unless effective.empty?
    end

    def ciba_resource_policy(resource, application)
      raise CibaSupport::ProtocolError, "invalid_target" unless ciba_valid_resource?(resource)
      policy = ciba_resource_server(resource, oauth_application: application)
      raise CibaSupport::ProtocolError, "invalid_target" unless policy
      unless policy.is_a?(Hash) && policy[:scopes].is_a?(Array) && policy[:scopes].all? { |v|
        v.is_a?(String) && v.match?(/\A[\x21\x23-\x5B\x5D-\x7E]+\z/)
      } && policy[:audience].is_a?(String) && !policy[:audience].empty? &&
          policy[:audience].valid_encoding? && policy[:audience].bytesize <= 1024
        raise ArgumentError, "invalid CIBA resource server configuration"
      end
      policy
    end

    def ciba_resource_consent(resources, application)
      raise ArgumentError, "resources not enabled" if !ciba_resources_enabled && resources != {}
      raise ArgumentError, "invalid resource consent" unless resources.is_a?(Hash) && resources.size <= 16
      result = resources.to_h do |resource, scope|
        policy = ciba_resource_policy(resource, application)
        unless scope.is_a?(String) && scope.bytesize <= 4096 && scope.valid_encoding? &&
               scope.match?(/\A[\x21\x23-\x5B\x5D-\x7E]+(?: [\x21\x23-\x5B\x5D-\x7E]+)*\z/)
          raise ArgumentError, "invalid resource scopes"
        end
        scopes = scope.split.uniq
        unless (scopes - policy[:scopes]).empty? && ciba_client_eligible?(application, scopes)
          raise CibaSupport::Ineligible, "resource scopes unavailable"
        end
        [resource, scopes.join(" ")]
      end
      JSON.generate(result)
    end

    def ciba_requested_resources
      values = @ciba_form_resources || []
      raise CibaSupport::ProtocolError, "invalid_target" if values.size > 16 ||
        (request.params.key?("resource") && !request.params["resource"].is_a?(String))
      values.each { |value| ciba_resource_policy(value, oauth_application) }
      JSON.generate(values.uniq)
    end

    def ciba_token_resource(row)
      return unless ciba_resources_enabled
      targets = @ciba_form_resources || []
      if targets.size > 1 || (request.params.key?("resource") && !request.params["resource"].is_a?(String))
        raise CibaSupport::ProtocolError, "invalid_target"
      end
      requested = JSON.parse(row[:requested_resources] || "[]")
      application = oauth_application_ds(row[:oauth_application_id]).first
      resource = targets.first
      if targets.empty? && !requested.empty?
        use_granted = ciba_use_granted_resource(ciba_snapshot(row))
        unless use_granted == true || use_granted == false
          raise ArgumentError, "ciba_use_granted_resource must return a boolean"
        end
        if use_granted
          resource = requested.size == 1 ? requested.first :
            ciba_default_resource(requested.map { |value| value.dup.freeze }.freeze,
              oauth_application: application)
        end
      end
      return if resource.nil? # Default node policy: use the OIDC/UserInfo grant.
      unless requested.include?(resource)
        raise CibaSupport::ProtocolError, "invalid_target"
      end
      policy = ciba_resource_policy(resource, application)
      consent = JSON.parse(ciba_locked_grant(row[:grant_id])[:resources] || "{}")
      scopes = row[:scopes].split & consent.fetch(resource, "").split & policy[:scopes]
      raise CibaSupport::ProtocolError, "invalid_grant" unless ciba_client_eligible?(application, scopes)
      {ciba_resource: resource, ciba_resource_audience: policy[:audience],
       oauth_grants_scopes_column => scopes.join(oauth_scope_separator)}
    end

    def ciba_claim_consent(allowed, rejected)
      raise ArgumentError, "explicit claims not enabled" if !ciba_claims_enabled && (allowed != [] || rejected != [])
      JSON.generate(allowed: ciba_claim_names(allowed), rejected: ciba_claim_names(rejected))
    end

    def ciba_parse_requested_claims
      value = ciba_parameter("claims", max: 8192)
      return JSON.generate({}) unless value
      data = JSON.parse(value, max_nesting: 10)
      unless data.is_a?(Hash) && (data.keys & %w[id_token userinfo]).any?
        ciba_error("invalid_request")
      end
      result = {}
      %w[id_token userinfo].each do |target|
        next unless data.key?(target)
        entries = data[target]
        unless entries.is_a?(Hash) && entries.size <= 64 && entries.all? { |name, options|
          name.bytesize <= 128 && (options.nil? || options.is_a?(Hash))
        }
          ciba_error("invalid_request")
        end
        result[target] = entries
      end
      JSON.generate(result)
    rescue JSON::ParserError, JSON::NestingError
      ciba_error("invalid_request")
    end

    def ciba_compile_claims(row, scopes)
      requested = JSON.parse(row[:requested_claims] || "{}")
      consent = JSON.parse(ciba_locked_grant(row[:grant_id])[:claims] || '{"allowed":[],"rejected":[]}')
      allowed = ciba_claim_names(consent.fetch("allowed"))
      rejected = ciba_claim_names(consent.fetch("rejected"))
      implicit = scopes.flat_map { |scope| scope == "address" ? ["address"] : Array(OIDC_SCOPES_MAP[scope]).map(&:to_s) }
      result = {"version" => 1}
      %w[id_token userinfo].each do |target|
        names = Array(requested[target]&.keys) & allowed
        names |= implicit if target == "userinfo"
        result[target] = (names & ciba_supported_claims) - rejected
      end
      JSON.generate(result)
    end

    def generate_id_token(grant, include_claims = false)
      return super unless grant[oauth_grants_type_column] == CibaSupport::GRANT_TYPE && grant[:ciba_claims]
      @ciba_issuing_claims = JSON.parse(grant[:ciba_claims])
      super(grant, true)
    ensure
      @ciba_issuing_claims = nil
    end

    def fill_with_account_claims(claims, account, scopes, locales)
      projection = @ciba_issuing_claims
      target = "id_token"
      # Legacy/unbound JWTs must never inherit another issuance's explicit consent.
      if !projection && @ciba_userinfo_grant_id && request.path == userinfo_path
        token_claims = authorization_token
        if token_claims && oauth_application
          row = valid_oauth_grant_ds(oauth_grants_oauth_application_id_column => oauth_application[oauth_applications_id_column],
            **resource_owner_params_from_jwt_claims(token_claims)).first
          if row && row[oauth_grants_type_column] == CibaSupport::GRANT_TYPE && row[:ciba_claims]
            projection = JSON.parse(row[:ciba_claims])
            target = "userinfo"
          end
        end
      end
      unless projection
        # offline_access requests refresh capability, not an account attribute.
        # Upstream otherwise dispatches unknown scopes to get_additional_param.
        scopes = scopes.reject { |scope| scope == "offline_access" } if @ciba_authentication || @ciba_userinfo_grant_id
        return super(claims, account, scopes, locales)
      end
      raise CibaSupport::ConfigurationError, "unsupported claims projection" unless projection["version"] == 1
      ciba_claim_names(projection.fetch(target)).each do |name|
        if name == "address"
          address = {}
          OIDC_SCOPES_MAP.fetch("address").each do |part|
            value = ciba_account_claim_value(account, part, :get_oidc_param)
            address[part] = value unless value.nil?
          end
          claims[:address] = address unless address.empty?
        else
          standard = OIDC_SCOPES_MAP.values.any? { |names| names.include?(name.to_sym) }
          value = ciba_account_claim_value(account, name.to_sym, standard ? :get_oidc_param : :get_additional_param)
          claims[name.to_sym] = value unless value.nil?
        end
      end
    end

    def ciba_account_claim_value(account, name, getter)
      callback = method(getter)
      callback.arity == 2 ? callback.call(account, name) : callback.call(account, name, nil)
    end

    def jwt_claims(grant)
      super.tap do |claims|
        if grant[oauth_grants_type_column] == CibaSupport::GRANT_TYPE
          claims[:"urn:rodauth:ciba:token_id"] = grant[oauth_grants_id_column]
          claims[:sub] = grant[ciba_token_subject_column] if grant[ciba_token_subject_column]
        end
      end
    end

    def _generate_access_token(params = {})
      return super unless @ciba_authentication && !oauth_jwt_access_tokens
      # Keep opaque CIBA credentials identifiable after their DB rows are cleaned
      # up, without changing unrelated OAuth token issuance or JWT formats.
      token = "ciba_at_#{oauth_unique_id_generator}"
      if oauth_grants_token_hash_column
        params[oauth_grants_token_hash_column] = generate_token_hash(token)
      else
        params[oauth_grants_token_column] = token
      end
      token
    end

    def authorization_token
      token = super
      return token unless token && request.path == userinfo_path
      return if token[:ciba_resource] || token["urn:rodauth:ciba:resource"]
      if token[oauth_grants_type_column] == CibaSupport::GRANT_TYPE
        application = oauth_application_ds(token[oauth_grants_oauth_application_id_column]).first
        return unless application
        @ciba_userinfo_grant_id = token[oauth_grants_id_column]
        return token.merge("scope" => token[oauth_grants_scopes_column], "sub" => token[oauth_grants_account_id_column].to_s,
          "client_id" => application[oauth_applications_client_id_column])
      end
      if token.key?("urn:rodauth:ciba:token_id")
        id = token["urn:rodauth:ciba:token_id"]
        return unless id.is_a?(Integer) && id.positive?
        row = valid_oauth_grant_ds(oauth_grants_id_column => id, oauth_grants_type_column => CibaSupport::GRANT_TYPE).first
        return unless row
        application = oauth_application_ds(row[oauth_grants_oauth_application_id_column]).first
        return unless application && application[oauth_applications_client_id_column] == token["client_id"]
        issued_subject = row[ciba_token_subject_column] || jwt_subject(row[oauth_grants_account_id_column], application)
        return unless issued_subject == token["sub"]
        @ciba_userinfo_grant_id = id
        return token.merge("sub" => row[oauth_grants_account_id_column].to_s)
      end
      token
    end

    def valid_oauth_grant_ds(*args)
      result = super
      if @ciba_userinfo_grant_id && request.path == userinfo_path
        result = result.where(oauth_grants_id_column => @ciba_userinfo_grant_id)
      end
      result
    end

    def ciba_process_signed_request!
      algorithm = oauth_application[oauth_applications_backchannel_authentication_request_signing_alg_column]
      unless request.params.key?("request")
        ciba_error("invalid_request") if algorithm
        return
      end
      ciba_error("invalid_request") unless algorithm && ciba_request_signing_algorithms.include?(algorithm)
      token = ciba_parameter("request", required: true, max: ciba_max_request_bytes)
      segments = token.split(".", -1)
      ciba_error("invalid_request") unless segments.size == 3 && segments.all? { |part| part.match?(/\A[A-Za-z0-9_-]+\z/) }
      header, claims = segments.first(2).map do |part|
        json = Base64.urlsafe_decode64(part).force_encoding(Encoding::UTF_8)
        ciba_error("invalid_request") unless json.valid_encoding?
        JSON.parse(json, max_nesting: 16, allow_duplicate_key: false)
      end
      ciba_error("invalid_request") unless header.is_a?(Hash) && claims.is_a?(Hash) &&
        header["alg"] == algorithm && !header.key?("crit") &&
        (!header.key?("kid") || header["kid"].is_a?(String))
      jwks = ciba_signed_request_jwks
      ciba_error("invalid_request") unless jwks.is_a?(Hash)
      keys = jwks[:keys] || jwks["keys"]
      ciba_error("invalid_request") unless keys.is_a?(Array)
      verified = keys.any? do |data|
        next false unless data.is_a?(Hash)
        data = data.transform_keys(&:to_s)
        next false unless %w[RSA EC OKP].include?(data["kty"]) &&
          (!data.key?("use") || data["use"] == "sig") &&
          (!data.key?("alg") || data["alg"] == algorithm) &&
          (!data.key?("key_ops") || (data["key_ops"].is_a?(Array) && data["key_ops"].include?("verify"))) &&
          (!header.key?("kid") || header["kid"] == data["kid"])
        begin
          if %w[Ed25519 EdDSA].include?(algorithm)
            key = ciba_ed25519_public_key(data)
            signature = Base64.urlsafe_decode64(segments.last)
            key && signature.bytesize == 64 && key.verify(nil, signature, segments.first(2).join("."))
          else
            next false if data["kty"] == "OKP"
            key = JWT::JWK.import(data).public_key
            JWT.decode(token, key, true, algorithms: [algorithm], verify_expiration: false, verify_not_before: false)
            true
          end
        rescue JWT::DecodeError, JWT::JWKError, ArgumentError, OpenSSL::PKey::PKeyError
          false
        end
      end
      ciba_error("invalid_request") unless verified
      client_id = oauth_application[oauth_applications_client_id_column]
      now = ciba_now
      leeway = oauth_jwt_iat_leeway
      audience = claims["aud"]
      ciba_error("invalid_request") unless claims["iss"] == client_id &&
        (audience.is_a?(String) || (audience.is_a?(Array) && audience.all? { |aud| aud.is_a?(String) })) &&
        Array(audience).include?(oauth_jwt_issuer) &&
        %w[exp iat nbf].all? { |name| claims[name].is_a?(Numeric) && claims[name].finite? } &&
        claims["exp"] > now - leeway && claims["nbf"] <= now + leeway &&
        claims["jti"].is_a?(String) &&
        (!claims.key?("client_id") || claims["client_id"] == client_id) &&
        !claims.key?("request") && !claims.key?("request_uri")
      # Authentication is already complete. Replace, never merge, protocol inputs.
      parameters = {}
      %w[scope login_hint login_hint_token id_token_hint binding_message acr_values nonce user_code client_notification_token request_context].each do |name|
        next unless claims.key?(name)
        ciba_error("invalid_request") unless claims[name].is_a?(String)
        parameters[name] = claims[name]
      end
      if claims.key?("requested_expiry")
        value = claims["requested_expiry"]
        ciba_error("invalid_request") unless value.is_a?(String) || value.is_a?(Integer)
        parameters["requested_expiry"] = value.to_s
      end
      if claims.key?("max_age")
        value = claims["max_age"]
        ciba_error("invalid_request") unless value.is_a?(String) || value.is_a?(Numeric)
        parameters["max_age"] = value.to_s
      end
      %w[claims authorization_details].each do |name|
        next unless claims.key?(name)
        value = claims[name]
        parameters[name] = value.is_a?(String) ? value : JSON.generate(value)
      end
      @ciba_form_resources = []
      if claims.key?("resource")
        value = claims["resource"]
        ciba_error("invalid_target") unless value.is_a?(String) ||
          (value.is_a?(Array) && !value.empty? && value.all? { |entry| entry.is_a?(String) })
        @ciba_form_resources = Array(value)
        parameters["resource"] = @ciba_form_resources.last
      end
      request.params.replace(parameters)
    rescue JSON::ParserError, ArgumentError, JWT::DecodeError
      ciba_error("invalid_request")
    end

    def ciba_decode_edwards_client_assertion(token, jwks)
      claims = ciba_decode_edwards_jwt(token, jwks, algorithms: Array(ciba_client_assertion_signing_algorithms))
      return unless claims
      if claims.key?("nbf")
        value = claims["nbf"]
        return unless value.is_a?(Numeric) && value.finite? && value <= Time.now.to_f
      end
      claims
    end

    def ciba_decode_edwards_jwt(token, jwks, algorithms:, allow_encoded_payload_crit: false)
      segments = token.split(".", -1)
      return unless segments.size == 3 && segments.all? { |part| part.match?(/\A[A-Za-z0-9_-]+\z/) }
      header, claims = segments.first(2).map do |part|
        JSON.parse(Base64.urlsafe_decode64(part), max_nesting: 16, allow_duplicate_key: false)
      end
      return unless header.is_a?(Hash) && claims.is_a?(Hash) &&
        algorithms.include?(header["alg"]) &&
        (!header.key?("crit") || (allow_encoded_payload_crit && header["crit"] == ["b64"] && header["b64"] == true)) &&
        (!header.key?("kid") || header["kid"].is_a?(String))
      keys = jwks.is_a?(Hash) ? (jwks[:keys] || jwks["keys"]) : jwks
      return unless keys.is_a?(Array)
      signature = Base64.urlsafe_decode64(segments.last)
      return unless signature.bytesize == 64
      verified = keys.any? do |data|
        next false unless data.is_a?(Hash)
        data = data.transform_keys(&:to_s)
        next false if (data.key?("alg") && data["alg"] != header["alg"]) ||
          (data.key?("use") && data["use"] != "sig") ||
          (data.key?("key_ops") && !(data["key_ops"].is_a?(Array) && data["key_ops"].include?("verify"))) ||
          (header.key?("kid") && data["kid"] != header["kid"])
        key = ciba_ed25519_public_key(data)
        key && key.verify(nil, signature, segments.first(2).join("."))
      end
      return unless verified
      claims
    rescue JSON::ParserError, ArgumentError, OpenSSL::PKey::PKeyError
      nil
    end

    # RFC 8410 SubjectPublicKeyInfo: Ed25519 OID, absent parameters, raw public key.
    # Keep this JWK adaptation local to CIBA; do not register global JWT algorithms.
    def ciba_ed25519_public_key(data)
      return unless data["kty"] == "OKP" && data["crv"] == "Ed25519"
      encoded = data["x"]
      return unless encoded.is_a?(String) && encoded.match?(/\A[A-Za-z0-9_-]{43}\z/)
      raw = Base64.urlsafe_decode64(encoded)
      return unless raw.bytesize == 32 && Base64.urlsafe_encode64(raw, padding: false) == encoded
      identifier = OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new("1.3.101.112")])
      spki = OpenSSL::ASN1::Sequence.new([identifier, OpenSSL::ASN1::BitString.new(raw)])
      OpenSSL::PKey.read(spki.to_der)
    end

    def ciba_signed_request_jwks
      @ciba_request_key_lookup = true
      oauth_application_jwks(oauth_application)
    rescue CibaSupport::HTTP::Error, IOError, SystemCallError, Timeout::Error, SocketError, OpenSSL::SSL::SSLError, Net::HTTPBadResponse
      raise CibaSupport::ProtocolError, "invalid_request"
    ensure
      @ciba_request_key_lookup = false
    end

    # This decoder is deliberately separate from access-token/client-assertion verification.
    # Expiration is ignored only for identity hints; no authorization is inherited.
    def ciba_id_token_hint_subject(token)
      algorithm = oauth_application[oauth_applications_id_token_signed_response_alg_column] || oauth_jwt_keys.keys.first
      ciba_error("invalid_request") unless %w[RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES384 ES512 HS256 HS384 HS512].include?(algorithm) || ciba_id_token_signing_keys.key?(algorithm)
      header = JWT::EncodedToken.new(token).header
      ciba_error("invalid_request") unless header["alg"] == algorithm &&
        header["b64"] != false &&
        (!header.key?("crit") || (header["crit"] == ["b64"] && header["b64"] == true)) &&
        (!header.key?("kid") || header["kid"].is_a?(String))
      keys = algorithm.start_with?("HS") ? ciba_hmac_id_token_secret(algorithm) : (oauth_jwt_public_keys[algorithm] || oauth_jwt_keys[algorithm])
      claims = nil
      if ciba_id_token_signing_keys.key?(algorithm)
        public_keys = Array(ciba_id_token_signing_keys.fetch(algorithm)).map { |key| ciba_edwards_public_jwk(key, algorithm) }
        claims = ciba_decode_edwards_jwt(token, public_keys, algorithms: [algorithm], allow_encoded_payload_crit: true)
      end
      Array(keys).each do |key|
        next if !algorithm.start_with?("HS") && header.key?("kid") && JWT::JWK.new(key).kid != header["kid"]
        begin
          claims, = JWT.decode(token, key, true, algorithms: [algorithm], verify_expiration: false,
            verify_iss: true, iss: oauth_jwt_issuer, verify_aud: true,
            aud: oauth_application[oauth_applications_client_id_column], verify_not_before: false, verify_iat: false,
            required_claims: %w[iss aud sub])
          break
        rescue JWT::DecodeError
          # A retained key without kid may be needed; never fetch keys from the hint.
        end
      end
      ciba_error("invalid_request") unless claims && claims["iss"] == oauth_jwt_issuer &&
        Array(claims["aud"]).include?(oauth_application[oauth_applications_client_id_column]) &&
        (!claims.key?("nbf") || (claims["nbf"].is_a?(Numeric) && claims["nbf"].finite? && claims["nbf"] <= ciba_now + oauth_jwt_iat_leeway)) &&
        claims["sub"].is_a?(String) &&
        (claims["aud"].is_a?(String) || (claims["aud"].is_a?(Array) && claims["aud"].all? { |aud| aud.is_a?(String) })) &&
        (!claims.key?("jti") || claims["jti"].is_a?(String)) &&
        (!claims.key?("iat") || (claims["iat"].is_a?(Numeric) && claims["iat"].finite? &&
          (claims.key?("exp") || claims["iat"] <= ciba_now + oauth_jwt_iat_leeway)))
      if ciba_id_token_hint_max_age && (!claims["iat"].is_a?(Numeric) || ciba_now - claims["iat"] > ciba_id_token_hint_max_age)
        ciba_error("invalid_request")
      end
      claims["sub"].freeze
    rescue JWT::DecodeError
      ciba_error("invalid_request")
    end

    def ciba_requested_max_age
      value = request.params["max_age"]
      if value.nil? || value == ""
        return oauth_application[oauth_applications_default_max_age_column]
      end
      ciba_error("invalid_request") unless value.is_a?(String) && value.valid_encoding? && value.bytesize <= 1024
      number = value.gsub(/\A[\t-\r \u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000\uFEFF]+|[\t-\r \u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000\uFEFF]+\z/, "")
      numeric = case number
                when "" then 0.0
                when /\A0[xX][0-9a-fA-F]+\z/, /\A0[bB][01]+\z/, /\A0[oO][0-7]+\z/
                  Integer(number).to_f
                when /\A[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\z/
                  Float(number.sub(/\.(?=[eE]|\z)/, ".0"))
                end
      unless numeric && numeric.finite? && numeric == numeric.to_i && numeric.between?(0, 9_007_199_254_740_991)
        ciba_error("invalid_request")
      end
      numeric.to_i
    rescue ArgumentError
      ciba_error("invalid_request")
    end

    def validate_ciba_request!
      %w[request request_uri].each do |name|
        ciba_error("invalid_request") if request.params.key?(name)
      end
      ciba_error("invalid_request") if request.params.key?("user_code") && !ciba_user_code_enabled
      hint_names = %w[login_hint login_hint_token id_token_hint].select { |name| request.params.key?(name) }
      ciba_error("invalid_request") unless hint_names.size == 1
      hint_name = hint_names.first
      ciba_error("invalid_request") if hint_name == "login_hint_token" && !ciba_login_hint_token_enabled
      ciba_error("invalid_request") if hint_name == "id_token_hint" && !ciba_id_token_hint_enabled
      hint = ciba_parameter(hint_name, required: true, max: hint_name == "login_hint" ? 1024 : 8192)
      ciba_error("invalid_request") if request.params["scope"].nil?
      scope = ciba_parameter("scope", required: true, max: 4096, error: "invalid_scope")
      ciba_error("invalid_scope") unless scope.match?(/\A[\x21\x23-\x5B\x5D-\x7E]+(?: [\x21\x23-\x5B\x5D-\x7E]+)*\z/)
      scopes = scope.split.uniq
      scopes -= ["offline_access"] unless ciba_refresh_tokens_enabled
      allowed = oauth_application_scopes & oauth_application[oauth_applications_scopes_column].to_s.split
      ciba_error("invalid_scope") unless scopes.include?("openid") && (scopes - allowed).empty?
      binding = request.params["binding_message"]
      unless binding.nil? || (binding.is_a?(String) && binding.valid_encoding?)
        ciba_error("invalid_binding_message")
      end
      validate_ciba_binding_message(binding)
      acr = ciba_parameter("acr_values") unless request.params["acr_values"] == ""
      if !acr && (defaults = oauth_application[oauth_applications_default_acr_values_column])
        acr = JSON.parse(defaults).join(" ")
        acr = nil if acr.empty?
      end
      expiry = ciba_parameter("requested_expiry", max: 20)
      ciba_error("invalid_request") if expiry && !expiry.match?(/\A[0-9]+\z/)
      ciba_error("invalid_request") if expiry && expiry.to_i.zero?
      lifetime = expiry ? [expiry.to_i, ciba_max_request_lifetime].min : ciba_request_lifetime
      result = {hint_name.to_sym => hint, scopes: scopes.join(oauth_scope_separator), binding_message: binding,
        acr_values: acr, nonce: ciba_parameter("nonce"), lifetime: lifetime, max_age: ciba_requested_max_age}
      result[:request_context] = ciba_parameter("request_context", max: 8192) if ciba_request_context_enabled
      result[:user_code] = ciba_parameter("user_code") if ciba_user_code_enabled
      result[:requested_claims] = ciba_parse_requested_claims if ciba_claims_enabled
      authentication_claims = []
      if oauth_application[oauth_applications_require_auth_time_column] ||
          !result[:max_age].nil?
        authentication_claims << "auth_time"
      end
      authentication_claims << "acr" if acr
      if result[:requested_claims]
        authentication_claims |= JSON.parse(result[:requested_claims]).fetch("id_token", {}).keys & %w[auth_time acr amr]
      end
      result[:authentication_claims] = JSON.generate(authentication_claims)
      result[:requested_resources] = ciba_requested_resources if ciba_resources_enabled
      if ciba_authorization_details_enabled
        details = ciba_checked_authorization_details(request.params.fetch("authorization_details", "[]"), oauth_application)
        if !details.empty? && JSON.parse(result[:requested_resources]).empty?
          raise CibaSupport::ProtocolError, "invalid_target"
        end
        result[:requested_authorization_details] = JSON.generate(details)
      end
      result
    end

    def validate_token_params
      super
      return unless param("grant_type") == CibaSupport::GRANT_TYPE
      validate_ciba_transport!
      ciba_error("unauthorized_client") unless ciba_client_eligible?(oauth_application)
      ciba_parameter("auth_req_id", required: true)
    end

    def create_token(grant_type)
      return ciba_refresh_access_token if ciba_refresh_request?
      return super unless grant_type == CibaSupport::GRANT_TYPE
      row = ciba_lock_source_after_grant(ciba_ds.where(ciba_values(
        auth_req_id_digest: Digest::SHA256.hexdigest(param("auth_req_id")),
        oauth_application_id: oauth_application[oauth_applications_id_column])), request_columns: true)
      ciba_error("invalid_grant") unless row
      ciba_error("expired_token") if row[:expires_at] <= ciba_now
      if row[:status] == "consumed"
        revoke_ciba_grant(row[:grant_id]) if row[:grant_id]
        ciba_error("invalid_grant")
      end
      if row[:status] == "denied"
        ciba_ds.where(ciba_values(id: row[:id])).update(ciba_values(status: "consumed", consumed_at: ciba_now))
        code = row[:completion_error] || "access_denied"
        status = {"invalid_token" => 401, "insufficient_scope" => 403}.fetch(code, 400)
        ciba_error(code, status)
      end
      ciba_guard(row[:id]) do
        ciba_claim!(row)
        if row[:status] == "pending"
          too_fast = row[:last_polled_at] && ciba_now < row[:last_polled_at] + row[:interval]
          interval = row[:interval] + (too_fast ? 5 : 0)
          ciba_ds.where(ciba_values(id: row[:id])).update(ciba_values(last_polled_at: ciba_now, interval: interval))
          ciba_error(too_fast ? "slow_down" : "authorization_pending")
        end
        application = oauth_application_ds(row[:oauth_application_id]).first
        begin
          authorized_scopes = ciba_authorized_scopes!(row, row[:grant_id])
        rescue CibaSupport::Ineligible, CibaSupport::IdentityMismatch, ArgumentError
          raise CibaSupport::ProtocolError, "invalid_grant"
        end
        unless row[:status] == "approved" && ciba_account_eligible?(row[:account_id]) && ciba_client_eligible?(application, authorized_scopes)
          raise CibaSupport::ProtocolError, "invalid_grant"
        end
        @oauth_application = application
        @ciba_current_request = ciba_snapshot(row)
        before_ciba_issue
        raise CibaSupport::Expired, "request expired" if row[:expires_at] <= ciba_now
        begin
          authorized_scopes = ciba_authorized_scopes!(row, row[:grant_id])
        rescue CibaSupport::Ineligible, CibaSupport::IdentityMismatch, ArgumentError
          raise CibaSupport::ProtocolError, "invalid_grant"
        end
        ciba_validate_enabled_capabilities!(row)
        updates = {status: "consumed", consumed_at: ciba_now}
        ciba_ds.where(ciba_values(id: row[:id])).update(ciba_values(updates))
        grant = ciba_generate_access_token(row, authorized_scopes)
        if ciba_refresh_tokens_enabled && row[:scopes].split.include?("offline_access") &&
           application[oauth_applications_grant_types_column].to_s.split.include?("refresh_token")
          grant[oauth_grants_refresh_token_column] = ciba_save_refresh_token(row)
        end
        row.merge!(updates)
        @ciba_current_request = ciba_snapshot(row)
        after_ciba_issue
        ciba_emit(row, "token_issued", "approved", "consumed")
        grant
      end
    ensure
      if grant_type == CibaSupport::GRANT_TYPE
        @ciba_authentication = @ciba_current_request = nil
      end
    end

    # A namespace lets disabled installations reject issued CIBA refresh tokens
    # without querying optional storage or changing ordinary OAuth refresh flows.
    def ciba_refresh_request?
      request.params["grant_type"] == "refresh_token" &&
        request.params["refresh_token"].is_a?(String) && request.params["refresh_token"].start_with?("ciba_rt_")
    end

    def ciba_token_revocation_request?
      return false unless features.include?(:oauth_token_revocation) && request.path == revoke_path
      token = request.params["token"]
      return false unless token.is_a?(String)
      return true if token.start_with?("ciba_rt_")
      if token.bytesize <= 8192 && token.count(".") == 2
        if @ciba_revocation_jwt_candidate.nil?
          begin
            unverified, = JWT.decode(token, nil, false)
            @ciba_revocation_jwt_candidate = unverified.is_a?(Hash) &&
              (unverified.key?("urn:rodauth:ciba:token_id") || unverified.key?("urn:rodauth:ciba:resource"))
          rescue JWT::DecodeError, ArgumentError
            @ciba_revocation_jwt_candidate = false
          end
        end
        # Unverified data selects only client authentication and a rejecting
        # validation path. It never identifies a DB row or grants authority.
        return true if @ciba_revocation_jwt_candidate
      end
      namespaced = token.start_with?("ciba_at_")
      return namespaced || !!@ciba_revocation_access_id if defined?(@ciba_revocation_access_id)
      return true if namespaced && token.bytesize > 1024 # validation rejects oversized values
      return false if token.bytesize > 1024
      column = oauth_grants_token_hash_column || oauth_grants_token_column
      value = oauth_grants_token_hash_column ? generate_token_hash(token) : token
      # Only saved CIBA opaque tokens select this behavior. Keep revoked rows
      # recognizable for idempotent retries; authorization happens under lock.
      @ciba_revocation_access_id = db[oauth_grants_table]
        .where(column => value, oauth_grants_type_column => CibaSupport::GRANT_TYPE)
        .exclude(oauth_grants_ciba_grant_id_column => nil).get(oauth_grants_id_column)
      namespaced || !!@ciba_revocation_access_id
    end

    # Provenance only: expired signed CIBA JWTs still cannot be revoked through
    # this endpoint. This verifier is never used to authorize token consumption.
    def ciba_signed_access_token?(token)
      header = JWT::EncodedToken.new(token).header
      algorithm = header["alg"]
      return false unless header["typ"] == "at+jwt" && !header.key?("crit") &&
        %w[RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES384 ES512 HS256 HS384 HS512].include?(algorithm)
      keys = algorithm.start_with?("HS") ? oauth_jwt_keys[algorithm] : (oauth_jwt_public_keys[algorithm] || oauth_jwt_keys[algorithm])
      Array(keys).any? do |key|
        next false if header.key?("kid") && JWT::JWK.new(key).kid != header["kid"]
        begin
          claims, = JWT.decode(token, key, true, algorithms: [algorithm],
            verify_iss: true, iss: oauth_jwt_issuer, required_claims: ["iss"],
            verify_expiration: false, verify_not_before: false, verify_iat: false)
          claims.key?("urn:rodauth:ciba:token_id") || claims.key?("urn:rodauth:ciba:resource")
        rescue JWT::DecodeError
          false
        end
      end
    rescue JWT::DecodeError, ArgumentError
      false
    end

    def ciba_revoke_access_artifacts
      ds = valid_oauth_grant_ds(oauth_grants_id_column => @ciba_revocation_access_id)
        .where(oauth_grants_type_column => CibaSupport::GRANT_TYPE)
      row = ciba_lock_source_after_grant(ds, grant_key: oauth_grants_ciba_grant_id_column)
      return unless row
      ciba_error("invalid_request") unless row[oauth_grants_oauth_application_id_column] == oauth_application[oauth_applications_id_column]
      grant_id = row[oauth_grants_ciba_grant_id_column]
      # The grant lock excludes completion/issuance using this consent. Retain
      # the consent itself, but remove sources that could issue from old approval.
      ciba_ds.where(ciba_values(grant_id: grant_id)).delete
      if db.table_exists?(ciba_refresh_tokens_table)
        db[ciba_refresh_tokens_table].where(grant_id: grant_id).delete
      end
      db[oauth_grants_table].where(oauth_grants_ciba_grant_id_column => grant_id)
        .update(oauth_grants_revoked_at_column => Sequel::CURRENT_TIMESTAMP)
    end

    def ciba_save_refresh_token(source, rotations: 0, created_at: ciba_now)
      token = "ciba_rt_#{SecureRandom.urlsafe_base64(32)}"
      keys = %i[grant_id account_id oauth_application_id scopes auth_time acr amr nonce authentication_claims
                requested_claims requested_resources requested_authorization_details]
      row = source.select { |key, _| keys.include?(key) }
      row.merge!(token_digest: Digest::SHA256.hexdigest(token), created_at: created_at,
        issued_at: ciba_now, expires_at: ciba_now + ciba_refresh_token_lifetime, rotations: rotations)
      db[ciba_refresh_tokens_table].insert(row)
      token
    end

    def ciba_refresh_access_token
      ciba_error("invalid_grant") unless ciba_refresh_tokens_enabled
      unless oauth_application[oauth_applications_grant_types_column].to_s.split.include?("refresh_token")
        ciba_error("unauthorized_client")
      end
      token = ciba_parameter("refresh_token", required: true, max: 1024)
      ds = db[ciba_refresh_tokens_table].where(token_digest: Digest::SHA256.hexdigest(token),
        oauth_application_id: oauth_application[oauth_applications_id_column])
      row = ciba_lock_source_after_grant(ds)
      ciba_error("invalid_grant") unless row && row[:expires_at] > ciba_now
      ciba_guard([:refresh, row[:id]]) { ciba_refresh_source(row, ds, token) }
    ensure
      @ciba_authentication = @ciba_current_refresh = nil
    end

    def ciba_validate_refresh_source!(row)
      raise CibaSupport::ProtocolError, "invalid_grant" unless row && row[:expires_at] > ciba_now && ciba_refresh_tokens_enabled
      application = oauth_application_ds(row[:oauth_application_id]).first
      unless application && application[oauth_applications_grant_types_column].to_s.split.include?("refresh_token")
        raise CibaSupport::ProtocolError, "invalid_grant"
      end
      begin
        scopes = ciba_authorized_scopes!(row, row[:grant_id])
      rescue CibaSupport::Ineligible, CibaSupport::IdentityMismatch, ArgumentError
        raise CibaSupport::ProtocolError, "invalid_grant"
      end
      unless ciba_account_eligible?(row[:account_id]) && ciba_client_eligible?(application, scopes)
        raise CibaSupport::ProtocolError, "invalid_grant"
      end
      @oauth_application = application
      ciba_validate_enabled_capabilities!(row)
      scopes
    end

    def ciba_refresh_source(row, ds, token)
      ciba_validate_refresh_source!(row)
      if row[:consumed_at]
        revoke_ciba_grant(row[:grant_id])
        ciba_error("invalid_grant")
      end
      requested_scope = ciba_parameter("scope", max: 4096, error: "invalid_scope")
      @ciba_current_refresh = ciba_snapshot(row)
      before_ciba_refresh
      row = (db.database_type == :sqlite ? ds : ds.for_update).first
      scopes = ciba_validate_refresh_source!(row)
      raise CibaSupport::ProtocolError, "invalid_grant" if row[:consumed_at]
      narrowed = row
      if requested_scope
        unless requested_scope.match?(/\A[\x21\x23-\x5B\x5D-\x7E]+(?: [\x21\x23-\x5B\x5D-\x7E]+)*\z/) &&
               (requested_scope.split - row[:scopes].split).empty?
          raise CibaSupport::ProtocolError, "invalid_scope"
        end
        narrowed = row.merge(scopes: requested_scope.split.uniq.join(oauth_scope_separator))
        scopes &= requested_scope.split
      end
      changed = ds.where(lock_version: row[:lock_version], consumed_at: nil)
        .update(lock_version: row[:lock_version] + 1)
      raise CibaSupport::Conflict, "concurrent refresh" unless changed == 1
      # Confidential clients match the reference default: rotate after 70% TTL,
      # stopping sliding renewal after one year from initial issuance.
      rotate = ciba_now - row[:created_at] < 31_557_600 &&
        (ciba_now - row[:issued_at]) * 10 >= (row[:expires_at] - row[:issued_at]) * 7
      if rotate
        ds.update(consumed_at: ciba_now)
        token = ciba_save_refresh_token(row, rotations: row[:rotations] + 1, created_at: row[:created_at])
      end
      grant = ciba_generate_access_token(narrowed, scopes)
      grant[oauth_grants_refresh_token_column] = token
      @ciba_current_refresh = ciba_snapshot(ds.first)
      after_ciba_refresh
      event = {version: 1, event_id: SecureRandom.uuid.freeze, type: "token_refreshed".freeze,
        refresh_token_id: row[:id], grant_id: row[:grant_id], occurred_at: ciba_now,
        account_id: row[:account_id], oauth_application_id: row[:oauth_application_id],
        rotated: rotate}.freeze
      db.after_commit(savepoint: true) { ciba_observe { observe_ciba_event(event) } }
      grant
    end

    def ciba_generate_access_token(row, authorized_scopes)
      @ciba_authentication = row
      attributes = {oauth_grants_account_id_column => row[:account_id],
        oauth_grants_oauth_application_id_column => row[:oauth_application_id],
        oauth_grants_scopes_column => authorized_scopes.join(oauth_scope_separator),
        oauth_grants_ciba_grant_id_column => row[:grant_id], oauth_grants_type_column => CibaSupport::GRANT_TYPE}
      attributes[ciba_token_subject_column] = jwt_subject(row[:account_id]) if ciba_pairwise_enabled
      attributes[:ciba_claims] = ciba_compile_claims(row, authorized_scopes) if ciba_claims_enabled
      resource_attributes = ciba_token_resource(row)
      attributes.merge!(resource_attributes) if resource_attributes
      details = ciba_compile_authorization_details(row, resource_attributes)
      attributes[:ciba_authorization_details] = details if details
      grant = generate_token(attributes, false)
      if authorized_scopes.include?("openid")
        id_grant = grant.merge(oauth_grants_scopes_column => authorized_scopes.join(oauth_scope_separator))
        generate_id_token(id_grant)
        grant[:id_token] = id_grant[:id_token]
        raise "ID Token generation did not complete" unless grant[:id_token]
      end
      grant
    end

    def json_access_token_payload(grant)
      payload = super
      # RFC 6749 section 5.1 requires scope when the granted scope differs
      # from the request (for example, ignoring unsupported offline_access).
      if grant[oauth_grants_type_column] == CibaSupport::GRANT_TYPE
        payload["scope"] = grant[oauth_grants_scopes_column]
        payload["authorization_details"] = JSON.parse(grant[:ciba_authorization_details]) if grant[:ciba_authorization_details]
      end
      payload
    end

    def ciba_validate_enabled_capabilities!(row)
      consent = ciba_locked_grant(row[:grant_id])
      # A legacy request may have been bound to a new-format consent after
      # migration. Neither side's restrictions may disappear on deactivation.
      [[ciba_claims_enabled, :requested_claims, :claims],
       [ciba_resources_enabled, :requested_resources, :resources],
       [ciba_authorization_details_enabled, :requested_authorization_details, :authorization_details]].each do |enabled, request_key, consent_key|
        if !enabled && (row[request_key] || consent[consent_key])
          raise CibaSupport::ProtocolError, "invalid_grant"
        end
      end
    end

    def id_token_claims(grant, algorithm)
      return super unless @ciba_authentication
      # Upstream's id_token_claims reads a browser-session login timestamp.
      # CIBA uses the application's verified authentication result instead.
      # generate_id_token still supplies upstream scope claims and signing.
      claims = jwt_claims(grant)
      claims.delete(:"urn:rodauth:ciba:token_id")
      claims.delete(:"urn:rodauth:ciba:resource")
      claims.delete(:authorization_details)
      # DPoP/mTLS cnf describes access-token sender constraints, not the ID Token.
      claims.delete(:cnf)
      # ID Token audience is the RP, even when access-token resource audiences differ.
      claims[:aud] = oauth_application[oauth_applications_client_id_column]
      row = @ciba_authentication
      claims[:nonce] = row[:nonce] if row[:nonce]
      selected = row[:authentication_claims] ? JSON.parse(row[:authentication_claims]) : %w[auth_time acr amr]
      grant[oauth_grants_scopes_column].to_s.split(oauth_scope_separator).each do |scope|
        selected |= Array(ciba_authentication_claims_by_scope[scope]) & %w[auth_time acr amr]
      end
      claims[:auth_time] = row[:auth_time] if row[:auth_time] && selected.include?("auth_time")
      claims[:acr] = row[:acr] if row[:acr] && selected.include?("acr")
      claims[:amr] = JSON.parse(row[:amr]) if row[:amr] && selected.include?("amr")
      claims[:at_hash] = id_token_hash(grant[oauth_grants_token_column], algorithm)
      claims
    end

    def ciba_emit(row, type, from, to)
      event = {version: 1, event_id: SecureRandom.uuid.freeze, request_id: row[:id], type: type.freeze,
        occurred_at: ciba_now, account_id: row[:account_id], oauth_application_id: row[:oauth_application_id],
        from: from&.freeze, to: to.freeze}
      event[:error] = row[:completion_error].dup.freeze if type == "failed"
      event.freeze
      db.after_commit(savepoint: true) { ciba_observe { observe_ciba_event(event) } }
    end

    def ciba_observe
      yield
    rescue StandardError => error
      begin
        report_ciba_observer_error(error)
      rescue StandardError
        # An unavailable reporter cannot change the committed result.
      end
    end

    def ciba_sqlite_busy_error?(error)
      db.database_type == :sqlite && error.is_a?(Sequel::DatabaseError) &&
        error.wrapped_exception.class.name == "SQLite3::BusyException"
    end

    def ciba_http
      # Upstream authentication can halt before ciba_error is reached.
      response["Cache-Control"] = "no-store"
      response["Pragma"] = "no-cache"
      yield
    rescue Rack::QueryParser::ParameterTypeError, Rack::QueryParser::InvalidParameterError, Rack::QueryParser::QueryLimitError
      @ciba_invalid_parameters = true
      ciba_error("invalid_request")
    rescue CibaSupport::Expired
      ciba_error("expired_token")
    rescue CibaSupport::ProtocolError => error
      ciba_error(error.code)
    rescue Sequel::DatabaseLockTimeout, Sequel::SerializationFailure
      response["Retry-After"] = ciba_poll_interval.to_s
      ciba_error("temporarily_unavailable", 503)
    rescue StandardError => error
      if ciba_sqlite_busy_error?(error)
        response["Retry-After"] = ciba_poll_interval.to_s
        ciba_error("temporarily_unavailable", 503)
      end
      begin
        report_ciba_processing_error(error)
      rescue StandardError
        # Do not leak exception messages (which can contain credentials).
      end
      ciba_error("server_error", 500)
    end

    def ciba_error(code, status = 400)
      response["Cache-Control"] = "no-store"
      response["Pragma"] = "no-cache"
      throw_json_response_error(status, code)
    end

    def ciba_transaction(&block)
      opts = {savepoint: true}
      opts[:mode] = :immediate if db.database_type == :sqlite
      db.transaction(opts, &block)
    end

    def transaction(opts = {}, &block)
      return super unless ciba_token_revocation_request? ||
        (request.path == token_path && (param("grant_type") == CibaSupport::GRANT_TYPE || ciba_refresh_request?))
      opts = opts.merge(savepoint: true)
      opts[:mode] = :immediate if db.database_type == :sqlite
      ciba_http { super(opts, &block) }
    end
  end
end
