# frozen_string_literal: true

module Rodauth
  module CibaSupport
    module Mtls
      private

      def oauth_server_metadata_body(*)
        super.tap do |metadata|
          metadata[:tls_client_certificate_bound_access_tokens] = true if features.include?(:oauth_tls_client_auth)
        end
      end

      def ciba_mtls_request?
        features.include?(:oauth_tls_client_auth) && (ciba_protocol_request? || @ciba_mtls_userinfo ||
          (features.include?(:oauth_token_introspection) && request.path == introspect_path &&
            ciba_dpop_userinfo_candidate?(param("token"))))
      end

      def client_certificate
        return super unless ciba_mtls_request?
        return if @ciba_mtls_storing
        return @ciba_tls_certificate if defined?(@ciba_tls_certificate)
        value = ciba_tls_client_certificate
        @ciba_tls_certificate = case value
                                when nil then nil
                                when OpenSSL::X509::Certificate then value
                                when String
                                  authorization_required if value.bytesize > 16_384
                                  OpenSSL::X509::Certificate.new(value)
                                else
                                  authorization_required
                                end
      rescue OpenSSL::X509::CertificateError, ArgumentError
        authorization_required
      end

      def ciba_certificate_thumbprint(certificate)
        Base64.urlsafe_encode64(Digest::SHA256.digest(certificate.to_der), padding: false)
      end

      def require_oauth_application
        return super unless ciba_mtls_request?
        client_id = param_or_nil("client_id")
        application = client_id && db[oauth_applications_table].where(oauth_applications_client_id_column => client_id).first
        methods = application ? application[oauth_applications_token_endpoint_auth_method_column].to_s.split : []
        return super if (methods & %w[tls_client_auth self_signed_tls_client_auth]).empty?
        # Like the reference registration contract, TLS clients select one
        # authentication method. Never fall back to upstream header trust.
        authorization_required unless methods.length == 1
        method = methods.first
        authorization_required if request.env["HTTP_AUTHORIZATION"] || request.params.key?("client_secret") || request.params.key?("client_assertion")
        certificate = client_certificate
        authorization_required unless certificate
        if method == "tls_client_auth"
          authorization_required unless ciba_tls_client_certificate_authorized? == true
          properties = %i[subject_dn san_dns san_uri san_ip san_email].filter_map do |suffix|
            name = :"tls_client_auth_#{suffix}"
            value = application[send(:"oauth_applications_#{name}_column")]
            [name, value] if value
          end
          authorization_required unless properties.length == 1 &&
            ciba_tls_client_certificate_subject_matches?(*properties.first) == true
        else
          authorization_required unless ciba_registered_certificate?(application, certificate)
        end
        @oauth_application = application
      end

      def ciba_registered_certificate?(application, certificate)
        previous = @ciba_tls_key_lookup
        @ciba_tls_key_lookup = true
        jwks = oauth_application_jwks(application)
        keys = jwks.is_a?(Hash) ? (jwks[:keys] || jwks["keys"]) : jwks
        unless keys.is_a?(Array) && keys.all? { |key| key.is_a?(Hash) }
          raise ProtocolError, "invalid_client_metadata"
        end
        expected = ciba_certificate_thumbprint(certificate)
        keys.is_a?(Array) && keys.any? do |jwk|
          next false unless jwk.is_a?(Hash)
          chain = jwk[:x5c] || jwk["x5c"]
          next false unless chain.is_a?(Array) && chain.first.is_a?(String) && chain.first.bytesize <= 24_000
          registered = OpenSSL::X509::Certificate.new(Base64.strict_decode64(chain.first))
          OpenSSL.fixed_length_secure_compare(ciba_certificate_thumbprint(registered), expected)
        end
      rescue CibaSupport::HTTP::Error, JSON::ParserError, IOError, SystemCallError, Timeout::Error,
             SocketError, OpenSSL::SSL::SSLError, Net::HTTPBadResponse
        raise ProtocolError, "invalid_client_metadata"
      rescue OpenSSL::X509::CertificateError, ArgumentError
        false
      ensure
        @ciba_tls_key_lookup = previous
      end

      def ciba_certificate_binding_required?
        # Capability is advertised separately. CIBA binding is a client policy;
        # leave upstream's global policy in effect only for its other grants.
        oauth_application[oauth_applications_tls_client_certificate_bound_access_tokens_column]
      end

      def generate_token(grant_params = {}, should_generate_refresh_token = true)
        if ciba_mtls_request? && grant_params[oauth_grants_type_column] == GRANT_TYPE && ciba_certificate_binding_required?
          # Validate before upstream's inner uniqueness transaction can convert a
          # protocol exception into a response and commit the outer consumption.
          raise ProtocolError, "invalid_grant" unless client_certificate
          raise ProtocolError, "invalid_request" if @dpop_claims
        end
        super
      end

      def store_token(grant_params, update_params = {})
        return super unless ciba_mtls_request? && grant_params[oauth_grants_type_column] == GRANT_TYPE
        if ciba_certificate_binding_required?
          update_params = update_params.merge(oauth_grants_certificate_thumbprint_column => ciba_certificate_thumbprint(client_certificate))
        end
        # Upstream would replace the certificate digest with a public-key JWK
        # thumbprint. Supply the completed binding and delegate token persistence.
        @ciba_mtls_storing = true
        super(grant_params, update_params)
      ensure
        @ciba_mtls_storing = false
      end

      def authorization_token
        token = super
        return token unless token && features.include?(:oauth_tls_client_auth) && request.path == userinfo_path && @ciba_userinfo_grant_id
        thumbprint = db[oauth_grants_table].where(oauth_grants_id_column => @ciba_userinfo_grant_id,
          oauth_grants_type_column => GRANT_TYPE).get(oauth_grants_certificate_thumbprint_column)
        return token unless thumbprint
        @ciba_mtls_userinfo = true
        certificate = client_certificate
        unless certificate && thumbprint == ciba_certificate_thumbprint(certificate)
          response["WWW-Authenticate"] = 'Bearer error="invalid_token"'
          ciba_error("invalid_token", 401)
        end
        token
      ensure
        @ciba_mtls_userinfo = false
      end

      def json_token_introspect_payload(grant)
        if features.include?(:oauth_tls_client_auth) && grant && grant.key?("urn:rodauth:ciba:token_id")
          # Introspection receives verified JWT claims, not the persisted grant.
          # Resolve its live issuance before reporting certificate binding.
          id = grant["urn:rodauth:ciba:token_id"]
          return {active: false} unless id.is_a?(Integer) && id.positive?
          row = db[oauth_grants_table].where(oauth_grants_id_column => id,
            oauth_grants_type_column => GRANT_TYPE, oauth_grants_revoked_at_column => nil)
            .where(Sequel.expr(Sequel[oauth_grants_expires_in_column]) >= Sequel::CURRENT_TIMESTAMP).first
          return {active: false} unless row
          application = oauth_application_ds(row[oauth_grants_oauth_application_id_column]).first
          return {active: false} unless application && application[oauth_applications_client_id_column] == grant["client_id"]
          subject = row[ciba_token_subject_column] || jwt_subject(row[oauth_grants_account_id_column], application)
          return {active: false} unless subject == grant["sub"]
          thumbprint = row[oauth_grants_certificate_thumbprint_column]
          return {active: false} if thumbprint && grant.dig("cnf", "x5t#S256") != thumbprint
          # The upstream username resolver otherwise treats a pairwise sub as
          # a local account key. Preserve the public sub and supply its verified
          # internal identity only for resolving the upstream response fields.
          return super(grant.merge(oauth_grants_account_id_column => row[oauth_grants_account_id_column])).tap do |payload|
            (payload[:cnf] ||= {})["x5t#S256"] = thumbprint if payload[:active] && thumbprint
          end
        end
        super.tap do |payload|
          if features.include?(:oauth_tls_client_auth) && payload[:active] && grant &&
              grant[oauth_grants_type_column] == GRANT_TYPE &&
              (thumbprint = grant[oauth_grants_certificate_thumbprint_column])
            (payload[:cnf] ||= {})["x5t#S256"] = thumbprint
          end
        end
      end
    end
  end
end
