# frozen_string_literal: true

module Rodauth
  module CibaSupport
    module Registration
      TLS_SUBJECT_METADATA = %w[tls_client_auth_subject_dn tls_client_auth_san_dns
        tls_client_auth_san_uri tls_client_auth_san_ip tls_client_auth_san_email].freeze
      # Protocol metadata, never arbitrary database column names. Applications
      # with proprietary metadata should validate it in their own registration
      # policy rather than expose internal storage through upstream's fallback.
      METADATA = %w[
        redirect_uris grant_types response_types token_endpoint_auth_method
        token_endpoint_auth_signing_alg client_uri logo_uri tos_uri policy_uri
        jwks_uri jwks scope contacts client_name subject_type sector_identifier_uri
        id_token_signed_response_alg id_token_encrypted_response_alg id_token_encrypted_response_enc
        userinfo_signed_response_alg userinfo_encrypted_response_alg userinfo_encrypted_response_enc
        request_object_signing_alg request_object_encryption_alg request_object_encryption_enc
        default_max_age require_auth_time default_acr_values initiate_login_uri request_uris
        dpop_bound_access_tokens
        tls_client_certificate_bound_access_tokens tls_client_auth_subject_dn
        tls_client_auth_san_dns tls_client_auth_san_uri tls_client_auth_san_ip tls_client_auth_san_email
        post_logout_redirect_uris authorization_details_types backchannel_token_delivery_mode
        backchannel_client_notification_endpoint backchannel_user_code_parameter
        backchannel_authentication_request_signing_alg
      ].freeze

      def oauth_client_registration_required_params
        return super unless ciba_dynamic_client_registration_enabled && ciba_registration_grant?(request.params)
        required = super - ["client_name"]
        request.params["response_types"] == [] ? required - ["redirect_uris"] : required
      end

      # Upstream loads/authenticates the registration resource in this route.
      # Hold its row through validation and update so merged metadata cannot be
      # invalidated by another registration update between those operations.
      def load_registration_client_uri_routes
        prefix = "/#{registration_client_uri_route}/"
        path = request.remaining_path
        return super unless %w[GET PUT DELETE].include?(request.request_method) && path.start_with?(prefix)
        segment = path.delete_prefix(prefix)
        return super if segment.empty? || segment.include?("/")
        client_id = Rack::Utils.unescape_path(segment)
        @ciba_registration_route = true
        if ciba_issued_management_bearer?
          token = request.env["HTTP_AUTHORIZATION"].to_s[/\A *Bearer (ciba_reg_[A-Za-z0-9_-]{43})\z/, 1]
          authorization_required unless token && db[oauth_applications_table].columns.include?(ciba_registration_token_digest_column)
          return ciba_transaction do
            # Lock the credential's owner, not the requested target. Opposite
            # cross-client requests never acquire each other's application row.
            ds = db[oauth_applications_table].where(ciba_registration_token_digest_column => Digest::SHA256.hexdigest(token))
            delete_owner = ciba_lock_registration_delete_grants(ds, token, client_id)
            ds = ds.for_update unless db.database_type == :sqlite
            source = ds.first
            authorization_required unless source && source[oauth_applications_registration_access_token_column] &&
              password_hash_match?(source[oauth_applications_registration_access_token_column], token)
            if source[oauth_applications_client_id_column] != client_id
              ds.update(ciba_registration_token_digest_column => nil, oauth_applications_registration_access_token_column => nil)
              # Rodauth halts with a throw, so Sequel commits this deliberate
              # credential invalidation while preserving the unrelated target.
              authorization_required
            end
            if delete_owner && delete_owner != source[oauth_applications_id_column]
              raise Sequel::SerializationFailure, "Registration credential owner changed while locking"
            end
            @ciba_registration_application = source
            ciba_delete_registered_client(source) if request.request_method == "DELETE"
            super
          end
        end
        return super unless %w[PUT DELETE].include?(request.request_method)
        ciba_transaction do
          ds = db[oauth_applications_table].where(oauth_applications_client_id_column => client_id)
          token = request.env["HTTP_AUTHORIZATION"].to_s[/\A *Bearer (.*)\Z/, 1]
          delete_owner = ciba_lock_registration_delete_grants(ds, token, client_id)
          ds = ds.for_update unless db.database_type == :sqlite
          @ciba_registration_application = ds.first
          if delete_owner && @ciba_registration_application && delete_owner != @ciba_registration_application[oauth_applications_id_column]
            raise Sequel::SerializationFailure, "Registration client changed while locking"
          end
          if request.request_method == "DELETE" && @ciba_registration_application &&
              @ciba_registration_application[oauth_applications_grant_types_column].to_s.split.include?(GRANT_TYPE)
            authorization_required unless token && password_hash_match?(
              @ciba_registration_application[oauth_applications_registration_access_token_column], token)
            ciba_delete_registered_client(@ciba_registration_application)
          end
          super
        end
      rescue Sequel::DatabaseLockTimeout, Sequel::SerializationFailure
        response["Retry-After"] = ciba_poll_interval.to_s
        ciba_error("temporarily_unavailable", 503)
      rescue Sequel::DatabaseError => error
        # The SQLite adapter wraps BusyException as generic DatabaseError.
        # Retry only this recognized contention outcome, never other DB errors.
        raise unless ciba_sqlite_busy_error?(error)
        response["Retry-After"] = ciba_poll_interval.to_s
        ciba_error("temporarily_unavailable", 503)
      ensure
        @ciba_registration_application = nil
        @ciba_registration_route = false
        @ciba_registration_replacement = false
        @ciba_rotated_registration_token = nil
      end

      private

      def ciba_lock_registration_delete_grants(dataset, token, client_id)
        return unless request.request_method == "DELETE"
        candidate = dataset.first
        return unless candidate && candidate[oauth_applications_client_id_column] == client_id &&
          (ciba_issued_management_bearer? || candidate[oauth_applications_grant_types_column].to_s.split.include?(GRANT_TYPE))
        authorization_required unless token && candidate[oauth_applications_registration_access_token_column] &&
          password_hash_match?(candidate[oauth_applications_registration_access_token_column], token)
        id = candidate.fetch(oauth_applications_id_column)
        # Issuance/refresh already lock consent before touching parent-client
        # FKs. Acquire existing consents in that order before the client lock;
        # the caller then reloads and authenticates the credential under lock.
        grants = db[ciba_grants_table].where(oauth_application_id: id).select(:id).order(:id)
        grants = grants.for_update unless db.database_type == :sqlite
        grants.all
        id
      end

      def ciba_delete_registered_client(application)
        id = application.fetch(oauth_applications_id_column)
        # Ordinary grants have no CIBA consent FK and therefore do not cascade
        # through ciba_grants. Remove all grants owned by this authorized client;
        # the outer transaction restores them if deleting the client fails.
        db[oauth_grants_table].where(oauth_grants_oauth_application_id_column => id).delete
        db[oauth_applications_table].where(oauth_applications_id_column => id).delete
        response.status = 204
        response["Cache-Control"] = "no-store"
        response["Pragma"] = "no-cache"
        request.halt(response.finish)
      end

      def password_hash_match?(hash, password)
        # A deliberately invalidated or never-issued management credential has
        # no verifier. Upstream BCrypt.new(nil) would otherwise raise a 500.
        return false if @ciba_registration_route && hash.nil?
        super
      end

      def ciba_registration_grant?(params)
        Array(params["grant_types"]).include?(GRANT_TYPE)
      end

      def ciba_issued_management_bearer?
        request.env["HTTP_AUTHORIZATION"].to_s.match?(/\A *Bearer ciba_reg_/)
      end

      def validate_client_registration_params(params, *args)
        existing = @ciba_registration_application
        relevant = ciba_registration_grant?(params) || params.keys.any? { |key| key.start_with?("backchannel_") } ||
          existing && (ciba_issued_management_bearer? || existing[oauth_applications_grant_types_column].to_s.split.include?(GRANT_TYPE))
        return super unless relevant
        unless ciba_dynamic_client_registration_enabled
          register_throw_json_response_error("invalid_client_metadata", "CIBA clients require static registration")
        end
        if existing
          unless params["client_id"] == existing[oauth_applications_client_id_column]
            register_throw_json_response_error("invalid_request", "client_id must match the authenticated client")
          end
          if %w[registration_access_token registration_client_uri client_secret_expires_at client_id_issued_at].any? { |key| params.key?(key) }
            register_throw_json_response_error("invalid_request", "Server-issued metadata cannot be supplied in an update")
          end
        end
        known = %w[backchannel_token_delivery_mode backchannel_client_notification_endpoint backchannel_user_code_parameter backchannel_authentication_request_signing_alg]
        allowed = existing ? METADATA + ["client_secret"] : METADATA
        normalized = params.select { |key, _| allowed.include?(key) }
        ignored = params.keys - normalized.keys
        if existing
          normalized = normalized.reject { |_, value| value.nil? || value == "" }
          normalized["grant_types"] ||= ["authorization_code"]
          normalized["response_types"] ||= ["code"]
          normalized["token_endpoint_auth_method"] ||= "client_secret_basic"
          normalized["scope"] ||= oauth_application_scopes.join(" ")
          if normalized["response_types"] != [] && !normalized.key?("redirect_uris")
            register_throw_json_response_error("invalid_client_metadata", "redirect_uris required for browser response types")
          end
        end
        normalized["redirect_uris"] = [] if normalized["response_types"] == [] && !normalized.key?("redirect_uris")
        if features.include?(:oauth_dpop)
          if !normalized.key?("dpop_bound_access_tokens") && db[oauth_applications_table].columns.include?(oauth_applications_dpop_bound_access_tokens_column)
            normalized["dpop_bound_access_tokens"] = false
          end
          if normalized.key?("dpop_bound_access_tokens") && ![true, false].include?(normalized["dpop_bound_access_tokens"])
            register_throw_json_response_error("invalid_client_metadata", "dpop_bound_access_tokens must be a boolean")
          end
        elsif normalized.key?("dpop_bound_access_tokens")
          normalized.delete("dpop_bound_access_tokens")
          ignored << "dpop_bound_access_tokens"
        end
        tls_bound = "tls_client_certificate_bound_access_tokens"
        if features.include?(:oauth_tls_client_auth)
          if !normalized.key?(tls_bound) && db[oauth_applications_table].columns.include?(oauth_applications_tls_client_certificate_bound_access_tokens_column)
            normalized[tls_bound] = false
          end
          if normalized.key?(tls_bound) && ![true, false].include?(normalized[tls_bound])
            register_throw_json_response_error("invalid_client_metadata", "#{tls_bound} must be a boolean")
          end
          if normalized[tls_bound] && normalized["dpop_bound_access_tokens"]
            register_throw_json_response_error("invalid_client_metadata", "Only one token binding mechanism may be required")
          end
          subjects = TLS_SUBJECT_METADATA & normalized.keys
          if subjects.any? { |key| !normalized[key].is_a?(String) || normalized[key].empty? }
            register_throw_json_response_error("invalid_client_metadata", "Certificate subject values must be nonempty strings")
          end
          if normalized["token_endpoint_auth_method"] == "tls_client_auth"
            if subjects.length != 1
              register_throw_json_response_error("invalid_client_metadata", "tls_client_auth requires one certificate subject value")
            end
          else
            subjects.each { |key| normalized.delete(key); ignored << key }
          end
        else
          (TLS_SUBJECT_METADATA + [tls_bound]).each do |key|
            ignored << key if normalized.key?(key)
            normalized.delete(key)
          end
        end
        default_acr_values = normalized.delete("default_acr_values")
        unless default_acr_values.nil?
          unless default_acr_values.is_a?(Array) && default_acr_values.all? { |value|
            value.is_a?(String) && oauth_acr_values_supported.include?(value)
          }
            register_throw_json_response_error("invalid_client_metadata", "default_acr_values must contain supported ACR strings")
          end
          default_acr_values = default_acr_values.uniq
        end
        if normalized.key?("require_auth_time") && ![true, false].include?(normalized["require_auth_time"])
          register_throw_json_response_error("invalid_client_metadata", "require_auth_time must be a boolean")
        end
        if normalized.key?("default_max_age")
          age = normalized["default_max_age"]
          # JSON numbers such as 1.0 are also integers in node's number model.
          # Validate before Sequel can coerce strings or truncate fractions.
          integer = age.is_a?(Integer) || age.is_a?(Float) && age.finite? && age == age.to_i
          unless integer && age.between?(0, 9_007_199_254_740_991)
            register_throw_json_response_error("invalid_client_metadata", "default_max_age must be a non-negative safe integer")
          end
          normalized["default_max_age"] = age.to_i
        end
        types = normalized.fetch("authorization_details_types", [])
        normalized.delete("authorization_details_types")
        if ciba_authorization_details_enabled
          unless types.is_a?(Array) && types.all? { |type| type.is_a?(String) && type.valid_encoding? &&
              !type.empty? && ciba_authorization_details_types.include?(type) }
            register_throw_json_response_error("invalid_client_metadata", "Unsupported authorization_details_types")
          end
        elsif params.key?("authorization_details_types")
          ignored << "authorization_details_types"
        end
        normalized.each do |key, value|
          if key.start_with?("backchannel_") && (!known.include?(key) ||
              (key == "backchannel_user_code_parameter" ? ![true, false].include?(value) : !value.is_a?(String)))
            register_throw_json_response_error("invalid_client_metadata", "Invalid CIBA client metadata")
          end
        end
        if normalized.key?("token_endpoint_auth_signing_alg")
          signing_algorithm = normalized["token_endpoint_auth_signing_alg"]
          method = normalized.fetch("token_endpoint_auth_method", "client_secret_basic")
          allowed = case method
                    when "private_key_jwt"
                      (ciba_client_assertion_signing_algorithms || oauth_jwt_keys.keys).reject { |alg| alg.start_with?("HS") || alg == "none" }
                    when "client_secret_jwt"
                      (ciba_client_assertion_signing_algorithms || oauth_jwt_keys.keys).select { |alg| %w[HS256 HS384 HS512].include?(alg) }
                    else
                      []
                    end
          unless signing_algorithm.is_a?(String) && allowed.include?(signing_algorithm)
            register_throw_json_response_error("invalid_client_metadata", "Unsupported client authentication signing algorithm")
          end
        end
        if normalized.key?("jwks") && !ciba_registration_jwks_valid?(normalized["jwks"])
          register_throw_json_response_error("invalid_client_metadata", "Invalid client JSON Web Key Set")
        end
        encryption = {}
        unless ciba_id_token_encryption_enabled
          ignored_encryption = normalized.keys & %w[id_token_encrypted_response_alg id_token_encrypted_response_enc]
          ignored.concat(ignored_encryption)
          normalized = normalized.reject { |key, _| ignored_encryption.include?(key) }
        end
        upstream_params = normalized
        if normalized.keys.any? { |key| %w[id_token_encrypted_response_alg id_token_encrypted_response_enc].include?(key) }
          algorithm = normalized["id_token_encrypted_response_alg"]
          method = normalized.fetch("id_token_encrypted_response_enc", "A128CBC-HS256")
          unless IdTokenEncryption::ALGORITHMS.include?(algorithm) && IdTokenEncryption::METHODS.include?(method)
            register_throw_json_response_error("invalid_client_metadata", "Unsupported CIBA ID Token encryption")
          end
          encryption[oauth_applications_id_token_encrypted_response_alg_column] = algorithm
          encryption[oauth_applications_id_token_encrypted_response_enc_column] = method
          # Validate only these two fields here. Do not widen upstream's lists
          # for unrelated UserInfo, request object or authorization encryption.
          upstream_params = normalized.reject { |key, _| %w[id_token_encrypted_response_alg id_token_encrypted_response_enc].include?(key) }
        end
        super(upstream_params, *args)
        @oauth_application_params.merge!(encryption)
        unless default_acr_values.nil?
          @oauth_application_params[oauth_applications_default_acr_values_column] = JSON.generate(default_acr_values)
        end
        @oauth_application_params[:authorization_details_types] = JSON.generate(types) if ciba_authorization_details_enabled
        @oauth_application_unrecognized_params.concat(ignored)
        columns = db[oauth_applications_table].columns
        if @oauth_application_params.keys.any? { |column| !columns.include?(column.to_sym) }
          register_throw_json_response_error("invalid_client_metadata", "Client metadata storage is not configured")
        end
        if existing
          # Only protocol metadata is replaced. Preserve identifiers, credential
          # verifiers and application-owned columns not part of this protocol.
          aliases = {"scope" => "scopes", "client_name" => "name", "client_uri" => "homepage_url", "redirect_uris" => "redirect_uri"}
          reset = METADATA.each_with_object({}) do |key, values|
            name = aliases.fetch(key, key)
            method_name = :"oauth_applications_#{name}_column"
            column = respond_to?(method_name) ? __send__(method_name) : name.to_sym
            values[column] = nil if columns.include?(column)
          end
          @oauth_application_params = reset.merge(@oauth_application_params)
        end
        candidate = (existing || {}).merge(@oauth_application_params)
        if !encryption.empty? &&
            !IdTokenEncryption::SYMMETRIC_ALGORITHMS.include?(candidate[oauth_applications_id_token_encrypted_response_alg_column]) &&
            !candidate[oauth_applications_jwks_column] && !candidate[oauth_applications_jwks_uri_column]
          register_throw_json_response_error("invalid_client_metadata", "CIBA encrypted ID Token requires recipient keys")
        end
        unless existing
          candidate[oauth_applications_scopes_column] ||= oauth_application_scopes.join(" ")
          candidate[oauth_applications_token_endpoint_auth_method_column] ||= "client_secret_basic"
        end
        if candidate[oauth_applications_grant_types_column].to_s.split.include?(GRANT_TYPE) &&
            candidate[oauth_applications_subject_type_column] == "pairwise" && ciba_pairwise_sector(candidate) &&
            !ciba_pairwise_sector_document_valid?(candidate, fresh: true)
          register_throw_json_response_error("invalid_client_metadata", "Invalid pairwise sector document")
        end
        if candidate[oauth_applications_grant_types_column].to_s.split.include?(GRANT_TYPE) && !ciba_client_eligible?(candidate)
          register_throw_json_response_error("invalid_client_metadata", "Unsupported CIBA client configuration")
        end
        algorithm = candidate[oauth_applications_backchannel_authentication_request_signing_alg_column]
        methods = candidate[oauth_applications_token_endpoint_auth_method_column].to_s.split
        if (algorithm || (methods & %w[private_key_jwt self_signed_tls_client_auth]).any?) &&
            !candidate[oauth_applications_jwks_column] && !candidate[oauth_applications_jwks_uri_column]
          register_throw_json_response_error("invalid_client_metadata", "CIBA client requires registered verification keys")
        end
        @ciba_registration_replacement = true if existing
      end

      def do_register(return_params = request.params.dup)
        if ciba_dynamic_client_registration_enabled && ciba_registration_grant?(return_params)
          if (defaults = @oauth_application_params[oauth_applications_default_acr_values_column])
            return_params["default_acr_values"] = JSON.parse(defaults)
          end
          if ciba_id_token_encryption_enabled && @oauth_application_params[oauth_applications_id_token_encrypted_response_alg_column]
            return_params["id_token_encrypted_response_enc"] = @oauth_application_params[oauth_applications_id_token_encrypted_response_enc_column]
          end
          return_params["redirect_uris"] ||= [] if return_params["response_types"] == []
          if features.include?(:oauth_dpop)
            return_params["dpop_bound_access_tokens"] = @oauth_application_params[oauth_applications_dpop_bound_access_tokens_column] || false
          end
          if features.include?(:oauth_tls_client_auth)
            return_params["tls_client_certificate_bound_access_tokens"] = @oauth_application_params[oauth_applications_tls_client_certificate_bound_access_tokens_column] || false
          end
          if ciba_authorization_details_enabled
            return_params["authorization_details_types"] = JSON.parse(@oauth_application_params.fetch(:authorization_details_types))
          end
        end
        super(return_params)
      end

      # Match node's registration-time structural/public-key checks. This is not
      # proof that a key is usable: signature verification still happens at use.
      def ciba_registration_jwks_valid?(jwks)
        return false unless jwks.is_a?(Hash) && jwks["keys"].is_a?(Array)
        string = ->(value) { value.is_a?(String) && !value.empty? }
        jwks["keys"].all? do |key|
          next false unless key.is_a?(Hash) && string.call(key["kty"])
          required, private_fields = case key["kty"]
                                     when "RSA" then [%w[e n], %w[d p q dp dq qi oth]]
                                     when "EC" then [%w[x y], %w[d]]
                                     when "OKP" then [%w[x], %w[d]]
                                     when "AKP" then [%w[alg pub], %w[priv]]
                                     when "oct" then next false
                                     else next true # Unknown key types are not usable keys.
                                     end
          if %w[EC OKP].include?(key["kty"])
            next false unless string.call(key["crv"])
            curves = key["kty"] == "EC" ? %w[P-256 P-384 P-521] : %w[Ed25519 X25519]
            next true unless curves.include?(key["crv"])
          end
          required.all? { |field| string.call(key[field]) } &&
            private_fields.none? { |field| key.key?(field) } &&
            %w[alg kid use].all? { |field| !key.key?(field) || string.call(key[field]) } &&
            (!key.key?("x5c") || (key["x5c"].is_a?(Array) && key["x5c"].all?(&string)))
        end
      end

      def initialize_create_params(create_params, return_params)
        super
        return unless ciba_dynamic_client_registration_enabled &&
          create_params[oauth_applications_grant_types_column].to_s.split.include?(GRANT_TYPE)
        algorithm = create_params[oauth_applications_id_token_signed_response_alg_column] || oauth_jwt_keys.keys.first
        if %w[HS256 HS384 HS512].include?(algorithm) && return_params["client_secret"].is_a?(String)
          required_bytes = algorithm.delete_prefix("HS").to_i / 8
          if return_params["client_secret"].bytesize < required_bytes
            # Upstream's default secret has 32 random bytes: enough for HS256,
            # but not for HS384/512. Keep its configured storage/hash handling.
            secret = SecureRandom.urlsafe_base64(required_bytes)
            set_client_secret(create_params, secret)
            return_params["client_secret"] = secret
          end
        end
        return unless ciba_issue_registration_access_token
        token, credentials = ciba_new_registration_credentials
        create_params.merge!(credentials)
        return_params["registration_access_token"] = token
        return_params["registration_client_uri"] = ciba_registration_client_uri(return_params.fetch("client_id"))
      end

      def ciba_new_registration_credentials
        column = oauth_applications_registration_access_token_column
        columns = db[oauth_applications_table].columns
        unless columns.include?(column) && columns.include?(ciba_registration_token_digest_column)
          raise ConfigurationError, "configure registration access-token hash and digest storage before enabling CIBA dynamic registration"
        end
        token = "ciba_reg_#{SecureRandom.urlsafe_base64(32)}"
        [token, {column => password_hash(token).to_s,
          ciba_registration_token_digest_column => Digest::SHA256.hexdigest(token)}]
      end

      def __update_and_return__(dataset, values, *args)
        return super unless @ciba_registration_replacement && ciba_rotate_registration_access_token
        token, credentials = ciba_new_registration_credentials
        result = super(dataset, values.merge(credentials), *args)
        @ciba_rotated_registration_token = token
        result
      end

      def ciba_registration_client_uri(client_id)
        "#{route_url(registration_client_uri_route)}/#{URI.encode_www_form_component(client_id)}"
      end

      def json_response_oauth_application(application)
        safe = application.dup
        safe.delete(oauth_applications_registration_access_token_column)
        ciba = ciba_issued_management_bearer? || [application, @ciba_registration_application].compact.any? do |entry|
          entry[oauth_applications_grant_types_column].to_s.split.include?(GRANT_TYPE)
        end
        return super(safe) unless ciba
        # Upstream's management serializer includes every configured column and
        # splits token_endpoint_auth_method as if it were an array. Keep its
        # metadata mapping, but suppress credentials and restore protocol types.
        @ciba_registration_response = {
          "client_id" => application[oauth_applications_client_id_column],
          "token_endpoint_auth_method" => application[oauth_applications_token_endpoint_auth_method_column],
          "registration_client_uri" => ciba_registration_client_uri(application[oauth_applications_client_id_column])
        }
        user_code = application[oauth_applications_backchannel_user_code_parameter_column]
        @ciba_registration_response["backchannel_user_code_parameter"] = user_code unless user_code.nil?
        require_auth_time = application[oauth_applications_require_auth_time_column]
        @ciba_registration_response["require_auth_time"] = require_auth_time unless require_auth_time.nil?
        if (defaults = application[oauth_applications_default_acr_values_column])
          @ciba_registration_response["default_acr_values"] = JSON.parse(defaults)
        end
        if features.include?(:oauth_dpop)
          @ciba_registration_response["dpop_bound_access_tokens"] = application[oauth_applications_dpop_bound_access_tokens_column] || false
        end
        if features.include?(:oauth_tls_client_auth)
          @ciba_registration_response["tls_client_certificate_bound_access_tokens"] = application[oauth_applications_tls_client_certificate_bound_access_tokens_column] || false
        end
        if ciba_authorization_details_enabled || application[:authorization_details_types]
          @ciba_registration_response["authorization_details_types"] = JSON.parse(application[:authorization_details_types] || "[]")
        end
        # Upstream has authenticated this bearer before invoking the serializer.
        # Echo the presented credential as node does, never its stored verifier.
        token = @ciba_rotated_registration_token || request.env["HTTP_AUTHORIZATION"].to_s[/\A *Bearer (.*)\Z/, 1]
        @ciba_registration_response["registration_access_token"] = token if token
        super(safe)
      ensure
        @ciba_registration_response = nil
      end

      def _json_response_body(body)
        if @ciba_registration_response && body.is_a?(Hash)
          body = body.reject { |key, _| %w[registration_access_token client_secret client_secret_hash].include?(key.to_s) }
          body = body.merge(@ciba_registration_response)
        end
        super(body)
      end
    end
  end
end
