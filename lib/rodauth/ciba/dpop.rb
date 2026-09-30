# frozen_string_literal: true

module Rodauth
  module CibaSupport
    # CIBA token and UserInfo proof boundary. External resource servers still
    # need their own validation of access-token signatures and sender binding.
    module Dpop
      private

      def ciba_dpop_userinfo_candidate?(token)
        return false unless token.is_a?(String)
        return true if token.start_with?("ciba_at_")
        return false if token.bytesize > 8192
        if token.count(".") == 2
          claims = JWT::EncodedToken.new(token).unverified_payload
          # Unverified claims select a stricter path only. Signature, expiry,
          # client, subject and stored grant checks still precede authorization.
          return claims.is_a?(Hash) && claims.key?("urn:rodauth:ciba:token_id")
        end
        return false if token.bytesize > 1024
        column = oauth_grants_token_hash_column || oauth_grants_token_column
        value = oauth_grants_token_hash_column ? generate_token_hash(token) : token
        db[oauth_grants_table].where(column => value, oauth_grants_type_column => GRANT_TYPE).any?
      rescue JWT::DecodeError
        false
      end

      def ciba_dpop_protected_request?
        @ciba_dpop_userinfo || ciba_dpop_token_request?
      end

      def ciba_dpop_error(code = "invalid_dpop_proof")
        if @ciba_dpop_userinfo
          response["WWW-Authenticate"] = "DPoP error=\"#{code}\""
          ciba_error(code, 401)
        end
        ciba_error(code)
      end

      def decode_access_token(token = fetch_access_token)
        return super unless @ciba_dpop_userinfo
        decoded = oauth_jwt_access_tokens ? super : oauth_grant_by_token(token)
        ciba_dpop_error("invalid_token") unless decoded
        if decoded[oauth_grants_type_column] == GRANT_TYPE && decoded[oauth_grants_dpop_jkt_column]
          decoded = decoded.merge("cnf" => {"jkt" => decoded[oauth_grants_dpop_jkt_column]})
        end
        decoded
      end

      def valid_oauth_grant_ds(grant_params = nil)
        return super unless @ciba_dpop_userinfo || @ciba_dpop_userinfo_checked
        # Upstream's OR thumbprint filter widens the complete predicate. Keep
        # revocation, expiration, identity and key binding conjunctive here.
        ds = db[oauth_grants_table].where(oauth_grants_revoked_at_column => nil,
          oauth_grants_type_column => GRANT_TYPE,
          oauth_grants_dpop_jkt_column => @dpop_thumbprint)
          .where(Sequel.expr(Sequel[oauth_grants_expires_in_column]) >= Sequel::CURRENT_TIMESTAMP)
        ds = ds.where(grant_params) if grant_params
        ds = ds.where(oauth_grants_id_column => @ciba_userinfo_grant_id) if @ciba_userinfo_grant_id
        ds
      end

      def oauth_grant_by_token_ds(token)
        if features.include?(:oauth_dpop) && features.include?(:oauth_token_introspection) &&
            request.path == introspect_path && ciba_dpop_userinfo_candidate?(token)
          # Authenticated introspection reports binding to the caller; it is not
          # a resource request proving possession of the access token's key.
          column = oauth_grants_token_hash_column || oauth_grants_token_column
          value = oauth_grants_token_hash_column ? generate_token_hash(token) : token
          return db[oauth_grants_table].where(column => value,
            oauth_grants_type_column => GRANT_TYPE, oauth_grants_revoked_at_column => nil)
            .where(Sequel.expr(Sequel[oauth_grants_expires_in_column]) >= Sequel::CURRENT_TIMESTAMP)
        end
        return super unless @ciba_dpop_userinfo || @ciba_dpop_userinfo_checked
        column = oauth_grants_token_hash_column || oauth_grants_token_column
        value = oauth_grants_token_hash_column ? generate_token_hash(token) : token
        valid_oauth_grant_ds.where(column => value)
      end

      def json_token_introspect_payload(grant)
        super.tap do |payload|
          if features.include?(:oauth_dpop) && payload[:active] &&
              grant && grant[oauth_grants_type_column] == GRANT_TYPE &&
              (jkt = grant[oauth_grants_dpop_jkt_column])
            payload[:cnf] = {jkt: jkt}
            payload[:token_type] = "DPoP"
          end
        end
      end

      def authorization_token
        return super if @ciba_dpop_userinfo_checked
        return super unless features.include?(:oauth_dpop) && request.path == userinfo_path
        access = fetch_access_token_from_authorization_header("dpop") || fetch_access_token
        return super unless ciba_dpop_userinfo_candidate?(access)
        @ciba_dpop_userinfo = true
        ciba_dpop_error("invalid_token") if access.bytesize > 8192
        @dpop_access_token = fetch_access_token_from_authorization_header("dpop")
        if @dpop_access_token
          validate_dpop_token(fetch_dpop_token)
          validate_ath(@dpop_claims, access)
          @authorization_token = decode_access_token(access)
        end
        token = super
        ciba_dpop_error("invalid_token") unless token
        if @dpop_access_token
          stored_jkt = db[oauth_grants_table].where(oauth_grants_id_column => @ciba_userinfo_grant_id)
            .get(oauth_grants_dpop_jkt_column)
          ciba_dpop_error("invalid_token") unless token["cnf"].is_a?(Hash) &&
            token["cnf"]["jkt"] == @dpop_thumbprint && stored_jkt == @dpop_thumbprint
          ciba_claim_dpop_proof!(token.fetch("client_id"))
        elsif token[oauth_grants_dpop_jkt_column] || token.dig("cnf", "jkt")
          ciba_dpop_error("invalid_token")
        end
        @ciba_dpop_userinfo_checked = true
        token
      rescue Sequel::UniqueConstraintViolation
        raise unless @ciba_dpop_userinfo
        ciba_dpop_error("invalid_token")
      ensure
        @ciba_dpop_userinfo = false
      end

      def validate_ath(claims, access_token)
        return super unless @ciba_dpop_userinfo
        expected = Base64.urlsafe_encode64(Digest::SHA256.digest(access_token), padding: false)
        ciba_dpop_error("invalid_token") unless claims["ath"] == expected
      end

      def ciba_dpop_token_request?
        features.include?(:oauth_dpop) && request.path == token_path &&
          (param("grant_type") == GRANT_TYPE || ciba_refresh_request?)
      end

      def validate_token_params
        if ciba_dpop_token_request? && !fetch_dpop_token && dpop_bound_access_tokens_required?
          ciba_error("invalid_grant")
        end
        super
      end

      def dpop_use_nonce?
        return super unless ciba_dpop_protected_request?
        oauth_dpop_use_nonce
      end

      def ciba_dpop_nonce_for(step)
        bytes = OpenSSL::KDF.hkdf(ciba_dpop_nonce_secret, salt: [step].pack("Q>"),
          info: "DPoP", length: 32, hash: "SHA256")
        Base64.urlsafe_encode64(bytes, padding: false)
      end

      def validate_nonce(claims)
        return super unless ciba_dpop_protected_request?
        @ciba_dpop_nonce_verified = false
        nonce = claims["nonce"]
        ciba_dpop_error if claims.key?("nonce") && !nonce.is_a?(String)
        step = ciba_now / 60
        next_nonce = ciba_dpop_nonce_for(step + 1) if ciba_dpop_nonce_secret
        challenge = lambda do
          response["DPoP-Nonce"] = next_nonce
          ciba_dpop_error("use_dpop_nonce")
        end
        if nonce && !nonce.empty?
          ciba_dpop_error unless next_nonce
          valid = nonce.bytesize == 43 && (-2..2).map do |offset|
            OpenSSL.fixed_length_secure_compare(ciba_dpop_nonce_for(step + offset), nonce)
          end.reduce(false, :|)
          challenge.call unless valid
          @ciba_dpop_nonce_verified = true
        else
          if (ciba_now - claims.fetch("iat")).abs > 300
            challenge.call if next_nonce
            ciba_dpop_error
          end
          challenge.call if dpop_use_nonce?
        end
        response["DPoP-Nonce"] = next_nonce if next_nonce && nonce != next_nonce
      end

      def dpop_decode(proof)
        return super unless ciba_dpop_protected_request?
        ciba_dpop_error unless proof.is_a?(String) && proof.bytesize <= 8192
        header = JWT::EncodedToken.new(proof).header
        unless header.is_a?(Hash) && header["jwk"].is_a?(Hash) && !header.key?("crit") &&
            verify_dpop_jwt_headers(header)
          ciba_dpop_error
        end
        # The generic OP decoder applies its issuer-token iat policy. Proof
        # freshness has its own window, checked below, including future iat.
        claims, = JWT.decode(proof, jwk_key(header["jwk"]), true,
          algorithms: [header["alg"]], verify_iat: false)
        claims
      rescue JWT::DecodeError, JWT::JWKError, ArgumentError, TypeError, OpenSSL::PKey::PKeyError
        raise unless ciba_dpop_protected_request?
        ciba_dpop_error
      end

      def validate_dpop_jwt_claims(claims)
        return super unless ciba_dpop_protected_request?
        iat, jti = claims.values_at("iat", "jti")
        unless iat.is_a?(Numeric) && iat.finite? && !iat.zero? &&
            jti.is_a?(String) && !jti.empty? && jti.bytesize <= 1024 &&
            claims["htm"] == request.request_method
          ciba_dpop_error
        end
        uri = URI.parse(claims["htu"]) if claims["htu"].is_a?(String)
        ciba_dpop_error unless uri.is_a?(URI::HTTP) && uri.host && !uri.userinfo
        uri.query = uri.fragment = nil
        # Bind the proof to the endpoint actually reached, including an
        # application-owned alias, rather than the canonical issuer's URL.
        expected = URI.parse(ciba_dpop_endpoint_uri)
        expected.query = expected.fragment = nil
        ciba_dpop_error unless uri.normalize == expected.normalize
      rescue URI::InvalidURIError
        raise unless ciba_dpop_protected_request?
        ciba_dpop_error
      end

      def validate_dpop_proof_usage(claims)
        return super unless ciba_dpop_protected_request?
        # Pending polls do not reserve proofs. Issuance claims inside its token
        # transaction; UserInfo claims after token provenance and key checks.
      end

      def generate_token(grant_params = {}, should_generate_refresh_token = true)
        if ciba_dpop_token_request? && @dpop_claims
          begin
            ciba_claim_dpop_proof!(oauth_application[oauth_applications_client_id_column])
          rescue Sequel::UniqueConstraintViolation
            # Raise through the outer token transaction, preserving approval
            # on rejection instead of committing a partially consumed request.
            raise ProtocolError, "invalid_grant"
          end
        end
        super
      end

      def ciba_claim_dpop_proof!(client_id)
        digest = Digest::SHA256.hexdigest(JSON.generate(["ciba_dpop", client_id, @dpop_claims.fetch("jti")]))
        # A valid server nonce replaces the proof iat as freshness evidence.
        # An ancient iat must never cause immediate replay-ledger cleanup.
        expires_at = @ciba_dpop_nonce_verified ? ciba_now + 301 : (@dpop_claims.fetch("iat") + 300).ceil + 1
        ciba_transaction do
          db[ciba_client_assertions_table].insert(digest: digest, expires_at: expires_at)
        end
      end
    end
  end
end
