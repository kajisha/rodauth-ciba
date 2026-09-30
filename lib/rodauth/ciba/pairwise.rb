# frozen_string_literal: true

module Rodauth
  module CibaSupport
    module PairwiseSubjects
      def jwt_subject(account_id, application = oauth_application)
        return super unless application &&
          application[oauth_applications_grant_types_column].to_s.split.include?(GRANT_TYPE) &&
          (application[oauth_applications_subject_type_column] || oauth_jwt_subject_type) == "pairwise"
        sector = ciba_pairwise_sector(application)
        raise ConfigurationError, "invalid CIBA pairwise client" unless ciba_pairwise_enabled && sector
        subject = ciba_pairwise_identifier(account_id, oauth_application: application, sector_identifier: sector)
        unless subject.is_a?(String) && subject.ascii_only? && !subject.empty? && subject.bytesize <= 255
          raise ConfigurationError, "invalid CIBA pairwise identifier"
        end
        subject
      end

      private

      def fill_with_account_claims(claims, account, scopes, locales)
        result = super
        if @ciba_userinfo_grant_id && request.path == userinfo_path && oauth_application &&
            (oauth_application[oauth_applications_subject_type_column] || oauth_jwt_subject_type) == "pairwise"
          claims["sub"] = jwt_subject(account[account_id_column], oauth_application)
        end
        result
      end

      def ciba_pairwise_sector(application)
        return unless ciba_pairwise_enabled
        authentication = application[oauth_applications_token_endpoint_auth_method_column]
        return unless authentication == "private_key_jwt" ||
          (authentication == "self_signed_tls_client_auth" && features.include?(:oauth_tls_client_auth))
        jwks_uri = application[oauth_applications_jwks_uri_column]
        return unless ciba_pairwise_uri(jwks_uri)
        return if application[oauth_applications_jwks_column]
        sector_uri = application[oauth_applications_sector_identifier_uri_column]
        responses = application[oauth_applications_response_types_column].to_s.split
        return if !responses.empty? && !sector_uri
        uri = sector_uri ? ciba_pairwise_uri(sector_uri, https: true) : ciba_pairwise_uri(jwks_uri)
        return unless uri
        # WHATWG URL.host includes a nondefault port, unlike Ruby URI#host.
        authority = uri.host.downcase
        authority += ":#{uri.port}" unless uri.port == uri.default_port
        authority
      end

      def ciba_pairwise_uri(value, https: false)
        return unless value.is_a?(String) && !value.empty?
        uri = URI(value)
        return unless (https ? uri.scheme == "https" : %w[http https].include?(uri.scheme)) &&
          uri.host && !uri.userinfo && !uri.fragment
        uri
      rescue URI::InvalidURIError
        nil
      end

      def ciba_pairwise_sector_document_valid?(application, fresh: false)
        value = application[oauth_applications_sector_identifier_uri_column]
        return true unless value
        redirects = application[oauth_applications_redirect_uri_column].to_s.split
        required = [application[oauth_applications_jwks_uri_column]]
        required += redirects unless application[oauth_applications_response_types_column].to_s.empty?
        # Like node's dynamic-client cache, bind validation to complete client
        # metadata rather than the document URL. Never cache failed validation.
        mutex, cache = self.class.instance_variable_get(:@ciba_sector_validation_cache)
        key = Digest::SHA256.hexdigest(JSON.generate(application.sort_by { |column, _| column.to_s }))
        cached = !fresh && mutex.synchronize { cache[key] = true if cache.delete(key) }
        return true if cached
        uri = ciba_pairwise_uri(value, https: true)
        return false unless uri
        response = ciba_pairwise_sector_response(uri)
        body = JSON.parse(response.body) if response.code.to_i == 200
        valid = body.is_a?(Array) && body.all? { |entry| entry.is_a?(String) } && (required - body).empty?
        if valid
          mutex.synchronize do
            cache.delete(key)
            cache[key] = true
            cache.shift while cache.size > 100
          end
        end
        valid
      rescue HTTP::Error, JSON::ParserError, IOError, SystemCallError, Timeout::Error,
             SocketError, OpenSSL::SSL::SSLError, Net::HTTPBadResponse
        false
      end

      def ciba_pairwise_sector_response(uri)
        Timeout.timeout(HTTP::TIMEOUT) do
          21.times do |redirect_count|
            response = HTTP.request(uri, Net::HTTP::Get.new(uri.request_uri), address_allowed: method(:ciba_http_address_allowed?))
            return response unless [301, 302, 303, 307, 308].include?(response.code.to_i) && response["location"]
            raise HTTP::Error, "too many sector redirects" if redirect_count == 20
            destination = URI.join(uri.to_s, response["location"]).to_s
            uri = ciba_pairwise_uri(destination)
            raise HTTP::Error, "invalid sector redirect URI" unless uri
          end
        end
      rescue URI::InvalidURIError
        raise HTTP::Error, "invalid sector redirect URI"
      end
    end
  end
end
