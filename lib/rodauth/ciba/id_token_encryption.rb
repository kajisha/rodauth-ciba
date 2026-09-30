# frozen_string_literal: true
module Rodauth
  module CibaSupport
    module IdTokenEncryption
      SYMMETRIC_ALGORITHMS = %w[dir A128KW A192KW A256KW A128GCMKW A192GCMKW A256GCMKW].freeze
      ECDH_ALGORITHMS = %w[ECDH-ES ECDH-ES+A128KW ECDH-ES+A192KW ECDH-ES+A256KW].freeze
      ALGORITHMS = (%w[RSA-OAEP RSA-OAEP-256] + SYMMETRIC_ALGORITHMS + ECDH_ALGORITHMS).freeze
      METHODS = %w[A128GCM A192GCM A256GCM A128CBC-HS256 A192CBC-HS384 A256CBC-HS512].freeze

      private

      def generate_id_token(grant, include_claims = false)
        previous = @ciba_symmetric_recipient_client
        if @ciba_authentication && ciba_id_token_encryption_enabled &&
            SYMMETRIC_ALGORITHMS.include?(oauth_application[oauth_applications_id_token_encrypted_response_alg_column])
          @ciba_symmetric_recipient_client = oauth_application[oauth_applications_id_column]
        end
        super
      ensure
        @ciba_symmetric_recipient_client = previous
      end

      def oauth_application_jwks(application)
        # Upstream eagerly resolves recipient keys while generating an ID Token.
        # Symmetric encryption has no public recipient key. Authentication runs
        # outside this scope and must still resolve/verify its registered keys.
        return if @ciba_symmetric_recipient_client &&
          @ciba_symmetric_recipient_client == application[oauth_applications_id_column]
        super
      end

      def ciba_gcm_key_wrap(token, key, algorithm, method)
        # RFC 7518 §4.7: a fresh 96-bit wrapping IV, empty AAD and a
        # 128-bit wrapping tag. Content encryption remains in the JWE backend.
        content = JWE::Enc.for(method)
        wrapper = OpenSSL::Cipher.new("aes-#{key.bytesize * 8}-gcm")
        wrapper.encrypt
        wrapper.key = key
        iv = SecureRandom.random_bytes(12)
        wrapper.iv = iv
        wrapper.auth_data = ""
        encrypted_key = wrapper.update(content.cek) + wrapper.final
        header = JSON.generate(alg: algorithm, enc: method, cty: "JWT",
          iss: oauth_jwt_issuer, aud: oauth_jwt_audience,
          iv: Base64.urlsafe_encode64(iv, padding: false),
          tag: Base64.urlsafe_encode64(wrapper.auth_tag(16), padding: false))
        ciphertext = content.encrypt(token, Base64.urlsafe_encode64(header, padding: false))
        JWE::Serialization::Compact.encode(header, encrypted_key, content.iv, ciphertext, content.tag)
      end

      def ciba_ecdh_public_key(jwk)
        if jwk["kty"] == "EC" && %w[P-256 P-384 P-521].include?(jwk["crv"])
          key = JWT::JWK.import(jwk.reject { |name, _| name == "d" }).keypair
          return unless key.is_a?(OpenSSL::PKey::EC) && key.check_key
          OpenSSL::PKey.read(key.public_to_der)
        elsif jwk["kty"] == "OKP" && jwk["crv"] == "X25519"
          encoded = jwk["x"]
          return unless encoded.is_a?(String) && encoded.match?(/\A[A-Za-z0-9_-]{43}\z/)
          raw = Base64.urlsafe_decode64(encoded)
          return unless raw.bytesize == 32 && Base64.urlsafe_encode64(raw, padding: false) == encoded
          identifier = OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new("1.3.101.110")])
          OpenSSL::PKey.read(OpenSSL::ASN1::Sequence.new([identifier, OpenSSL::ASN1::BitString.new(raw)]).to_der)
        end
      rescue JWT::JWKError, OpenSSL::PKey::PKeyError, ArgumentError
        nil
      end

      def ciba_ecdh_derived_key(shared, algorithm, method)
        direct = algorithm == "ECDH-ES"
        bits = (direct ? (method[/HS(\d+)$/, 1] || method[/^A(\d+)/, 1]) : algorithm[/A(\d+)KW$/, 1]).to_i
        name = direct ? method : algorithm
        # RFC 7518 §4.6.2: empty PartyUInfo/PartyVInfo; SHA-256 Concat KDF.
        info = [name.bytesize].pack("N") + name + [0, 0, bits].pack("N3")
        (1..((bits + 255) / 256)).map do |counter|
          OpenSSL::Digest.digest("SHA256", [counter].pack("N") + shared + info)
        end.join.byteslice(0, bits / 8)
      end

      def ciba_ecdh_encrypt(token, recipient, algorithm, method, headers)
        # The reference's public ECDH CryptoKey import accepts no key usages.
        # Do not silently discard a selected recipient's declared operations.
        if recipient.key?("key_ops") && recipient["key_ops"] != []
          raise ConfigurationError, "CIBA ECDH public recipient key_ops must be omitted or empty"
        end
        public_key = ciba_ecdh_public_key(recipient)
        raise ConfigurationError, "Invalid CIBA ECDH recipient key" unless public_key
        if recipient["crv"] == "X25519"
          ephemeral = OpenSSL::PKey.generate_key("X25519")
          raw = OpenSSL::ASN1.decode(ephemeral.public_to_der).value.last.value
          epk = {kty: "OKP", crv: "X25519", x: Base64.urlsafe_encode64(raw, padding: false)}
        else
          ephemeral = OpenSSL::PKey::EC.generate(public_key.group.curve_name)
          epk = JWT::JWK.new(ephemeral).export.select { |name, _| %i[kty crv x y].include?(name) }
        end
        shared = ephemeral.derive(public_key)
        raise ConfigurationError, "Invalid CIBA ECDH shared secret" if shared.bytes.all?(&:zero?)
        derived = ciba_ecdh_derived_key(shared, algorithm, method)
        content = JWE::Enc.for(method)
        encrypted_key = if algorithm == "ECDH-ES"
          content.cek = derived
          ""
        else
          JWE::Alg.encrypt_cek(algorithm.split("+").last, derived, content.cek)
        end
        header = JSON.generate(headers.merge(alg: algorithm, enc: method, epk: epk))
        ciphertext = content.encrypt(token, Base64.urlsafe_encode64(header, padding: false))
        JWE::Serialization::Compact.encode(header, encrypted_key, content.iv, ciphertext, content.tag)
      rescue OpenSSL::PKey::PKeyError
        raise ConfigurationError, "Invalid CIBA ECDH recipient key agreement"
      end

      def ciba_encrypt_id_token(token, options)
        algorithm = options[:encryption_algorithm]
        method = options[:encryption_method]
        unless ALGORITHMS.include?(algorithm) && METHODS.include?(method)
          raise ConfigurationError, "Unsupported CIBA ID Token encryption"
        end
        if SYMMETRIC_ALGORITHMS.include?(algorithm)
          secret = ciba_id_token_encryption_secret(oauth_application: oauth_application)
          unless secret.is_a?(String) && secret.valid_encoding? && !secret.empty?
            raise ConfigurationError, "CIBA symmetric encryption requires the client secret"
          end
          bits = if algorithm == "dir"
            method[/HS(\d+)$/, 1] || method[/^A(\d+)/, 1]
          else
            algorithm[/^A(\d+)/, 1]
          end
          length = bits.to_i / 8
          digest = length <= 32 ? "SHA256" : length <= 48 ? "SHA384" : "SHA512"
          key = OpenSSL::Digest.digest(digest, secret.encode(Encoding::UTF_8))[0, length]
          require "jwe"
          return ciba_gcm_key_wrap(token, key, algorithm, method) if algorithm.end_with?("GCMKW")
          return JWE.encrypt(token, key, alg: algorithm, enc: method,
            cty: "JWT", iss: oauth_jwt_issuer, aud: oauth_jwt_audience)
        end
        jwks = options[:jwks]
        keys = jwks.is_a?(Hash) ? (jwks[:keys] || jwks["keys"]) : jwks
        candidates = Array(keys).select do |item|
          next false unless item.is_a?(Hash)
          candidate = item.transform_keys(&:to_s)
          ecdh = ECDH_ALGORITHMS.include?(algorithm)
          next false unless (ecdh ? %w[EC OKP].include?(candidate["kty"]) : candidate["kty"] == "RSA") &&
            (!candidate.key?("alg") || candidate["alg"] == algorithm) &&
            (!candidate.key?("use") || candidate["use"] == "enc") &&
            (ecdh || !candidate.key?("key_ops") || (candidate["key_ops"].is_a?(Array) &&
              candidate["key_ops"].include?("encrypt"))) &&
            (!candidate.key?("kid") || (candidate["kid"].is_a?(String) && !candidate["kid"].empty?))
          true
        end
        raise ProtocolError, "invalid_client_metadata" if candidates.empty?
        # node-oidc-provider scores explicit matching alg/use above omitted
        # metadata; equal scores retain registration order.
        recipient = candidates.each_with_index.min_by do |item, index|
          candidate = item.transform_keys(&:to_s)
          score = (candidate["alg"] == algorithm ? 1 : 0) + (candidate["use"] == "enc" ? 1 : 0)
          [-score, index]
        end&.first
        raise ConfigurationError, "No suitable CIBA ID Token recipient key" unless recipient
        recipient = recipient.transform_keys(&:to_s)
        headers = {cty: "JWT", iss: oauth_jwt_issuer, aud: oauth_jwt_audience}
        headers[:kid] = recipient["kid"] if recipient["kid"]
        # Load after Rodauth's feature initialization. The JWE backend is used
        # only here; upstream algorithm advertisement/authentication is unchanged.
        require "jwe"
        return ciba_ecdh_encrypt(token, recipient, algorithm, method, headers) if ECDH_ALGORITHMS.include?(algorithm)
        if recipient.key?("key_ops") && !recipient["key_ops"].include?("wrapKey")
          raise ConfigurationError, "CIBA RSA recipient key_ops must include wrapKey"
        end
        key = JWT::JWK.import(recipient).keypair
        raise ConfigurationError, "CIBA RSA recipient key must be at least 2048 bits" if key.n.num_bits < 2048
        JWE.encrypt(token, key.public_key,
          alg: algorithm, enc: method, **headers)
      end
    end
  end
end
