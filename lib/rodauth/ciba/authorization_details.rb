# frozen_string_literal: true
require "json"

module Rodauth
  module CibaSupport
    # Structural validation only. Type registration, client eligibility and
    # permission narrowing belong to the application/protocol integration.
    module AuthorizationDetails
      class Invalid < ArgumentError; end

      ARRAY_FIELDS = %w[locations actions datatypes privileges].freeze
      MAX_BYTES = 8192
      MAX_ENTRIES = 32
      MAX_NESTING = 10

      def self.parse(json)
        unless json.is_a?(String) && json.bytesize <= MAX_BYTES
          raise Invalid, "invalid authorization-details JSON"
        end
        json = json.dup.force_encoding(Encoding::UTF_8)
        raise Invalid, "invalid authorization-details encoding" unless json.valid_encoding?
        data = immutable(JSON.parse(json, max_nesting: MAX_NESTING, allow_duplicate_key: false))
        unless data.is_a?(Array) && data.size <= MAX_ENTRIES
          raise Invalid, "authorization details must be a bounded array"
        end
        data.each do |detail|
          unless detail.is_a?(Hash) && nonempty_string?(detail["type"])
            raise Invalid, "authorization detail must have a type"
          end
          ARRAY_FIELDS.each do |field|
            next unless detail.key?(field)
            values = detail[field]
            unless values.is_a?(Array) && values.all? { |value| nonempty_string?(value) }
              raise Invalid, "invalid authorization-details array field"
            end
          end
          if detail.key?("identifier") && !nonempty_string?(detail["identifier"])
            raise Invalid, "invalid authorization-details identifier"
          end
        end
        data
      rescue JSON::ParserError
        raise Invalid, "invalid authorization-details JSON"
      end

      def self.nonempty_string?(value)
        value.is_a?(String) && !value.empty?
      end

      def self.immutable(value)
        case value
        when Hash then value.to_h { |key, item| [key.freeze, immutable(item)] }.freeze
        when Array then value.map { |item| immutable(item) }.freeze
        else value.freeze
        end
      end
      private_class_method :nonempty_string?, :immutable
    end
  end
end
