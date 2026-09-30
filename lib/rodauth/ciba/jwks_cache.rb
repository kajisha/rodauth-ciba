# frozen_string_literal: true
require "time"
require "json"

module Rodauth
  module CibaSupport
    # Application-scoped JWKS cache. Ordinary HTTP caching remains delegated.
    # The separate entries retain explicit stale allowances without depending on
    # upstream TtlStore internals. Replacing an entry invalidates in-flight snapshots.
    class JwksCache
      class StatusError < HTTP::Error
        attr_reader :status
        def initialize(status)
          @status = status
          super("JWKS retrieval failed")
        end
      end
      LIMIT = 1024

      def initialize(upstream)
        @upstream, @entries, @mutex = upstream, {}, Mutex.new
      end

      def [](key)
        @upstream[key]
      end

      def set(key, &block)
        @upstream.set(key, &block)
      end

      def uncache(key)
        @mutex.synchronize { @entries.delete(key) }
        @upstream.uncache(key)
      end

      def fetch(key)
        snapshot = @mutex.synchronize do
          @entries.delete_if { |_uri, entry| entry[:until] && entry[:until] <= now }
          entry = @entries[key]
          return entry[:payload] if entry && entry[:fresh] && now < entry[:fresh]
          unless entry
            @entries.shift while @entries.size >= LIMIT
            entry = @entries[key] = {}
          end
          entry
        end
        started = now
        response = yield
        received, wall = now, Time.now.to_f
        raise StatusError, response.code.to_i unless response.code.to_i == 200
        payload = JSON.parse(response.body, symbolize_names: true)
        unless payload.is_a?(Hash) && payload[:keys].is_a?(Array) && payload[:keys].all? { |jwk| jwk.is_a?(Hash) }
          raise HTTP::Error, "invalid remote JWKS"
        end
        lifetime, grace = policy(response, wall, received - started)
        replacement = {payload: payload, fresh: received + lifetime, until: received + lifetime + grace}
        @mutex.synchronize do
          if @entries[key].equal?(snapshot)
            if replacement[:until] > now
              @entries[key] = replacement
            else
              @entries.delete(key)
            end
          else
            # A newer fetch/eviction wins. Never return the older fetched keys.
            newer = @entries[key]
            return newer[:payload] if newer && newer[:fresh] && now < newer[:fresh]
            raise HTTP::Error, "JWKS changed during retrieval"
          end
        end
        payload
      rescue StatusError, Timeout::Error => error
        transient = error.is_a?(Timeout::Error) || [500, 502, 503, 504].include?(error.status)
        @mutex.synchronize do
          entry = @entries[key]
          if transient && entry.equal?(snapshot) && entry[:payload] && now < entry[:until]
            return entry[:payload]
          end
          # A newer successful fetch can satisfy this call, but stale snapshots
          # cannot survive eviction or a concurrent invalidating response.
          if transient && entry && !entry.equal?(snapshot) && entry[:fresh] && now < entry[:fresh]
            return entry[:payload]
          end
          @entries.delete(key) if !transient && entry.equal?(snapshot)
        end
        raise
      rescue StandardError
        @mutex.synchronize { @entries.delete(key) if @entries[key].equal?(snapshot) }
        raise
      end

      private

      def now
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end

      def policy(response, wall, delay)
        directives = {}
        # Split outside quoted strings; ambiguous syntax/duplicates disable reuse.
        parts = response["cache-control"].to_s.split(/,(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)/)
        parts.each do |part|
          match = /\A\s*([!#$%&'*+.^_`|~0-9A-Za-z-]+)(?:\s*=\s*("[^"\\]*"|[!#$%&'*+.^_`|~0-9A-Za-z-]+))?\s*\z/.match(part)
          return [0, 0] unless match
          name = match[1].downcase
          return [0, 0] if directives.key?(name)
          directives[name] = match[2]&.delete_prefix('"')&.delete_suffix('"')
        end
        return [0, 0] if directives.key?("no-store") || directives.key?("no-cache")
        # Do not cache variant responses without a full Vary-aware cache key.
        return [0, 0] if response["vary"] && !response["vary"].strip.empty?
        numeric = lambda do |name|
          value = directives[name]
          value && /\A\d+\z/.match?(value) ? value.to_i : nil
        end
        date = response["date"] ? Time.httpdate(response["date"]).to_f : wall
        age = response["age"] || "0"
        return [0, 0] unless /\A\d+\z/.match?(age)
        current_age = [[wall - date, 0].max, age.to_i + delay].max
        lifetime = if directives.key?("max-age")
          numeric.call("max-age") or return [0, 0]
        elsif response["expires"]
          Time.httpdate(response["expires"]).to_f - date
        else
          # No heuristic reuse: absent explicit freshness means fetch on demand.
          return [0, 0]
        end
        if directives.key?("s-maxage")
          shared_lifetime = numeric.call("s-maxage")
          return [0, 0] unless shared_lifetime
          lifetime = [lifetime, shared_lifetime].min
        end
        grace = if directives.key?("must-revalidate") || directives.key?("proxy-revalidate") || directives.key?("s-maxage")
          0
        elsif directives.key?("stale-if-error")
          allowance = numeric.call("stale-if-error")
          return [0, 0] unless allowance
          [allowance, 60].min
        else
          0
        end
        [lifetime - current_age, grace]
      rescue ArgumentError
        [0, 0]
      end
    end
  end
end
