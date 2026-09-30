# frozen_string_literal: true
require "ipaddr"
require "net/http"
require "socket"
require "timeout"

module Rodauth
  module CibaSupport
    module HTTP
      class Error < StandardError; end
      # Based on the reference provider's special-use ranges; also block multicast
      # and IPv4-compatible IPv6. IPAddr handles mapped addresses without text tricks.
      BLOCKED = %w[
        0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16
        172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.31.196.0/24
        192.52.193.0/24 192.88.99.0/24 192.168.0.0/16 192.175.48.0/24
        198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4
        ::/96 64:ff9b::/96 64:ff9b:1::/48 100::/64 100:0:0:1::/64
        2001::/23 2001:db8::/32 2002::/16 2620:4f:8000::/48 3fff::/20
        5f00::/16 fc00::/7 fe80::/10 ff00::/8
      ].map { |range| IPAddr.new(range) }.freeze
      TIMEOUT = 2.5
      MAX_BODY_BYTES = 65_536

      def self.public_address?(address)
        return false unless address.is_a?(String) && !address.include?("%") && !address.include?("/")
        ip = IPAddr.new(address)
        ip = ip.native if ip.ipv4_mapped?
        BLOCKED.none? { |range| range.include?(ip) }
      rescue IPAddr::InvalidAddressError
        false
      end

      def self.request(uri, request, address_allowed: method(:public_address?), read_body: true)
        uri = URI(uri.to_s)
        unless %w[http https].include?(uri.scheme) && uri.hostname && !uri.hostname.empty? && !uri.userinfo && !uri.fragment
          raise Error, "invalid outbound URI"
        end
        Timeout.timeout(TIMEOUT) do
          addresses = Addrinfo.getaddrinfo(uri.hostname, uri.port, nil, :STREAM).map(&:ip_address).uniq
          raise Error, "outbound address rejected" if addresses.empty? || addresses.any? { |address| address_allowed.call(address) != true }
          # Disable ambient proxies: otherwise the validated IP would not be the peer.
          http = Net::HTTP.new(uri.hostname, uri.port, nil)
          http.ipaddr = addresses.first
          http.use_ssl = uri.scheme == "https"
          http.open_timeout = http.read_timeout = http.write_timeout = TIMEOUT
          result = nil
          http.start do |connection|
            connection.request(request) do |response|
              # Nonlocal return unwinds Net::HTTP.start's ensure and closes the
              # socket without its normal implicit response-body drain.
              return response unless read_body
              body = +""
              response.read_body do |chunk|
                raise Error, "outbound response too large" if body.bytesize + chunk.bytesize > MAX_BODY_BYTES
                body << chunk
              end
              response.body = body
              result = response
            end
          end
          result
        end
      rescue URI::InvalidURIError
        raise Error, "invalid outbound URI"
      end
    end
  end
end
