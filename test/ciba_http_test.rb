# frozen_string_literal: true
require_relative "test_helper"
require "rodauth/ciba/http"
require "minitest/mock"

class CibaHTTPTest < Minitest::Test
  HTTP = Rodauth::CibaSupport::HTTP

  def test_special_use_addresses_and_mapped_forms
    %w[127.0.0.1 10.1.2.3 172.16.1.1 192.168.1.1 169.254.169.254 100.64.0.1
       192.0.2.1 198.18.0.1 224.0.0.1 255.255.255.255 :: ::1 ::ffff:127.0.0.1
       ::ffff:7f00:1 ::127.0.0.1 fe80::1 fc00::1 ff02::1 64:ff9b::7f00:1 2001:db8::1
       2002:7f00:1:: fe80::1%lo0 127.0.0.1/8 bad].each { |ip| refute HTTP.public_address?(ip), ip }
    %w[1.1.1.1 8.8.8.8 2606:4700:4700::1111 ::ffff:8.8.8.8].each { |ip| assert HTTP.public_address?(ip), ip }
  end

  def test_uri_and_loopback_rejected_before_any_connection
    %w[file:///etc/passwd ftp://example.test/ https://user:pass@example.test/ https://example.test/#x http://127.0.0.1:1/].each do |uri|
      assert_raises(HTTP::Error) { HTTP.request(uri, Net::HTTP::Get.new("/")) }
    end
  end

  def test_dns_address_is_pinned_while_hostname_and_tls_are_preserved
    client = Net::HTTP.new("keys.example.test", 443, nil)
    response = Struct.new(:body).new
    response.define_singleton_method(:read_body) { |&block| block.call("{}") }
    client.define_singleton_method(:start) { |&block| block.call(self) }
    client.define_singleton_method(:request) { |_request, &block| block.call(response) }
    resolver_calls = 0
    resolver = ->(host, port, *_args) { resolver_calls += 1; assert_equal "keys.example.test", host; assert_equal 443, port; [Addrinfo.ip("8.8.8.8")] }
    factory = ->(host, port, proxy) { assert_equal "keys.example.test", host; assert_equal 443, port; assert_nil proxy; client }
    Addrinfo.stub(:getaddrinfo, resolver) do
      Net::HTTP.stub(:new, factory) do
        result = HTTP.request("https://keys.example.test/jwks", Net::HTTP::Get.new("/jwks"))
        assert_equal "{}", result.body
      end
    end
    assert_equal 1, resolver_calls
    assert_equal "8.8.8.8", client.ipaddr
    assert_equal "keys.example.test", client.address
    assert client.use_ssl?
  end

  def test_header_only_response_closes_without_waiting_for_body
    server = TCPServer.new("127.0.0.1", 0)
    worker = Thread.new do
      socket = server.accept
      begin
        while (line = socket.gets) && line != "\r\n"
        end
        socket.write("HTTP/1.1 200 OK\r\nContent-Length: 10000000\r\n\r\n")
        # No body is sent: reading or draining it would hang until the timeout.
        begin
          socket.read(1).nil?
        rescue Errno::ECONNRESET
          true
        end
      ensure
        socket.close
      end
    end
    uri = URI("http://127.0.0.1:#{server.addr[1]}/notify")
    response = HTTP.request(uri, Net::HTTP::Get.new("/notify"), read_body: false,
      address_allowed: ->(address) { address == "127.0.0.1" })
    assert_equal "200", response.code
    assert_equal true, Timeout.timeout(5) { worker.value }
  ensure
    server&.close
    worker&.kill if worker&.alive?
    worker&.join
  end

  def test_mixed_public_private_dns_answers_rejected_before_http_creation
    Addrinfo.stub(:getaddrinfo, [Addrinfo.ip("8.8.8.8"), Addrinfo.ip("127.0.0.1")]) do
      Net::HTTP.stub(:new, ->(*) { flunk "must not connect to mixed DNS answers" }) do
        assert_raises(HTTP::Error) { HTTP.request("https://keys.example.test/", Net::HTTP::Get.new("/")) }
      end
    end
  end
end
