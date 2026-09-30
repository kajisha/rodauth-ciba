# frozen_string_literal: true
# Temporary local-only certificates for the real TLS reference fixture.
require "openssl"
require "fileutils"
directory = ARGV.fetch(0)
FileUtils.mkdir_p(directory)
server_key = OpenSSL::PKey::RSA.generate(2048)
client_key = OpenSSL::PKey::RSA.generate(2048)
def certificate(key, common_name, serial, server: false)
  cert = OpenSSL::X509::Certificate.new
  cert.version = 2
  cert.serial = serial
  cert.subject = cert.issuer = OpenSSL::X509::Name.parse("/CN=#{common_name}")
  cert.public_key = key.public_key
  cert.not_before = Time.now - 60
  cert.not_after = Time.now + 3600
  extensions = OpenSSL::X509::ExtensionFactory.new
  extensions.subject_certificate = extensions.issuer_certificate = cert
  cert.add_extension(extensions.create_extension("basicConstraints", "CA:TRUE", true))
  cert.add_extension(extensions.create_extension("keyUsage", "digitalSignature,keyEncipherment,keyCertSign", true))
  cert.add_extension(extensions.create_extension("extendedKeyUsage", server ? "serverAuth" : "clientAuth"))
  cert.add_extension(extensions.create_extension("subjectAltName", "IP:127.0.0.1,DNS:localhost")) if server
  cert.sign(key, OpenSSL::Digest.new("SHA256"))
end
File.write(File.join(directory, "server-key.pem"), server_key.to_pem, perm: 0600)
File.write(File.join(directory, "server.pem"), certificate(server_key, "localhost", 1, server: true).to_pem)
File.write(File.join(directory, "client-key.pem"), client_key.to_pem, perm: 0600)
File.write(File.join(directory, "client.pem"), certificate(client_key, "client", 2).to_pem)
File.write(File.join(directory, "same-key-other-cert.pem"), certificate(client_key, "client", 3).to_pem)
