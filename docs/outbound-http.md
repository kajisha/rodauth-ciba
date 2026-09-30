# CIBA outbound HTTP boundary

Signed CIBA request JWKS fetching and protected CIBA-client assertion JWKS
fetching use a dedicated transport boundary while retaining upstream's
registered-key lookup and cache. Unrelated OAuth clients keep their existing
HTTP behavior. Optional ping uses the same boundary with its own
HTTPS endpoint validation.

The default `ciba_http_address_allowed?(address)` rejects special-use address
ranges, including private/loopback/link-local addresses, multicast and mapped
IPv4 equivalents. IPAddr parses addresses; text prefixes are not trusted.
Every DNS answer must pass policy. The connection is pinned to the first
validated address via Net::HTTP#ipaddr while retaining the original hostname
for Host and TLS verification. Ambient HTTP proxies are disabled so they cannot
bypass that destination check. The shared request primitive does not follow
redirects. Sector-document fetching explicitly follows up to 20 redirects,
repeating the same destination checks at every hop under one 2.5-second deadline.
Ping and JWKS fetching retain their existing refusal to follow redirects.

For JWKS and sector documents the transport bounds response bodies to 65536 bytes.
Ping needs only the response status: it closes the connection immediately after
headers without reading or draining the body. The transport uses a 2.5-second outer
Ruby timeout, as well as connection/read/write timeouts. Registered JWKS URIs
retain upstream's HTTP/HTTPS scheme support; production registrations should
use HTTPS. Userinfo, fragments and other URI schemes are rejected. Transport
validation failures are invalid_request for signed CIBA authentication requests
and invalid_client for JWT client authentication. They do not save pending work.

If an application deliberately needs an internal endpoint, override
`ciba_http_address_allowed?` narrowly for that deployment. Returning true allows
that resolved address. There is no default private-network exception. The
loopback JWKS fixture overrides only 127.0.0.1 on its test app; this is not a
production recommendation. Operators must account for the separate risk of
which clients may register destinations, and retain their egress controls.

Compared with node's connected-socket guard, the gem validates all DNS answers
and pins one before connection. It additionally rejects multicast and
IPv4-compatible IPv6. It does not implement multi-address connection fallback.
The allow-policy applies when a network lookup happens; an already cached JWKS
remains usable until upstream cache invalidation/expiry. Network refusal alone
is therefore not a key-revocation mechanism.

Tests cover IP ranges/mapped forms, default loopback refusal before any receiver
request, mixed DNS answers, hostname/TLS configuration and IP pinning, real
loopback cache/rotation/error behavior under a narrow test exception, and an
oversized response. The DNS pinning test inspects the configured Net::HTTP
client; it is not an adversarial live DNS-rebinding experiment. Installed-gem
ping tests directly verify untrusted TLS rejection and a stalled receiver's
timeout; saved approval survives. Hostname mismatch and expired certificates
remain unverified.
The independent node ping harness separately verifies real TLS notifications
and default loopback rejection; do not transfer that evidence to the gem.
