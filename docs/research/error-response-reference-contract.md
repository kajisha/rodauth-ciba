# CIBA error response boundaries

A new HTTP-envelope regression exposed an early authentication response without
Cache-Control. The response halted in upstream authentication before ciba_error
could add headers. The CIBA HTTP wrapper now sets Cache-Control: no-store and
Pragma: no-cache before executing its body. Ordinary OAuth paths continue to
use their existing handling; no global OP policy was changed.

The pinned node 9.12.2 real HTTP fixture verifies wrong Basic credentials at
Backchannel and token endpoints: HTTP401 invalid_client with no-store, but no
Pragma header. The gem retains its existing Pragma policy. The original comparison found that omitting all client identity gave HTTP400
in node, unlike the gem's HTTP401. The correction below aligns that boundary.

- [Initial cache-header failure](../validation/error-cache-red.txt)
- [Node 24 wire response](../validation/node-error-cache.txt)
- [Three databases](../validation/error-cache-matrix.txt): each 30 tests / 590
  assertions, no failures/errors/skips, including Basic and mTLS token rejection.

The new envelope test checks missing/invalid inputs, unresolved user, invalid
binding message, missing authentication, and an injected internal exception.
No access/ID/refresh token, public request identifier, error_uri or private
exception text is returned. Description ASCII handling remains covered by
separate customization tests. This does not establish arbitrary application
error_uri validation or an exhaustive error mapping for every extension.

## Missing identity versus failed authentication

The reference HTTP fixture now asserts both endpoints return400 invalid_request
without WWW-Authenticate when all client identity is absent. Wrong Basic
credentials remain401 invalid_client. The gem now follows this distinction only
on the backchannel endpoint and CIBA token grant. An assertion can still identify
the client through its subject without a separate client_id. Presented invalid
assertions or Basic credentials continue through existing authentication errors.
Refresh, revocation and non-CIBA grants retain their previous upstream routing.

[Reference execution](../validation/node-missing-client.txt),
[before correction](../validation/missing-client-red.txt),
[three-DB regression](../validation/missing-client-matrix.txt).
This establishes absent identity and the tested authentication failures, not
identical precedence for every combination of malformed parameters.
