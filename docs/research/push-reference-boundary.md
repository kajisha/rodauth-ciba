# Push is outside the reference implementation's delivery modes

The selected released node-oidc-provider 9.12.2 accepts only poll and ping in
`features.ciba.deliveryModes`. `lib/helpers/configuration.js` validates this at
provider construction; the live registration fixture now directly asserts that
configuring push throws its supported-mode error. The existing HTTP DCR test
also rejects client push metadata.

The gem likewise does not advertise push, rejects push DCR metadata without
inserting a client, and rejects static push clients at the Backchannel endpoint.
A new regression changes an existing approved request's client to push and
verifies token-endpoint unauthorized_client, no request mutation and no grant.

- [Node 24 configuration and HTTP registration execution](../validation/node-push-boundary.txt)
- [Gem boundary execution: 5 tests / 55 assertions](../validation/push-boundary-audit-current.txt)

Consequently the audit preserves all push requirement IDs, but labels the
conditional delivery/claim/callback requirements reference_unsupported. This
means no push implementation has been tested or declared conformant. It does
not silently discard requirements or count absent functionality as passing.
External push client duties remain client_only; token-endpoint refusal has its
own direct evidence. Revisit these conditions if the selected reference or the
requested enabled modes change. Pairwise poll/ping, mTLS and refresh remain
independently in scope; their implementation does not imply push support.
