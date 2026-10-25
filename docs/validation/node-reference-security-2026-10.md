# Reference Node runtime security update (2026-10-25)

This updates the development/reference runtime for CVE-2026-111497.
The [Node.js advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
identifies the bundled Brotli decoder issue and patched releases 22.23.4,
24.22.1 and 26.12.1. The full OP harness uses `fetch`, so its runtime is
updated even though no malformed Brotli test or exploit was attempted.
No direct Brotli dependency was found in the Ruby gem's production dependencies;
this is not evidence of a production gem vulnerability.

## Official image verification

Docker Hub's `library/node` registry was queried on 2026-10-25 with an anonymous
pull token from `auth.docker.io`. The tag endpoint was
`https://registry-1.docker.io/v2/library/node/manifests/24.22.1-bookworm-slim`.
The exact returned OCI index bytes were SHA-256 hashed and matched the
`Docker-Content-Digest` header. The linux/amd64 child manifest and its config
blob were fetched by digest and their raw byte hashes also matched.
The config contains `NODE_VERSION=24.22.1`.

- Pinned tag: `node:24.22.1-bookworm-slim`
- OCI index: `sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205`
- linux/amd64 manifest: `sha256:2dd9a4f758e173b65fee15388f7706af6fb01ef50cf7a2c0538711d67a6981ae`

The same verification was also performed for `node:26.12.1-bookworm-slim`:
index `sha256:28147155d47dc31abe0a46e0d12b59b2fb3d0a2dcc5dc65fce76a074180b16fe`,
linux/amd64 manifest `sha256:1884ec272c7c06aba7696262fb822dc602f8fa5eb978d03617d6bfe487d7ebac`,
config `NODE_VERSION=26.12.1`. This diagnostic alternative is not the selected
runtime because this provider version warns on Node26.

The mTLS runner and both Docker reproduction commands now use the explicit
24.22.1 tag and verified OCI index digest. The dependency lockfile, provider
version, test behavior and Ruby CI configuration are unchanged.

## Fresh validation

A portable official `node-v24.22.1-win-x64.zip` was downloaded under the task's
temporary directory and verified against the release's `SHASUMS256.txt` over
HTTPS. Archive SHA-256:
`d2046d28c2c3dcd211ac5145c0bf30e2047ef9dfb306693c8c6e2eccd8b95fa5`.
It reported `v24.22.1`; the global Node installation was unchanged.

- `npm ci --ignore-scripts --no-audit --no-fund`: exit 0, 40 packages installed.
- `npm test` in `test/reference/full-op`: exit 0, 469 PASS lines. Used the
  portable Windows runtime and existing Git OpenSSL for owned loopback fixtures.
  [New full output](node-full-op-24.22.1-windows.txt).
- `node --experimental-vm-modules test/reference/lifecycle.mjs`: exit 0.
  [New isolated-harness output](node-reference-lifecycle-24.22.1-windows.txt).
- `node --check` on all 30 reference `.mjs` files: exit 0.
- `git diff --check`: exit 0.

The pinned Linux Docker image was verified as registry data, not executed.
Docker and Ruby were unavailable, so `bin/test-mtls-reference` and the Ruby/DB
matrix were not run locally. `bash -n bin/test-mtls-reference` failed before
parsing because Git Bash could not create its MSYS object (`0xC0000022`, access
denied); it was not retried. WSL was not accessed. The shell change is limited
to the image reference. Existing CI runs the Ruby matrix and database job; it
does not execute the Node reference harness.

All older validation logs and dated research results remain unchanged as
historical evidence. In particular, the old Node24.21.0 and Node26.5.0 logs do
not establish validation of the new image. No PoC, malformed Brotli input,
system installation, deployment, gem publication or merge was performed.
