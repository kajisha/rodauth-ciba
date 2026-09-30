# frozen_string_literal: true
require_relative "lib/rodauth/ciba/version"

Gem::Specification.new do |spec|
  spec.name = "rodauth-ciba"
  spec.version = Rodauth::CibaSupport::VERSION
  spec.authors = ["rodauth-ciba contributors"]
  spec.summary = "CIBA poll/ping OpenID Provider extension for rodauth-oauth"
  spec.description = "Adds backchannel authentication, Ruby completion APIs, transactional hooks and observation events to rodauth-oauth."
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.3"
  spec.files = Dir["lib/**/*.rb", "examples/**/*", "docs/api.md", "docs/protocol-coverage.md", "docs/operations.md", "docs/release-validation.md", "docs/requirements-audit.md", "docs/requirements-audit.json", "docs/security-review.md", "docs/node-alignment.md", "docs/research/node-oidc-provider-comparison.md", "docs/research/node-ciba-lifecycle.md", "docs/validation/node-alignment-tests.txt"] +
               %w[README.md LICENSE CHANGELOG.md docs/failure-contract.md docs/alignment-roadmap.md docs/claims.md docs/research/claims-reference-contract.md docs/research/consent-api-evolution.md docs/research/completion-error-boundaries.md docs/adr/0003-follow-rodauth-hook-conventions.md docs/adr/0004-retain-atomic-issuance-and-stage-alignment.md]
  spec.files += %w[docs/resources.md docs/authorization-details.md docs/research/resource-reference-contract.md docs/research/rar-reference-contract.md]
  spec.require_paths = ["lib"]
  spec.files << "docs/login-hint-token.md"
  spec.files << "docs/id-token-hint.md"
  spec.files << "docs/id-token-encryption.md"
  spec.files << "docs/user-code.md"
  spec.files += %w[docs/requirements-audit-current.md docs/requirements-audit-current.json]
  spec.files << "docs/request-context.md"
  spec.files += %w[docs/authentication-claims.md docs/max-age.md docs/alignment-closeout.md]
  spec.files += %w[docs/research/required-parameter-inventory.md docs/research/request-parameter-inventory.md docs/research/alignment-partial-triage.md]
  spec.files << "docs/research/registration-reference-contract.md"
  spec.files << "docs/research/pairwise-reference-contract.md"
  spec.files << "docs/pairwise.md"
  spec.files += %w[docs/refresh-tokens.md docs/research/refresh-reference-contract.md]
  spec.files << "docs/research/access-token-revocation-reference.md"
  spec.files << "docs/outbound-http.md"
  spec.files += %w[docs/ping.md docs/research/ping-reference-contract.md]
  spec.files += %w[docs/signed-requests.md docs/research/signed-request-reference-contract.md]
  spec.files << "docs/research/id-token-hint-reference-contract.md"
  spec.files << "docs/research/dpop-reference-contract.md"
  spec.files << "docs/research/mtls-reference-contract.md"
  spec.files << "docs/research/client-assertion-algorithm-contract.md"
  spec.metadata["rubygems_mfa_required"] = "true"
  spec.add_dependency "rodauth-oauth", "= 1.7.0"
  spec.add_dependency "rodauth", "~> 2.28.0"
  spec.add_dependency "sequel", "~> 5.108.0"
  spec.add_dependency "jwt", "~> 3.3.0"
  spec.add_dependency "jwe", "~> 1.1.1"
  spec.add_dependency "json", "~> 2.18"
  spec.add_dependency "bcrypt", "~> 3.1"
end
