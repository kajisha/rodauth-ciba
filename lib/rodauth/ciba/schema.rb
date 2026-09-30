# frozen_string_literal: true

module Rodauth
  module CibaSupport
    # Explicit migration helper. Never called automatically on application startup.
    module Schema
      # Preserve the signed token's original subject across client sector changes.
      def self.add_pairwise_subject(db, table: :oauth_grants, column: :ciba_subject)
        db.alter_table(table) { add_column column, String, size: 255 }
      end

      # Lookup only: management credentials remain verified against upstream's
      # password hash. Existing clients have no digest until credentials are issued.
      def self.add_registration_token_digest(db, table: :oauth_applications, column: :ciba_registration_token_digest)
        db.alter_table(table) do
          add_column column, String, size: 64
          add_index column, unique: true
        end
      end

      def self.add_request_context(db, table: :ciba_requests, column: :request_context)
        db.alter_table(table) { add_column column, String, text: true }
      end

      # NULL preserves the output contract of already accepted requests/sources.
      def self.add_authentication_claims(db, table: :ciba_requests, column: :authentication_claims)
        db.alter_table(table) { add_column column, String, text: true }
      end

      def self.add_request_max_age(db, table: :ciba_requests, column: :max_age)
        db.alter_table(table) { add_column column, :bigint }
      end

      # NULL retains access_denied for previously denied requests.
      def self.add_completion_error(db, table: :ciba_requests, column: :completion_error)
        db.alter_table(table) { add_column column, String, text: true }
      end

      # Optional refresh sources are independent of collected access tokens and
      # request cleanup. Consumed digests remain until expiry for replay detection.
      # Creating storage does not enable protocol support.
      def self.create_refresh_tokens(db, table: :ciba_refresh_tokens, grants_table: :ciba_grants,
                                     accounts_table: :accounts, account_key: :id, account_type: Integer,
                                     applications_table: :oauth_applications, application_key: :id,
                                     application_type: Integer)
        db.create_table(table) do
          primary_key :id
          String :token_digest, size: 64, unique: true, null: false
          foreign_key :grant_id, grants_table, null: false, on_delete: :cascade
          foreign_key :account_id, accounts_table, key: account_key, type: account_type, null: false, on_delete: :cascade
          foreign_key :oauth_application_id, applications_table, key: application_key, type: application_type, null: false, on_delete: :cascade
          String :scopes, text: true, null: false
          %i[created_at issued_at expires_at].each { |name| Bignum name, null: false }
          Bignum :auth_time
          Bignum :consumed_at
          Integer :lock_version, null: false, default: 0
          Integer :rotations, null: false, default: 0
          %i[acr amr nonce authentication_claims requested_claims requested_resources requested_authorization_details].each do |name|
            String name, text: true
          end
          index :grant_id
          index :expires_at
        end
      end

      def self.add_ping(db, applications_table: :oauth_applications,
                        endpoint_column: :backchannel_client_notification_endpoint,
                        table: :ciba_ping_deliveries, requests_table: :ciba_requests, request_key: :id)
        db.alter_table(applications_table) { add_column endpoint_column, String, text: true }
        db.create_table(table) do
          foreign_key :request_id, requests_table, key: request_key, primary_key: true, null: false, on_delete: :cascade
          String :auth_req_id, null: false
          String :notification_token, text: true, null: false
          String :endpoint, text: true, null: false
        end
      end

      def self.add_user_code(db, table: :oauth_applications, column: :backchannel_user_code_parameter)
        db.alter_table(table) { add_column column, TrueClass }
      end

      def self.add_signed_requests(db, table: :oauth_applications,
                                   column: :backchannel_authentication_request_signing_alg)
        db.alter_table(table) { add_column column, String, size: 16 }
      end

      # Storage foundation for optional RAR; no backfill implies no permission.
      # Protocol activation is separate from this explicit migration.
      def self.add_authorization_details(db, requests_table: :ciba_requests,
                                        request_column: :requested_authorization_details,
                                        grants_table: :ciba_grants, tokens_table: :oauth_grants,
                                        applications_table: :oauth_applications)
        db.alter_table(requests_table) { add_column request_column, String, text: true }
        db.alter_table(grants_table) { add_column :authorization_details, String, text: true }
        db.alter_table(tokens_table) { add_column :ciba_authorization_details, String, text: true }
        db.alter_table(applications_table) { add_column :authorization_details_types, String, text: true }
      end

      # Optional resource indicators. Activate only after all workers are upgraded.
      def self.add_resources(db, requests_table: :ciba_requests, request_column: :requested_resources,
                            grants_table: :ciba_grants, tokens_table: :oauth_grants)
        db.alter_table(requests_table) { add_column request_column, String, text: true }
        db.alter_table(grants_table) { add_column :resources, String, text: true }
        db.alter_table(tokens_table) do
          add_column :ciba_resource, String, text: true
          add_column :ciba_resource_audience, String, text: true
        end
      end

      # Optional explicit-claims capability; run once after the base schema.
      def self.add_claims(db, requests_table: :ciba_requests, request_column: :requested_claims,
                         grants_table: :ciba_grants, tokens_table: :oauth_grants)
        db.alter_table(requests_table) { add_column request_column, String, text: true }
        db.alter_table(grants_table) { add_column :claims, String, text: true }
        db.alter_table(tokens_table) { add_column :ciba_claims, String, text: true }
      end

      # Forward migration for development schemas created before nonce support.
      def self.add_request_nonce(db, table: :ciba_requests, column: :nonce)
        db.alter_table(table) { add_column column, String, text: true }
      end

      def self.add_client_metadata(db, table: :oauth_applications, column: :backchannel_token_delivery_mode)
        db.alter_table(table) { add_column column, String, size: 8 }
      end

      # Shared replay ledger for JWT authentication by CIBA-capable clients.
      def self.create_client_assertions(db, table: :ciba_client_assertions)
        db.create_table(table) do
          String :digest, size: 64, primary_key: true, null: false
          Bignum :expires_at, null: false
          index :expires_at
        end
      end

      # Consent is separate from upstream OAuth grant rows, which also store tokens.
      def self.create_grants(db, table: :ciba_grants, accounts_table: :accounts,
                             account_key: :id, account_type: Integer,
                             applications_table: :oauth_applications, application_key: :id,
                             application_type: Integer)
        db.create_table(table) do
          primary_key :id
          foreign_key :account_id, accounts_table, key: account_key, type: account_type, null: false, on_delete: :cascade
          foreign_key :oauth_application_id, applications_table, key: application_key, type: application_type, null: false, on_delete: :cascade
          String :scopes, text: true, null: false
          Bignum :created_at, null: false
          Bignum :expires_at
          Bignum :revoked_at
        end
      end

      def self.add_grant_reference(db, table: :oauth_grants, column: :ciba_grant_id, grants_table: :ciba_grants)
        db.alter_table(table) { add_foreign_key column, grants_table, index: true, on_delete: :cascade }
      end

      def self.create(db, table: :ciba_requests, columns: {}, accounts_table: :accounts,
                      account_key: :id, account_type: Integer, applications_table: :oauth_applications,
                      application_key: :id, application_type: Integer, grants_table: :ciba_grants)
        col = ->(name) { columns.fetch(name, name) }
        db.create_table(table) do
          primary_key col[:id]
          String col[:auth_req_id_digest], size: 64, unique: true, null: false
          foreign_key col[:account_id], accounts_table, key: account_key, type: account_type, null: false, on_delete: :cascade
          foreign_key col[:oauth_application_id], applications_table, key: application_key, type: application_type, null: false, on_delete: :cascade
          foreign_key col[:grant_id], grants_table, on_delete: :cascade
          String col[:scopes], text: true, null: false
          String col[:status], size: 16, null: false, default: "pending"
          Integer col[:lock_version], null: false, default: 0
          %i[created_at expires_at].each { |name| Bignum col[name], null: false }
          %i[last_polled_at completed_at consumed_at auth_time max_age].each { |name| Bignum col[name] }
          Bignum col[:interval], null: false, default: 5
          %i[binding_message acr_values acr amr nonce authentication_claims completion_error].each { |name| String col[name], text: true }
          index [col[:status], col[:id]]
          index col[:expires_at]
          check(Sequel[col[:interval]] > 0)
          check(Sequel[col[:lock_version]] >= 0)
          check(Sequel[col[:status]] => %w[pending approved denied consumed])
        end
      end
    end
  end
end
