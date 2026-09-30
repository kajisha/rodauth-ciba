# frozen_string_literal: true
# Copy into your app's Sequel migrations after accounts/oauth_applications exist.
require "rodauth/ciba/schema"
Sequel.migration do
  up do
    Rodauth::CibaSupport::Schema.add_client_metadata(self)
    Rodauth::CibaSupport::Schema.create_grants(self)
    Rodauth::CibaSupport::Schema.add_grant_reference(self)
    Rodauth::CibaSupport::Schema.create(self)
    Rodauth::CibaSupport::Schema.create_client_assertions(self)
  end
  down do
    drop_table(:ciba_requests, :ciba_client_assertions)
    alter_table(:oauth_grants) { drop_foreign_key :ciba_grant_id }
    drop_table(:ciba_grants)
    alter_table(:oauth_applications) { drop_column :backchannel_token_delivery_mode }
  end
end
