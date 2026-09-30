# frozen_string_literal: true
require_relative "test_helper"
require "rodauth/ciba/authorization_details"

class AuthorizationDetailsTest < Minitest::Test
  Details = Rodauth::CibaSupport::AuthorizationDetails

  def test_preserves_typed_data_without_inventing_authorization_semantics
    value = [{"type" => "payment", "actions" => ["initiate"],
      "amount" => {"currency" => "JPY", "value" => "123.00"}, "custom" => [nil, true, 5]}]
    parsed = Details.parse(JSON.generate(value))
    assert_equal value, parsed
    assert_equal [], Details.parse("[]")
    assert_raises(FrozenError) { parsed << {} }
    assert_raises(FrozenError) { parsed.first["actions"] << "cancel" }
    assert_raises(FrozenError) { parsed.first["amount"]["value"].replace("999") }
    assert_raises(FrozenError) { parsed.first["type"] = "other" }
  end

  def test_rejects_invalid_json_and_common_shapes
    ["{", "null", "{}", "[null]", "[1]", '[{"type":1}]', '[{"type":""}]',
      '[{"actions":["read"]}]', '[{"type":"files","identifier":""}]'].each do |json|
      assert_raises(Details::Invalid, json) { Details.parse(json) }
    end
    %w[locations actions datatypes privileges].each do |field|
      [nil, "read", [""], [1], [{}]].each do |value|
        assert_raises(Details::Invalid) { Details.parse(JSON.generate([{type: "files", field => value}])) }
      end
    end
  end

  def test_rejects_duplicate_keys_at_every_depth
    ['[{"type":"files","type":"payment"}]',
      '[{"type":"payment","amount":{"value":1,"value":999}}]',
      '[{"type":"files","actions":["read"],"actions":["delete"]}]'].each do |json|
      assert_raises(Details::Invalid) { Details.parse(json) }
    end
  end

  def test_bounds_size_depth_count_and_encoding
    assert_raises(Details::Invalid) { Details.parse(nil) }
    assert_raises(Details::Invalid) { Details.parse("\xFF".dup.force_encoding(Encoding::UTF_8)) }
    assert_raises(Details::Invalid) { Details.parse("[{\"type\":\"\xFF\"}]".b) }
    assert_equal "顧客", Details.parse(JSON.generate([{type: "顧客"}]).b).first.fetch("type")
    assert_raises(Details::Invalid) { Details.parse(JSON.generate([{type: "x", blob: "x" * 8192}])) }
    assert_raises(Details::Invalid) { Details.parse(JSON.generate(Array.new(33) { {type: "x"} })) }
    value = {type: "x", nested: 11.times.reduce(nil) { |nested, _| {child: nested} }}
    assert_raises(Details::Invalid) { Details.parse(JSON.generate([value])) }
    assert_equal 32, Details.parse(JSON.generate(Array.new(32) { {type: "x"} })).size
  end
end

class CibaIntegrationTest
  def test_rar_schema_migration_preserves_legacy_data_and_empty_permissions
    id = accept_request
    approve(id)
    assert_equal 200, poll(id).status
    before = %i[ciba_requests ciba_grants oauth_grants oauth_applications].to_h { |table| [table, @db[table].first] }
    Rodauth::CibaSupport::Schema.add_authorization_details(@db)
    expected_columns = {ciba_requests: :requested_authorization_details, ciba_grants: :authorization_details,
      oauth_grants: :ciba_authorization_details, oauth_applications: :authorization_details_types}
    expected_columns.each do |table, column|
      row = @db[table].first
      assert row.key?(column)
      assert_nil row.delete(column)
      assert_equal before.fetch(table), row
    end
    assert_error poll(id), "invalid_grant"
  end
end
