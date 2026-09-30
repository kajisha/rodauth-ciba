# frozen_string_literal: true
require_relative "ciba_signed_request_test"

class CibaIntegrationTest
  def test_max_age_normalization_precedence_and_saved_policy
    @db.alter_table(:oauth_applications) { add_column :default_max_age, :bigint }
    {nil => 60, "" => 60, "0" => 0, "-0" => 0, " " => 0, "60" => 60,
     "1.0" => 1, "1." => 1, "1.e2" => 100, "1e2" => 100, "0x10" => 16,
     "0b10" => 2, "0o10" => 8, "\uFEFF1\u00A0" => 1}.each do |input, expected|
      @db[:oauth_applications].update(default_max_age: 60)
      params = {scope: "openid", login_hint: "customer@example.test"}
      params[:max_age] = input unless input.nil?
      seen = []
      response = post("/backchannel-authentication", params, "test.device" => ->(row, _) { seen << row })
      assert_equal 200, response.status, response.body
      assert_equal expected, seen.last[:max_age]
      assert seen.last.frozen?
      row_id = seen.last.fetch(:id)
      @db[:oauth_applications].update(default_max_age: 999)
      assert_equal expected, auth.ciba_request(row_id)[:max_age]
      id = JSON.parse(response.body).fetch("auth_req_id")
      # Like the reference, the core does not enforce the application's freshness decision.
      approve(id, auth_time: 123)
      assert_equal 123, decode_id_token(poll(id)).last.fetch("auth_time")
    end
    @db[:oauth_applications].update(default_max_age: nil)
    response = post("/backchannel-authentication", scope: "openid", login_hint: "customer@example.test")
    assert_equal 200, response.status, response.body
    assert_nil @db[:ciba_requests].order(:id).last[:max_age]
  end

  def test_max_age_invalid_values_do_not_dispatch_or_persist
    seen = []
    ["-1", "1.5", "NaN", "Infinity", "9007199254740992", "1_0", "0x", "\u00851", ["60"]].each do |input|
      response = post("/backchannel-authentication", {scope: "openid", login_hint: "customer@example.test", max_age: input},
        "test.device" => ->(row, _) { seen << row })
      assert_error response, "invalid_request"
    end
    assert_empty seen
    assert_equal 0, @db[:ciba_requests].count
  end

  def test_max_age_signed_values_are_isolated_from_unsigned_values
    enable_signed_requests
    [0, 1.0, "1e2"].each do |value|
      response = post("/backchannel-authentication", request: signed_ciba_request({max_age: value}), max_age: "999")
      assert_equal 200, response.status, response.body
      assert_equal Float(value).to_i, @db[:ciba_requests].order(:id).last[:max_age]
    end
    [nil, true, [], -1].each do |value|
      before = @db[:ciba_requests].count
      assert_error post("/backchannel-authentication", request: signed_ciba_request({max_age: value}), max_age: "60"), "invalid_request"
      assert_equal before, @db[:ciba_requests].count
    end
    response = post("/backchannel-authentication", request: signed_ciba_request, max_age: "999")
    assert_equal 200, response.status, response.body
    assert_nil @db[:ciba_requests].order(:id).last[:max_age]
  end

  def test_max_age_migration_does_not_reinterpret_pending_requests
    id = accept_request
    saved = @db[:ciba_requests].first.reject { |key, _| key == :max_age }
    @db.alter_table(:ciba_requests) { drop_column :max_age }
    Rodauth::CibaSupport::Schema.add_request_max_age(@db)
    row = @db[:ciba_requests].first
    assert_nil row[:max_age]
    assert_equal saved, row.reject { |key, _| key == :max_age }
    approve(id)
    assert_equal 200, poll(id).status
  end
end
