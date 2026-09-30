# frozen_string_literal: true
require_relative "test_helper"

class CibaIntegrationTest
  def test_nonce_is_bound_to_start_request_not_poll_and_not_observed
    events = []
    response = post("/backchannel-authentication", {login_hint: "customer@example.test", scope: "openid", nonce: "start-correlation"},
      "test.observe" => ->(event) { events << event })
    assert_equal 200, response.status
    public_id = JSON.parse(response.body).fetch("auth_req_id")
    row = @db[:ciba_requests].first
    assert_equal "start-correlation", auth.ciba_request(row[:id])[:nonce]
    assert auth.ciba_request(row[:id])[:nonce].frozen?
    approve(public_id)
    result = post("/token", {grant_type: GRANT, auth_req_id: public_id, nonce: "poll-tampering"},
      "test.observe" => ->(event) { events << event })
    assert_equal 200, result.status, result.body
    _, claims = decode_id_token(result)
    assert_equal "start-correlation", claims.fetch("nonce")
    assert events.none? { |event| event.key?(:nonce) }
  end

  def test_nonce_is_optional_and_bounded
    id = accept_request
    approve(id)
    _, claims = decode_id_token(poll(id))
    refute claims.key?("nonce")
    ["", "a" * 1025].each do |nonce|
      assert_error post("/backchannel-authentication", login_hint: "customer@example.test", scope: "openid", nonce: nonce), "invalid_request"
    end
  end

  def test_nonce_forward_migration_preserves_existing_request
    public_id = accept_request
    request_id = @db[:ciba_requests].get(:id)
    @db.alter_table(:ciba_requests) { drop_column :nonce }
    before = @db[:ciba_requests].first
    Rodauth::CibaSupport::Schema.add_request_nonce(@db)
    assert_equal before, @db[:ciba_requests].first.reject { |key, _| key == :nonce }
    assert_nil auth.ciba_request(request_id)[:nonce]
    approve(public_id)
    _, claims = decode_id_token(poll(public_id))
    refute claims.key?("nonce")
  end
end
