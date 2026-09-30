# frozen_string_literal: true
require_relative "ciba_claims_test"
require_relative "ciba_refresh_test"
require_relative "ciba_signed_request_test"

class CibaIntegrationTest
  def test_empty_acr_values_uses_defaults_in_plain_and_signed_requests
    @db.alter_table(:oauth_applications) { add_column :default_acr_values, String, text: true }
    [false, true].each do |signed|
      enable_signed_requests if signed
      [nil, [], %w[first second]].each do |defaults|
        @db[:oauth_applications].update(default_acr_values: defaults && JSON.generate(defaults))
        [nil, "", "explicit"].each do |value|
          params = {scope: "openid", login_hint: "customer@example.test"}
          params[:acr_values] = value unless value.nil?
          params = {request: signed_ciba_request(params), acr_values: "unsigned-override"} if signed
          response = post("/backchannel-authentication", params)
          assert_equal 200, response.status, response.body
          row = @db[:ciba_requests].order(:id).last
          expected = value == "explicit" ? value : defaults&.join(" ")
          expected = nil if expected == ""
          expected ? assert_equal(expected, row[:acr_values]) : assert_nil(row[:acr_values])
          id = JSON.parse(response.body).fetch("auth_req_id")
          approve(id, acr: "achieved")
          _, claims = decode_id_token(poll(id))
          assert_equal !expected.nil?, claims.key?("acr")
          assert_equal "achieved", claims["acr"] if expected
        end
      end
    end
  end

  def test_authentication_claim_migration_preserves_legacy_sources
    enable_refresh
    started = post("/backchannel-authentication", scope: "openid offline_access", login_hint: "customer@example.test")
    assert_equal 200, started.status, started.body
    id = JSON.parse(started.body).fetch("auth_req_id")
    approve(id, auth_time: 123, acr: "achieved", amr: ["pwd"])
    before = @db[:ciba_requests].first.reject { |key, _| key == :authentication_claims }
    @db.alter_table(:ciba_requests) { drop_column :authentication_claims }
    @db.alter_table(:ciba_refresh_tokens) { drop_column :authentication_claims }
    Rodauth::CibaSupport::Schema.add_authentication_claims(@db)
    Rodauth::CibaSupport::Schema.add_authentication_claims(@db, table: :ciba_refresh_tokens)
    after = @db[:ciba_requests].first
    assert_nil after[:authentication_claims]
    assert_equal before, after.reject { |key, _| key == :authentication_claims }
    issued = poll(id)
    assert_equal 200, issued.status, issued.body
    refreshed = refresh_with(JSON.parse(issued.body).fetch("refresh_token"))
    assert_equal 200, refreshed.status, refreshed.body
    [issued, refreshed].each do |result|
      _, claims = decode_id_token(result)
      assert_equal 123, claims.fetch("auth_time")
      assert_equal "achieved", claims.fetch("acr")
      assert_equal ["pwd"], claims.fetch("amr")
    end
    newer = accept_request
    approve(newer, auth_time: 123)
    refute decode_id_token(poll(newer)).last.key?("auth_time")
  end

  def test_authentication_claim_selection_initial_and_refresh
    enable_explicit_claims
    enable_refresh
    @db.alter_table(:oauth_applications) { add_column :require_auth_time, TrueClass }
    [false, true].each do |by_scope|
      mapping = by_scope ? {"openid" => %w[auth_time acr amr]} : {}
      @app.plugin(:rodauth) { ciba_authentication_claims_by_scope mapping }
      [nil, false, true].each do |required|
        @db[:oauth_applications].update(require_auth_time: required)
        [nil, 123].each do |time|
          [:default, :explicit, :acr].each do |selection|
            params = {scope: "openid offline_access", login_hint: "customer@example.test"}
            params[:claims] = JSON.generate(id_token: {auth_time: nil, acr: nil, amr: nil}) if selection == :explicit
            params[:acr_values] = "requested" if selection == :acr
            started = post("/backchannel-authentication", params)
            assert_equal 200, started.status, started.body
            id = JSON.parse(started.body).fetch("auth_req_id")
            approve(id, auth_time: time, acr: "achieved", amr: ["pwd"])
            issued = poll(id)
            assert_equal 200, issued.status, issued.body
            refreshed = refresh_with(JSON.parse(issued.body).fetch("refresh_token"))
            assert_equal 200, refreshed.status, refreshed.body
            [issued, refreshed].each do |result|
              _, claims = decode_id_token(result)
              assert_equal !time.nil? && (by_scope || required == true || selection == :explicit), claims.key?("auth_time")
              assert_equal 123, claims["auth_time"] if claims.key?("auth_time")
              assert_equal by_scope || selection != :default, claims.key?("acr")
              assert_equal "achieved", claims["acr"] if claims.key?("acr")
              assert_equal by_scope || selection == :explicit, claims.key?("amr")
              assert_equal ["pwd"], claims["amr"] if claims.key?("amr")
            end
          end
        end
      end
    end
  end

  def test_registered_authentication_defaults_apply_before_dispatch
    enable_refresh
    @db.alter_table(:oauth_applications) do
      add_column :default_acr_values, String, text: true
      add_column :default_max_age, :bigint
    end
    [nil, 0, 60].each do |age|
      [[], %w[first second]].each do |defaults|
        [nil, "override"].each do |explicit|
          @db[:oauth_applications].update(default_max_age: age, default_acr_values: JSON.generate(defaults))
          params = {scope: "openid offline_access", login_hint: "customer@example.test"}
          params[:acr_values] = explicit if explicit
          seen = []
          started = post("/backchannel-authentication", params, "test.device" => ->(row, _) { seen << row })
          assert_equal 200, started.status, started.body
          expected_acr = explicit || (defaults.join(" ") unless defaults.empty?)
          expected_acr ? assert_equal(expected_acr, seen.last[:acr_values]) : assert_nil(seen.last[:acr_values])
          id = JSON.parse(started.body).fetch("auth_req_id")
          approve(id, auth_time: 123, acr: "achieved")
          @db[:oauth_applications].update(default_max_age: nil, default_acr_values: nil)
          issued = poll(id)
          assert_equal 200, issued.status, issued.body
          refreshed = refresh_with(JSON.parse(issued.body).fetch("refresh_token"))
          assert_equal 200, refreshed.status, refreshed.body
          [issued, refreshed].each do |result|
            _, claims = decode_id_token(result)
            assert_equal !age.nil?, claims.key?("auth_time")
            assert_equal !expected_acr.nil?, claims.key?("acr")
            assert_equal "achieved", claims["acr"] if expected_acr
          end
        end
      end
    end
  end

  def test_authentication_claim_selection_survives_client_policy_change
    enable_refresh
    @db.alter_table(:oauth_applications) { add_column :require_auth_time, TrueClass }
    [true, false].each do |required|
      @db[:oauth_applications].update(require_auth_time: required)
      started = post("/backchannel-authentication", scope: "openid offline_access", login_hint: "customer@example.test")
      assert_equal 200, started.status, started.body
      id = JSON.parse(started.body).fetch("auth_req_id")
      approve(id, auth_time: 123)
      @db[:oauth_applications].update(require_auth_time: !required)
      issued = poll(id)
      assert_equal 200, issued.status, issued.body
      refreshed = refresh_with(JSON.parse(issued.body).fetch("refresh_token"))
      assert_equal 200, refreshed.status, refreshed.body
      [issued, refreshed].each do |result|
        _, claims = decode_id_token(result)
        assert_equal required, claims.key?("auth_time")
      end
    end
  end
end
