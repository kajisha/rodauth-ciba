# frozen_string_literal: true
require_relative "test_helper"
require "rack/test"
require_relative "../examples/demo_app"

class DemoTest < Minitest::Test
  def setup
    @db = Sequel.sqlite
    CibaDemo.create_schema(@db)
    @app = CibaDemo.build(@db)
    @http = Rack::Test::Session.new(Rack::MockSession.new(@app))
  end

  def teardown
    @db.disconnect
  end

  def test_browser_approval_checks_csrf_and_finishes_request
    # A host can relax the binding-message policy; the view must still escape it.
    @app.plugin(:rodauth) { validate_ciba_binding_message { |_message| } }
    @http.basic_authorize("demo-client", "demo-secret")
    @http.post("/backchannel-authentication", scope: "openid", login_hint: "customer@example.test", binding_message: "<script>")
    assert_equal 200, @http.last_response.status
    @http.get("/")
    html = @http.last_response.body
    assert_includes html, "&lt;script&gt;"
    refute_includes html, "<script>"
    token = html[/name="csrf" value="([^"]+)"/, 1]
    assert token
    id = @db[:ciba_requests].get(:id)
    @http.post("/decision", id: id.to_s, decision: "approve", csrf: "invalid")
    assert_equal 403, @http.last_response.status
    assert_equal "pending", @db[:ciba_requests].get(:status)
    @http.post("/decision", id: id.to_s, decision: "approve", csrf: token)
    assert_equal 302, @http.last_response.status
    assert_equal "approved", @db[:ciba_requests].get(:status)
    grant_id = @db[:ciba_requests].get(:grant_id)
    assert_equal "openid", @db[:ciba_grants].where(id: grant_id).get(:scopes)
    @http.post("/decision", id: id.to_s, decision: "approve", csrf: token)
    assert_equal 302, @http.last_response.status
    assert_equal 1, @db[:ciba_grants].count
  end

  def test_demo_denial_and_conflicting_approval_do_not_leave_consent
    @http.basic_authorize("demo-client", "demo-secret")
    @http.post("/backchannel-authentication", scope: "openid", login_hint: "customer@example.test")
    assert_equal 200, @http.last_response.status
    id = @db[:ciba_requests].get(:id)
    @http.get("/")
    token = @http.last_response.body[/name="csrf" value="([^"]+)"/, 1]
    @http.post("/decision", id: id.to_s, decision: "deny", csrf: token)
    assert_equal 302, @http.last_response.status
    assert_equal "denied", @db[:ciba_requests].get(:status)
    @http.post("/decision", id: id.to_s, decision: "approve", csrf: token)
    assert_equal 409, @http.last_response.status
    assert_equal 0, @db[:ciba_grants].count
  end

  def test_demo_cannot_complete_another_customers_request
    @db[:accounts].insert(email: "other@example.test", status_id: 2)
    @http.basic_authorize("demo-client", "demo-secret")
    @http.post("/backchannel-authentication", scope: "openid", login_hint: "other@example.test")
    assert_equal 200, @http.last_response.status
    id = @db[:ciba_requests].get(:id)
    @http.get("/")
    token = @http.last_response.body[/name="csrf" value="([^"]+)"/, 1]
    %w[approve deny].each do |decision|
      @http.post("/decision", id: id.to_s, decision: decision, csrf: token)
      assert_equal 409, @http.last_response.status
      assert_equal "pending", @db[:ciba_requests].get(:status)
    end
    assert_equal 0, @db[:ciba_grants].count
  end
end

class DemoTest
  def test_default_require_loads_jwt_backend_in_fresh_process
    require "open3"
    require "rbconfig"
    output, errors, status = Open3.capture3(RbConfig.ruby, "-I", File.expand_path("../lib", __dir__), File.expand_path("../examples/smoke.rb", __dir__))
    assert status.success?, errors
    assert_includes output, "PASS: installed-gem"
  end
end
