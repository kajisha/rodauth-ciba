# frozen_string_literal: true
require "tmpdir"
require "rackup/handler/webrick"
require_relative "demo_app"

Dir.mktmpdir("ciba-demo-") do |directory|
  db = Sequel.sqlite(File.join(directory, "demo.db"))
  CibaDemo.create_schema(db)
  begin
    Rackup::Handler::WEBrick.run(CibaDemo.build(db), Host: "127.0.0.1", Port: 9292)
  ensure
    db.disconnect
  end
end
