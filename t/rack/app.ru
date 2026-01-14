class App

  def call(env)
    headers = {"content-type" => "text/plain"}
    Rack::Utils.set_cookie_header!(headers, "country", { :value => "UK", :path => "/"})
    Rack::Utils.set_cookie_header!(headers, "autologin", { :value => "yes", :path => "/", :secure => true})
    [200, headers, ["Hello"]]
  end

end

run App.new
