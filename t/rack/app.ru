class App

  def call(environ)
    [200, {"content-type" => "text/plain"}, ['Hello']]
  end

end

run App.new
