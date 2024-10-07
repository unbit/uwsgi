class App

  def call(environ)
    [200, {'Content-Type' => 'text/html'}, ['Hello']]
  end

end

run App.new
