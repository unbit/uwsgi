#require 'fiber'
require 'sinatra'

get '/hi' do

   for i in 1..10
	puts "ruby"
	#UWSGI.suspend()
   end

  "Hello World!"
end

run Sinatra::Application
