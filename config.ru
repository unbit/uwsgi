require 'fiber'
require 'sinatra'

get '/hi' do

   for i in 1..10
	puts "ruby"
	#Fiber.yield
   end


  "Hello World!"
end

run Sinatra::Application
