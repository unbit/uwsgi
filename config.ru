require 'fiber'
require 'sinatra'

get '/hi' do

   class Response
	def each
		for i in 1..10
			yield "ciao<br/>"
			Fiber.yield
		end
	end
   end

   Response.new
end

run Sinatra::Application
