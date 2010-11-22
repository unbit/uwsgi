require 'sinatra'

get '/hi' do
	"Hello World"
end

run Sinatra::Application
