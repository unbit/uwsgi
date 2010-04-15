require 'socket'
require 'rack/content_length'
require 'rack/rewindable_input'
require 'stringio'

module Rack
  module Handler
    class Uwsgi

      def self.run(app, options={})
	if ENV['UWSGI_FD']
          server = UNIXServer.for_fd(ENV['UWSGI_FD'].to_i)
	else
          server = TCPServer.new(options[:Host], options[:Port])
	end
	while client = server.accept
          serve client, app
	end
      end

      def self.serve(client, app)

	head, sender = client.recvfrom(4)

	unless head
	  client.close
	  return
	end
	
	mod1, size, mod2 = head.unpack('CvC')

	if size == 0 or size.nil?
	  client.close
	  return
	end

	vars, sender = client.recvfrom(size)

	if vars.length != size
	  client.close
	  return
	end

	env = Hash.new

	i = 0
	while i < size
          kl = vars[i, 2].unpack('v')[0]
          i = i + 2
          key = vars[i, kl]
	  i = i + kl
          vl = vars[i, 2].unpack('v')[0]
          i = i + 2
	  value = vars[i, vl]
          i = i + vl
          env[key] = value
	end



        env.delete "HTTP_CONTENT_LENGTH"
        env.delete "HTTP_CONTENT_TYPE"

        env["SCRIPT_NAME"] = ""  if env["SCRIPT_NAME"] == "/"
        env["QUERY_STRING"] ||= ""
        env["HTTP_VERSION"] ||= env["SERVER_PROTOCOL"]
        env["REQUEST_PATH"] ||= "/"
        env.delete "PATH_INFO"  if env["PATH_INFO"] == ""
        env.delete "CONTENT_TYPE"  if env["CONTENT_TYPE"] == ""
        env.delete "CONTENT_LENGTH"  if env["CONTENT_LENGTH"] == ""
        
	
	if env["CONTENT_LENGTH"].to_i > 4096
		rack_input = Rack::RewindableInput::Tempfile.new('Rack_uwsgi_Input')
		rack_input.chmod(0000)
		rack_input.set_encoding(Encoding::BINARY) if rack_input.respond_to?(:set_encoding)
      		rack_input.binmode
      		if RUBY_PLATFORM !~ /(mswin|mingw|cygwin|java)/
        	  rack_input.unlink
		end

		remains = env["CONTENT_LENGTH"].to_i
		while remains > 0
			if remains >= 4096
				buf, sender = client.recvfrom(4096)
			else
				buf, sender = client.recvfrom(remains)
			end

			rack_input.write( buf )
			remains -= buf.length
		end

	elsif env["CONTENT_LENGTH"].to_i > 0
		rack_input =  StringIO.new(client.recvfrom(env["CONTENT_LENGTH"].to_i)[0])
	else
		rack_input = StringIO.new('')
	end

	rack_input.rewind

        env.update({"rack.version" => [1,1],
                     "rack.input" => rack_input,
                     "rack.errors" => $stderr,

                     "rack.multithread" => false,
                     "rack.multiprocess" => true,
                     "rack.run_once" => false,

                     "rack.url_scheme" => ["yes", "on", "1"].include?(env["HTTPS"]) ? "https" : "http"
                   })


        app = Rack::ContentLength.new(app)

        begin
          status, headers, body = app.call(env)
          begin
            send_headers client, env["HTTP_VERSION"] ,status, headers
            send_body client, body
          ensure
            body.close  if body.respond_to? :close
          end
	rescue Errno::EPIPE, Errno::ECONNRESET
        ensure
	  rack_input.close
	  client.close
        end
      end

      def self.send_headers(client, protocol, status, headers)
	client.print "#{protocol} #{status} #{Rack::Utils::HTTP_STATUS_CODES[status]}\r\n"
        headers.each { |k, vs|
          vs.split("\n").each { |v|
            client.print "#{k}: #{v}\r\n"
          }
        }
        client.print "\r\n"
        client.flush
      end

      def self.send_body(client, body)
        body.each { |part|
          client.print part
          client.flush
        }
      end
    end
  end
end
