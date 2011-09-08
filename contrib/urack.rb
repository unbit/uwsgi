require 'rubygems'
require 'socket'
begin
        require 'bundler/setup'
rescue LoadError
end
require 'rack'
require 'rack/content_length'
require 'rack/rewindable_input'
require 'stringio'

require 'optparse'

options = {
        :processes => 1,
        :threads => 1,
        :master => false,
        :logging => true,
        :static => true,
        :config => nil,
        :cachehack => false
}

opts = OptionParser.new do |opts|

        opts.on("-p", "--processes=nproc", Integer, '') { |p| options[:processes] = p }
        opts.on("-t", "--threads=nthreads", Integer, '') { |t| options[:threads] = t }
        opts.on("-M", "--master", '') { options[:master] = true }
        opts.on("-L", "--no-logging", '') { options[:logging] = false }
        opts.on("-S", "--no-static", '') { options[:static] = false }
        opts.on("-C", "--cache-hack", '') { options[:cachehack] = true }
        
        opts.parse! ARGV
end

if ARGV[0]
        options[:config] = ARGV[0]
end

def human_round(float)
        (float * (10 ** 2)).round / (10 ** 2).to_f
end

$requests = 0
$workers = Array.new
$mywid = 0

module Rack

  class RailsCachingHack
    def initialize app
      @app = app
    end

    def stripuri(uri)
      uri = uri.split('/')
      uri.slice!(1)
      val = uri.join('/')
    end
    def call env
      env['PATH_INFO'] = stripuri(env['PATH_INFO']) if env['PATH_INFO']
      env['REQUEST_URI'] = stripuri(env['REQUEST_URI']) if env['REQUEST_URI']
      env['REQUEST_URI'] = '/' if env['REQUEST_URI'] == ''
      @app.call env
    end
  end

  module Handler
    class Unbit

      def self.run(app, options={})
        server = UNIXServer.for_fd(0)

        can_spawn = true
        if options[:master]
                $0 = 'uRack master'
                $workers[0] = Process.pid
                ulog("master process enabled (pid: #{$workers[0]})")
                $workers[1] = Process.fork
                if $workers[1].to_i > 0
                        ulog("spawned worker 1 (pid: #{$workers[1]})")
                elsif $workers[1].to_i == 0
                        $0 = "uRack worker 1"
			$mywid = 1
                        can_spawn = false
                end
        else
                $0 = 'uRack worker 1'
                $workers[0] = nil
                $workers[1] = Process.pid
		$mywid = 1
                ulog("spawned worker 1 (pid: #{$workers[1]})")
        end

        if options[:processes] > 1 and can_spawn
                for p in 2..options[:processes]
                        $workers[p] = Process.fork
                        if $workers[p].to_i == 0
                                $0 = "uRack worker #{p}"
				$mywid = p
                                break
                        elsif $workers[p].to_i > 0
                                ulog("spawned worker #{p} (pid: #{$workers[p]})")
                        end
                end
        end

        # am i the master ?
        if options[:master] and Process.pid == $workers[0]
                while 1
                        i_am_a_child = false
                        pid = Process.waitpid
                        for wid in 1..options[:processes]
                                if $workers[wid] == pid
                                        ulog("worker #{wid} died ! (pid: #{pid})")
                                        $workers[wid] = Process.fork
                                        if $workers[wid].to_i == 0
                                                $0 = "uRack worker #{wid}"
                                                i_am_a_child = true
						$mywid = wid
                                                break
                                        elsif $workers[wid].to_i > 0
                                                ulog("respawned worker #{wid} (pid: #{$workers[wid]})")
                                        end
                                        
                                end
                        end
                        break if i_am_a_child
                end
        end
        
	if options[:threads] > 2
		for t in 2..options[:threads]
			wt = Thread.new do
			    ulog("spawning thread #{t} on worker #{$mywid}")
            		    while client = server.accept
                		serve client, app, options
            		    end
			end
		end
	end

        while client = server.accept
        	serve client, app, options
        end

      end

      def self.serve(client, app, options)

        speed = Time.now
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
                rack_input = Rack::RewindableInput::Tempfile.new('Rack_unbit_Input')
                rack_input.chmod(0000)
                rack_input.set_encoding(Encoding::BINARY) if rack_input.respond_to?(:set_encoding)
                rack_input.binmode
                rack_input.unlink

                remains = env["CONTENT_LENGTH"].to_i
                while remains > 0
                        if remains >= 4096
                                buf, sender = client.recvfrom(4096)
                        else
                                buf, sender = client.recvfrom(remains)
                        end

			if buf.length == 0
				break
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

        disconnected = false
        begin
          status, headers, body = app.call(env)
          begin
            send_headers client, env["HTTP_VERSION"] ,status, headers
            send_body client, body
          ensure
            body.close  if body.respond_to? :close
          end
        rescue Errno::EPIPE, Errno::ECONNRESET
          disconnected = true
        ensure
          rack_input.close
          client.close
        end
        $requests = $requests+1
        
        ulog("req: #{$requests} ip: #{env['REMOTE_ADDR']} pid: #{Process.pid} as: #{human_round(syscall(356).to_f/1024/1024)} MB => #{env['REQUEST_METHOD']} #{env['REQUEST_URI']} in #{Time.now-speed} secs [#{status}]#{' DISCONNECTED !!!' if disconnected}") if options[:logging]
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

def ulog(message)
        $stderr.puts "[#{Time.new}] uRack: #{message}"
end

ulog("starting at #{Dir.getwd}")
limit_as = human_round(Process.getrlimit(Process::RLIMIT_AS)[1].to_f/1024/1024)
ulog("your process address space limit is #{limit_as} MB")
server = Rack::Handler.get('Unbit')

starttime = Time.now

app = nil

if options[:config]
        cfgfile = File.read(options[:config])
        if cfgfile[/^#\\(.*)/]
                opts.parse! $1.split(/\s+/)
        end
        app = eval "Rack::Builder.new {( " + cfgfile + "\n )}.to_app", nil, options[:config]
else
        # falling back to rails
        if Dir.getwd =~ /\/public\/?$/  
                require '../config/environment'
        else
                require 'config/environment'
        end
        app = Rack::Builder.new {
                if options[:cachehack]
                        use Rack::RailsCachingHack
                end
                if options[:static]
                        use Rails::Rack::Static
                end
                if ActionController.const_defined?(:Dispatcher) && (ActionController::Dispatcher.instance_methods.include?(:call) || ActionController::Dispatcher.instance_methods.include?("call"))
                        run ActionController::Dispatcher.new
                else
                        require 'thin'
                        run Rack::Adapter::Rails.new(:environment => ENV['RAILS_ENV'])
                end
        }
end


ulog("your app is ready (in #{Time.now-starttime} seconds).")


server.run(app, options)

