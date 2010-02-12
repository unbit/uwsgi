# Copyright 2009 Unbit S.a.s. <info@unbit.it>
# see the COPYRIGHT file

$stdout.sync = true
options = {}

if Process.uid == 0
        puts "Never run uRack as root !!!"
        exit
end

$stderr.puts "[#{Time.new}] starting uRack"

def human_round(float)
        (float * (10 ** 2)).round / (10 ** 2).to_f
end

unless ENV.has_key?('UNBIT_RACK_PATH')
        if File.exists?("#{ARGV.last}/config/environment.rb")
                RAILS_ROOT = String.new(ARGV.last)
        else
                RAILS_ROOT = String.new(Dir.getwd)
        end
        options[:sockname] = '/tmp/uwsgi.sock'
        options[:sock_chmod] = 0
        options[:stderr_logfile] = nil
else
        $domain = ARGV.last.gsub('[','').gsub(']','')   
        $unbit_log_base = "[uRack/Unbit on #{$domain}]"
        RAILS_ROOT = String.new(ENV['UNBIT_RACK_PATH'])
        options[:unbit] = true
        $limit_as = human_round(Process.getrlimit(Process::RLIMIT_AS)[1].to_f/1024/1024)
        puts "#{$unbit_log_base} process address space limit is #{$limit_as} MB"
        $uidsec_size = syscall(357,0,0)
        puts "#{$unbit_log_base} need #{$uidsec_size} bytes to store uidsec_struct..."
        $uidsec = '1' * $uidsec_size
        puts "#{$unbit_log_base} uidsec_struct allocated."
end


options[:environment] = (ENV['RAILS_ENV'] || "development").dup
options[:processes] = 1
options[:serve_file] = nil
options[:max_input_size] = 8
options[:unbit_debug] = false
options[:master] = true
options[:gc_freq] = nil

require 'optparse'

ARGV.clone.options do |opts|
        opts.on('-s', '--socket=socket', String, 'Unix socket path.', 'Default: /tmp/uwsgi.sock') { |v|
                options[:sockname] = v
        }
        opts.on('-C','--chmod','chmod to 666 the unix socket.') {
                options[:sock_chmod] = true
        }
        opts.on('-F','--serve-file','serve static file.') {
                options[:serve_file] = true
        }
        opts.on('-p', '--processes=processes', Integer, 'Number of processes to spawn.', 'Default: 1') {|v|
                options[:processes] = v
        }
        opts.on('-g', '--gc-freq=requests', Integer, 'Number of requests between GC.', 'Default: 1') {|v|
                options[:gc_freq] = v
        }
        opts.on('-d', '--daemon=logfile', 'Put processes in background.', 'Default: all processes stay in foreground') {|v|
                options[:stderr_logfile] = v
        }
        opts.on('-i', '--max-input-size=size', 'Max POST data size (in Kbyte). Bigger data goes into a temporary file.', 'Default: 8') {|v|
                options[:max_input_size] = v
        }
        opts.on('-D', '--unbit-debug', 'Enable debug-level logging.', 'Default: disabled') {|v|
                options[:unbit_debug] = true
        }
        opts.on('-M', '--master-process', 'Enable the master process manager.', 'Default: disabled') {|v|
                options[:master] = true
        }
        opts.on("-e", '--environment=name', String, 'Specifies the environment to run this server under (test/development/production).','Default: development') { |v|
                options[:environment] = v
        }

        opts.separator ""

        opts.parse!
end

puts "[#{Time.new}] uRack: loading app [#{RAILS_ROOT}]..."
starttime = Time.now
require RAILS_ROOT + "/config/environment"

options[:app_name] = RAILS_ROOT

require 'socket'
require 'rubygems'
require 'rack'
require 'rack/utils'
require 'rack/content_length'

module Rack
        module Handler
                class Unbit
                        class Tempfile < ::Tempfile
                                def _close
                                        @tmpfile.close if @tmpfile
                                        @data[1] = nil if @data
                                        @tmpfile = nil
                                end
                        end
                        def self.run(app, options={})

                                # parse the socket options
                                # note: on unbit we use the stdin as communication socket
                                
                                server = nil
                                master_pid = Process.pid
                                options[:processes] ||= 1

                                unless options[:unbit]
                                        begin
                                                ::File.delete(options[:sockname])
                                        rescue
                                        end

                                        server = UNIXServer.new(options[:sockname])
                                        if options[:sock_chmod]
                                                ::File.chmod(0666, options[:sockname])
                                        end

                                        if options[:stderr_logfile]
                                                cwd = Dir.getwd
                                                Process.daemon
                                                Dir.chdir(cwd)
                                                $stdout.reopen(options[:stderr_logfile],'a')
                                                $stderr.reopen(options[:stderr_logfile],'a')
                                                # log files need to be unbuffered !
                                                $stdout.sync = true
                                                $stderr.sync = true
                                                # pid is changed after the .daemon call
                                                master_pid = Process.pid
                                        end
                                else
                                        server = UNIXServer.for_fd($stdin.fileno)
                                end

                                $workers = Array.new

                                if options[:master]
                                        $0 = "uRack #{ARGV.last}"
                                        pid = Process.fork
                                        if pid.to_i > 0
                                                puts "[#{Time.new}] uRack: spawned rack worker 1 (pid: #{pid})"
                                                $workers[1] = pid ;
                                        end
                                end

                                # the check on master pid is necessary
                                # without it the first worker will execute this part
                                if options[:processes] > 1 and Process.pid == master_pid
                                        for p in 2..options[:processes]
                                                pid = Process.fork
                                                break if pid.to_i == 0
                                                puts "[#{Time.new}] uRack: spawned rack worker #{p} (pid: #{pid})"
                                                $workers[p] = pid ;
                                        end
                                end


                                
                                # am i the master ?
                                if options[:master] and Process.pid == master_pid
                                        Signal.trap('TERM') do
                                                puts "[#{Time.new}] uRack: gracefully killing uRack"
                                                for wid in 1..options[:processes]
                                                        Process.kill('TERM', $workers[wid]);
                                                end
                                                exit 0;
                                        end
                                        Signal.trap('QUIT') do
                                                puts "[#{Time.new}] uRack: brutally killing uRack"
                                                for wid in 1..options[:processes]
                                                        Process.kill('INT', $workers[wid]);
                                                end
                                                exit 0;
                                        end
                                        puts "[#{Time.new}] uRack: the master process manager is alive."
                                        while 1
                                                pid = Process.waitpid
                                                puts "[#{Time.new}] uRack: worker died ! (pid: #{pid})"
                                                newpid = Process.fork
                                                break if newpid.to_i == 0
                                                puts "[#{Time.new}] uRack: respawned rack worker (pid: #{newpid})"
                                                for wid in 1..options[:processes]
                                                        if $workers[wid] == pid
                                                                $workers[wid] = newpid
                                                                break
                                                        end
                                                end
                                        end
                                end

                                if Process.pid != master_pid
                                        $0 = $0.gsub(/^uRack/,'urack')
                                        Signal.trap("TERM") do
                                                puts "[#{Time.new}] uRack: grecefully killing process #{Process.pid}..."
                                                if $in_request == 0
                                                        puts "[#{Time.new}] uRack: goodbye to process #{Process.pid}"
                                                        exit 0
                                                end
                                                $manage_next_request = nil
                                        end
                                        Signal.trap('INT') do
                                                puts "[#{Time.new}] uRack: brutally killing process #{Process.pid}..."
                                                exit 0
                                        end
                                        Signal.trap('PIPE') do
                                                puts "[#{Time.new}] uRack: the webserver (or the client) has closed the connection with process #{Process.pid} !!!"
                                        end
                                end

                                max_input_size = options[:max_input_size].to_i * 1024
                                requests = 0

                                null_post = StringIO.new('')

                                options[:app_name] ||= Dir.getwd

                                app = Rack::ContentLength.new(app)

                                $manage_next_request = true

                                if options[:gc_freq].to_i > 1
                                        GC.disable
                                end

                                while $manage_next_request

                                        $in_request = 0 
                                        client = server.accept
                                        $in_request = 1

                                        timed_out = false
                                                        
                                        ver, size, arg1 = client.recvfrom(4)[0].unpack('CvC')

                                        vars = client.recvfrom(size)[0]
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

                                        rack_input = null_post

                                        env.delete 'CONTENT_LENGTH' if env['CONTENT_LENGTH'] == ''

                                        if env['CONTENT_LENGTH'].to_i > 0
                                                cl = env['CONTENT_LENGTH'].to_i

                                                if cl <= max_input_size
                                                        poststr = ''
                                                        while poststr.size < cl
                                                                poststr = poststr + client.recvfrom(cl-poststr.size)[0] ;
                                                        end
                                                        
                                                        rack_input = StringIO.new(poststr)
                                                else
                                                        rack_input = Tempfile.new('UnbitRack')
                                                        rack_input.chmod(0000)

                                                        bytes_read = 0
                                                        while bytes_read < cl
                                                                buf = client.recvfrom(4096)[0]
                                                                rack_input.write(buf)
                                                                bytes_read += buf.size
                                                        end
                                                        rack_input.rewind
                                                end
                                        end

                                        env["SCRIPT_NAME"] = ""
                                        env.update({"rack.version" => [0,1],
                                                "rack.input" => rack_input,
                                                "rack.errors" => $stderr,
                                                "rack.multithread" => false,
                                                "rack.multiprocess" => true,
                                                "rack.run_once" => false,
                                                "rack.url_scheme" => "http"
                                        })

                                        env["QUERY_STRING"] ||= ""
                                        env["HTTP_VERSION"] ||= env["SERVER_PROTOCOL"]
                                        env["REQUEST_PATH"] ||= "/"


                                        begin
                                                #puts env.inspect
                                                $start_of_request = Time.new
                                                status, headers, body = app.call(env)
                                                $speed = Time.new - $start_of_request
                                        
                                                client.print "#{env["HTTP_VERSION"]} #{status} #{Rack::Utils::HTTP_STATUS_CODES[status]}\r\n"
                                                headers.each {|k,vs|
                                                        vs.split("\n").each { |v|
                                                                client.print "#{k}: #{v}\r\n"
                                                        }
                                                }
                                                client.print "\r\n"
                                                client.flush

                                                body.each {|part|
                                                        client.print part
                                                        client.flush
                                                }
                                        rescue Errno::EPIPE
                                                puts "[#{Time.new}] uRack: the webserver (or the client) has closed the connection with process #{Process.pid} !!!"
                                                timed_out = true
                                        ensure
                                                if rack_input.respond_to? :unlink
                                                        rack_input.unlink
                                                end
                                                unless rack_input.closed?
                                                        rack_input.close
                                                end
                                                client.close
                                                requests = requests+1
                                                # logging 
                                                begin
                                                        # the syscall 356 is only available on unbit kernels
                                                        # other systems need to use the proc file way
                                                        # stat = ::File.open('/proc/self/stat', 'r')
                                                        # procline = stat.readline
                                                        # statd = procline.split /\s+/
                                                        # stat.close
                                                        $stderr.puts "[#{Time.new}] uRack: [#{options[:app_name]}] req: #{requests} ip: #{env['REMOTE_ADDR']} pid: #{Process.pid} as: #{human_round(syscall(356).to_f/1024/1024)} MB => #{env['REQUEST_METHOD']} #{env['REQUEST_URI']} in #{$speed} secs [#{status}]#{' TIMED OUT !!!' if timed_out}"
                                                rescue
                                                        $stderr.puts "[#{Time.new}] uRack: [#{options[:app_name]}] req: #{requests} unable to get /proc/self/stat or syscall 356"
                                                end
                                                if syscall(357, $uidsec, 0) == $uidsec_size
                                                        if $uidsec[120..123].unpack('i')[0] > 0
                                                                $stderr.puts "[#{Time.new}] uRack: found a memory allocation error for request #{requests} (pid: #{Process.pid}). Better to kill myself..."
                                                                $manage_next_request = nil
                                                        end
                                                end
                                                $uidsec = '1' * $uidsec_size
                                                if options[:unbit_debug]
                                                        current_as = human_round( (syscall(356).to_f/1024/1024) - $last_as )
                                                        $stderr.puts "#{$unbit_log_base} resource status after request #{requests}: AS for this request: #{current_as} MB | OBJ for this request: #{ObjectSpace.each_object {} - $last_obj} | OBJ total: #{ObjectSpace.each_object {}}"
                                                        $last_as = human_round(syscall(356).to_f/1024/1024) ;
                                                        $last_obj = ObjectSpace.each_object {}
                                                end
                                                if options[:gc_freq].to_i > 1
                                                        if requests % options[:gc_freq].to_i == 0
                                                                $stderr.puts "[#{Time.new}] uRack: [#{options[:app_name]}] calling GC for pid #{Process.pid} after #{requests} requests."
                                                                GC.enable ; GC.start ; GC.disable
                                                        end
                                                end
                                        end
                                end

                                puts "[#{Time.new}] uRack: goodbye to process #{Process.pid}"
                        end
                end
        end
end

server = Rack::Handler.get('Unbit')

app = Rack::Builder.new {
        if options[:serve_file]
                puts "[#{Time.new}] uRack: file serving enabled."
                use Rails::Rack::Static
        end
        if ActionController.const_defined?(:Dispatcher) && (ActionController::Dispatcher.instance_methods.include?(:call) || ActionController::Dispatcher.instance_methods.include?("call"))
                run ActionController::Dispatcher.new
        else
                require 'thin'
                run Rack::Adapter::Rails.new(:environment => ENV['RAILS_ENV'])
        end
}.to_app

if options[:unbit]
$after_spawn_used_as = human_round(syscall(356).to_f/1024/1024)
$stderr.puts "#{$unbit_log_base} now you have #{$limit_as-$after_spawn_used_as} MB of address space available (used #{$after_spawn_used_as}MB after app startup)"
end
secs = Time.now-starttime
puts "[#{Time.new}] uRack: ready to serve requests after #{secs.to_i} secs (pid: #{Process.pid})"

if options[:unbit_debug]
        $last_as = $after_spawn_used_as ;
        $last_obj = ObjectSpace.each_object {}
end

server.run(app, options)
