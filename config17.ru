require 'stringio'

hello = proc do |signum|
  puts "Hello i am signal #{signum}"
end

file_changed = proc do |signum| 
  puts "/tmp has been modified"
end

UWSGI.register_signal(17, '', hello)
UWSGI.register_signal(30, '', file_changed)

UWSGI.add_rb_timer(17 , 2)
UWSGI.add_timer(17 , 1)
UWSGI.add_file_monitor(30 , '/tmp')

puts UWSGI.signal_registered(1)
puts UWSGI.signal_registered(17)

run lambda { |env| 
        puts env.inspect
	UWSGI.signal(17)
	[200, {'Content-Type'=>'text/plain'}, StringIO.new("Hello World!\n")] 
}
