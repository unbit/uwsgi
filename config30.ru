require 'stringio'
require 'uwsgidsl'



signal 17,'mule5' do |signum|
end

puts UWSGI::VERSION
puts UWSGI::NUMPROC
puts UWSGI::HOSTNAME

puts UWSGI::OPT.inspect

timer 2 do |signum|
  puts "ciao sono un dsl ruby: #{signum} #{UWSGI::OPT.inspect}"
end

timer 1,'mule1' do |signum|
  puts "1 second elapsed (signum #{signum})"
end

filemon '/tmp' do |signum|
  puts "/tmp has been modified"
end

cron 5,-1,-1,-1,-1 do |signum|
  puts "cron ready #{signum}"
end

cron 58,-1,-1,-1,-1 do |signum|
  puts "cron ready #{signum}"
end

postfork do
  puts "fork() called"
end

rpc 'pippo' do
  "i am an rpc function"
end

rpc 'pluto' do |x,y|
  "i am another rpc function #{x} #{y}"
end

begin
  foo_func
rescue
end

puts UWSGI.cache_exists('nilkey')
puts UWSGI.cache_exists?('nilkey')

UWSGI.cache_set!('foobar_key?a=1', UWSGI::OPT.inspect)
begin
puts UWSGI.cache_get(nil)
rescue
end
puts UWSGI.cache_get('foobar_key?a=1')


run lambda { |env| 
  puts env.inspect
  UWSGI.setprocname("i am the uWSGI rack plugin")
  UWSGI.signal(17)
  [200, {'Content-Type'=>'text/plain'}, StringIO.new("Hello World! #{UWSGI.mem.inspect}\n")] 
}
