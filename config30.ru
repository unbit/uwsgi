require 'stringio'
require 'uwsgidsl'

timer 2 do |signum|
  puts "ciao sono un dsl ruby: #{signum}"
end

=begin
timer 1,'mule' do |signum|
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
=end

run lambda { |env| 
  puts env.inspect
  #UWSGI.signal(17)
  [200, {'Content-Type'=>'text/plain'}, StringIO.new("Hello World!\n")] 
}
