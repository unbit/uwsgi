require 'net/http'

Net::HTTP.start("uwsgi.it") do |http|
  resp = http.get("/install")
  open("install.sh", "wb") do |file|
      file.write(resp.body)
  end
end

major,minor = RUBY_VERSION.split('.')
if major.to_i >= 2 or (major.to_i == 1 and minor.to_i >= 9)
  # a trick for installations with messy PATH
  ENV['UWSGICONFIG_RUBYPATH'] = File.join(RbConfig::CONFIG['bindir'], RbConfig::CONFIG['ruby_install_name']).sub(/.*\s.*/m, '"\&"')
  system("bash install.sh ruby2 #{Dir.pwd}/uwsgi.ruby")
else
  system("bash install.sh rack #{Dir.pwd}/uwsgi.ruby")
end

open("Makefile", "w") do |file|
  file.write("all:\n")
  file.write("\t\n")
end
