require 'net/http'

Net::HTTP.start("uwsgi.it") do |http|
  resp = http.get("/install")
  open("install.sh", "wb") do |file|
      file.write(resp.body)
  end
end

system("bash install.sh rack #{Dir.pwd}/uwsgi.ruby")

open("Makefile", "w") do |file|
  file.write("all:\n")
  file.write("\t\n")
end
