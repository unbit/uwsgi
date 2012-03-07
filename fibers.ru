require 'fiber'
class SuspendingBody

	def each
		for i in 1..3
			yield "number: #{i}\n"
			UWSGI.async_sleep(1)
			puts "sleep..."
			Fiber.yield
		end

		fd = UWSGI.async_connect("81.174.68.52:80")
		UWSGI.wait_fd_write(fd, 3)
		Fiber.yield
		io = IO.new(fd)
		puts "connected"
		io.syswrite("GET /uwsgi/export/1081%3A362d695b2f25/plugins/fiber/fiber.c HTTP/1.0\r\n")
		io.syswrite("Host: projects.unbit.it\r\n")
		io.syswrite("\r\n")

		UWSGI.wait_fd_read(fd, 3)
		Fiber.yield

		puts "data available"

		begin
		while body = io.sysread(fd)
			yield body
			Fiber.yield
		end
		rescue
		end
	
		io.close
	end

end

class RackFoo

	def call(env)
		[200, { 'Content-Type' => 'text/plain'}, SuspendingBody.new]
	end

end

run RackFoo.new
