require 'fiber'
class SuspendingBody

	def each
		for i in 1..10
			yield "number: #{i}\n"
			Fiber.yield
		end
	end

end

class RackFoo

	def call(env)
		[200, { 'Content-Type' => 'text/plain'}, SuspendingBody.new]
	end

end

run RackFoo.new
