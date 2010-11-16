class SuspendingBody

	def each
		for i in 1..100
			yield "numero: #{i}\n"
		end
	end

end

class RackFoo

	def call(env)
		[200, { 'Content-Type' => 'text/plain'}, SuspendingBody.new]
	end

end

run RackFoo.new
