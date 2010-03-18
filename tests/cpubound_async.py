
def application(env, start_response):
	start_response( '200 OK', [ ('Content-Type','text/html') ])
	for i in range(1,10000):
		yield "<h1>%s</h1>" % i
