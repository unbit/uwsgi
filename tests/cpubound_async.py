import time

def application(env, start_response):
	start_response( '200 OK', [ ('Content-Type','text/html') ])
	for i in range(1,1000):
		yield "<h1>%s at %s</h1>" % (i, str(time.time()))
