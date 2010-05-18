def application(env, start_response):
	print env
	start_response('200 Ok', [('Content-type', 'text/plain')])
	yield "hello world"
	yield "hello world2"

	for i in xrange(1,1000):
		yield str(i)
