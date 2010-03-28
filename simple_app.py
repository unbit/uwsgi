def application(env, start_response):
	print env
	start_response('200 Ok', [('Content-type', 'text/plain')])
	yield "hello world"
