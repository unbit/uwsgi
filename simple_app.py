def application(env, start_response):
	start_response('200 Ok', [('Content-type', 'text/plain')])
	return "hello world"
