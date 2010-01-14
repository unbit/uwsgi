def application(env, start_response):
	start_response('200 Ok', [('Content-type', 'text/plain; charset=UTF-32')])
	return "hello world"
