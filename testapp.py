import uwsgi

def application(env, start_response):
	start_response('200 OK', [('Content-Type', 'text/plain')])
	try:
		yield "Shared counter is %d\n" % uwsgi.sharedarea_inclong(100)
	except:
		yield 'Hello World'

	print env

applications = {'/':'application'}
