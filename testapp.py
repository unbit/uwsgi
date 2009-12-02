import uwsgi

import time

def myspooler(env):
	print env
	for i in range(1,100):
		uwsgi.sharedarea_inclong(100)
		time.sleep(1)

uwsgi.spooler = myspooler

def application(env, start_response):
	start_response('200 OK', [('Content-Type', 'text/plain')])
	try:
		yield "Shared counter is %d\n" % uwsgi.sharedarea_inclong(100)
	except:
		yield 'Hello World'

applications = {'/':'application'}
