import uwsgi
import time

def application(env, start_response):

	start_response('200 Ok', [ ('Content-Type','text/html') ] )

	yield "I am the worker %d<br/>" % uwsgi.worker_id()

	grunt = uwsgi.grunt()
	
	if grunt is None:
		print "worker %d detached" % uwsgi.worker_id()
	else:
		yield "And now i am the grunt with a fix worker id of %d<br/>" % uwsgi.worker_id()
		time.sleep(2)
		yield "Now, i will start a very slow task...<br/>"
		for i in xrange(1,10):
			yield "waiting for %d seconds<br/>" % i
			time.sleep(i)
	
		
