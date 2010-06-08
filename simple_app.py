import uwsgi

print "uWSGI version:", uwsgi.version

def ciao():
	print "modifica su /tmp"

def ciao2():
	print "nuovo uwsgi_server"

#uwsgi.event_add(uwsgi.EVENT_FILE, "/tmp", ciao)
#uwsgi.event_add(uwsgi.EVENT_DNSSD, "_uwsgi._tcp", ciao2)
#uwsgi.event_add(uwsgi.EVENT_TIMER, 1000, ciao2)

def application(env, start_response):
	print env
	start_response('200 Ok', [('Content-type', 'text/plain')])
	yield "hello world"
	yield "hello world2"

	for i in xrange(1,1000):
		yield str(i)
