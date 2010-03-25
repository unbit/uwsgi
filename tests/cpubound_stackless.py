import time
import stackless

def application(env, start_response):
	start_response( '200 OK', [ ('Content-Type','text/html') ])
	#print env
	for i in range(1,100000):
		#print i
		yield "<h1>%s at %s</h1>\n" % (i, str(time.time()))
		#schedule every 2
		if i % 2 == 0:
			stackless.schedule()

	print "DONE AT %d" % i
