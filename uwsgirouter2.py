
import uwsgi


def application(e,s):

	cl = 0
	if e.has_key('CONTENT_LENGTH'):
		cl = int(e['CONTENT_LENGTH'])

	for part in uwsgi.send_message("192.168.173.100:3032", 0, 0, e, 0, e['wsgi.input'].fileno(), cl):
		yield part 
