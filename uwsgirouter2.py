
import uwsgi


def application(e,s):

	for part in uwsgi.send_message("192.168.173.100:3032", 0, 0, e, 0, e['wsgi.input'].fileno(), uwsgi.cl()):
		yield part 
