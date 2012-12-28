
import uwsgi

fd = uwsgi.connect("127.0.0.1:3033")

def application(e,s):

	for part in uwsgi.send_message(fd, 0, 4, e, 30, e['wsgi.input'].fileno(), uwsgi.cl()):
		yield part 
