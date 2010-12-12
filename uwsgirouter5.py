
import uwsgi

fd = uwsgi.connect("192.168.173.100:3033")
for part in uwsgi.send_message(fd, 0, 4, {"leave_open":"1"}, 30):
	print part

def application(e,s):

	for part in uwsgi.send_message(fd, 0, 4, e, 30, e['wsgi.input'].fileno(), uwsgi.cl()):
		print part
		yield part 
