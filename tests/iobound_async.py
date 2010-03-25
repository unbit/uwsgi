import socket
import select
import errno

def send_request(env, client):

	client.setblocking(1)

	client.send(b"GET /intl/it_it/images/logo.gif HTTP/1.0\r\n")
	client.send(b"Host: www.google.it\r\n\r\n")

	while 1:
		yield env['x-wsgiorg.fdevent.readable'](client.fileno(), 10)
		buf = client.recv(4096)
		if len(buf) == 0:
			break
		else:
			yield buf


def application(env, start_response):

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.setblocking(0)

	#env['x-wsgiorg.fdevent.readable'] = lambda fd,t: ""
	#env['x-wsgiorg.fdevent.writable'] = lambda fd,t: ""

	#yield ""

	c = s.connect_ex(('www.google.it', 80))
	if c == errno.EINPROGRESS:
		yield env['x-wsgiorg.fdevent.writable'](s.fileno(), 10)
		for r in send_request(env, s):
			yield r
	elif c == errno.EISCONN: 
		for r in send_request(env, s):
			yield r
	else:
		start_response( '500 Internal Server Error', [ ('Content-Type', 'text/html')])
		yield "Internal Server Error"

	s.close()
