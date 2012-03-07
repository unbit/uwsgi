import socket
import select
import errno
import struct

def send_request(env, client):

	client.setblocking(1)

	data = "hello world\r\n"
	
	# send uwsgi-echo header
	client.send(struct.pack('<BHB', 101, len(data), 0))

	# send body
	client.send(data)

	while 1:
		yield env['x-wsgiorg.fdevent.readable'](client.fileno(), 10)
		buf = client.recv(4096)
		if len(buf) == 0:
			break
		else:
			yield buf


def application(env, start_response):

	s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
	s.setblocking(0)

	#env['x-wsgiorg.fdevent.readable'] = lambda fd,t: ""
	#env['x-wsgiorg.fdevent.writable'] = lambda fd,t: ""

	#yield ""

	c = s.connect_ex('echo.sock')
	if c == errno.EINPROGRESS:
		yield env['x-wsgiorg.fdevent.writable'](s.fileno(), 10)
		for r in send_request(env, s):
			yield r
	elif c == errno.EISCONN or c == 0: 
		start_response('200 Ok', [ ('Content-Type', 'text/plain')])
		for r in send_request(env, s):
			yield r
	else:
		print c
		start_response( '500 Internal Server Error', [ ('Content-Type', 'text/plain')])
		yield "Internal Server Error"

	s.close()
