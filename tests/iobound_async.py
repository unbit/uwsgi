import uwsgi

def send_request(env, client):

	uwsgi.send(client, b"GET /intl/it_it/images/logo.gif HTTP/1.0\r\n")

	# test for suspend/resume
	uwsgi.suspend()

	uwsgi.send(client, b"Host: www.google.it\r\n\r\n")


	while 1:
		yield uwsgi.wait_fd_read(client, 2)
		if env['x-wsgiorg.fdevent.timeout']:
			return

		buf = uwsgi.recv(client, 4096)
		if buf:
			yield buf
		else:
			break


def application(env, start_response):

	c = uwsgi.async_connect('74.125.232.115:80')

	# wait for connection
	yield uwsgi.wait_fd_write(c, 2)
	
	if env['x-wsgiorg.fdevent.timeout']:
		uwsgi.close(c)
		raise StopIteration

	if uwsgi.is_connected(c):
		for r in send_request(env, c):
			yield r
	else:
		start_response( '500 Internal Server Error', [ ('Content-Type', 'text/html')])
		yield "Internal Server Error"

	uwsgi.close(c)
