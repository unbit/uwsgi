import uwsgi

def application(env, start_response):

	# open the socket
	fd = uwsgi.async_connect("192.168.173.100:3032")

	# wait for connection ready (3s timeout)
	yield uwsgi.wait_fd_write(fd, 3)

	# has timed out ?
	if env['x-wsgiorg.fdevent.timeout']:
		print "connection timed out !!!"
		raise StopIteration

	# connection refused ?
	if not uwsgi.is_connected(fd):
		print "unable to connect"
		raise StopIteration
	

	# send request
	# env can contains python objects, but send_message will discard them.
	# In this way we will automagically have a congruent and valid uwsgi packet
	uwsgi.async_send_message(fd, 0, 0, env)

	# send the http body
	# ready body in async mode and resend to fd	
	# uwsgi.recv will use always an internal buffer of 4096, but can be limited in the number of bytes to read

	# does thir request has a body ?
	cl = 0
	if env.has_key('CONTENT_LENGTH'):
		cl = int(env['CONTENT_LENGTH'])

	if cl > 0:
		# get the input fd
		input = env['wsgi.input'].fileno()

		# read (in async mode) upto 'cl' data and send to uwsgi peer
		while cl > 0:
			bufsize = min(cl, 4096)
			yield uwsgi.wait_fd_read(input, 30)
			if env['x-wsgiorg.fdevent.timeout']:
				print "connection timed out !!!"
				raise StopIteration
			body = uwsgi.recv(input, bufsize)
			if body:
				uwsgi.send(fd, body)
				cl = cl - len(body)
			else:
				break
	

	# wait for response (30s timeout)
	yield uwsgi.wait_fd_read(fd, 30)

	# has timed out ?
	if env['x-wsgiorg.fdevent.timeout']:
		print "connection timed out !!!"
		raise StopIteration

	data = uwsgi.recv(fd)
	# recv the data, if it returns None the callable will end
	while data:
		yield data
		# wait for response
		yield uwsgi.wait_fd_read(fd, 30)
		data = uwsgi.recv(fd)

	uwsgi.close(fd)
	
