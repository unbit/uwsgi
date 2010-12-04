import uwsgi

def application(env, start_response):

	# open the socket
	fd = uwsgi.async_connect("192.168.173.100:3032")

	# wait for connection ready
	yield uwsgi.wait_fd_write(fd, 3)

	if env['x-wsgiorg.fdevent.timeout']:
		print "connection timed out !!!"
		raise StopIteration

	if fd < 0:
		print "unable to connect"
		raise StopIteration
	

	# send request
	# env can contains python objects, but send_message will discard them.
	# In this way we will automagically have a congruent and valid uwsgi packet
	uwsgi.async_send_message(fd, 0, 0, env)

	# send the http body
	# ready body in async mode and resend to fd	
	# uwsgi.recv is a bit of magic as it will check for the wsgi_req timeout flag. If it is set None will be returned
	# uwsgi.recv will use always an internal buffer of 4096, but can be limited in the number of bytes to read
	cl = 0
	if env.has_key('CONTENT_LENGTH'):
		cl = int(env['CONTENT_LENGTH'])

	if cl > 0:
		input = env['wsgi.input'].fileno()
		yield uwsgi.wait_fd_read(input, 30)
		bufsize = min(cl, 4096)
		body = uwsgi.recv(input, bufsize)
		while body and cl > 0:
			uwsgi.send(fd, body)
			cl = cl - len(body)
			yield uwsgi.wait_fd_read(input, 30)
			bufsize = min(cl, 4096)
			body = uwsgi.recv(input, bufsize)
	

	# wait for response
	yield uwsgi.wait_fd_read(fd, 30)
	data = uwsgi.recv(fd)
	# recv the data, if it returns None the callable will end
	while data:
		yield data
		# wait for response
		yield uwsgi.wait_fd_read(fd, 30)
		data = uwsgi.recv(fd)

	uwsgi.close(fd)
	
