import uwsgi

def application(env, start_response):

	print env

	# open the socket
	fd = uwsgi.async_connect("127.0.0.1:3032")
	# wait for connection ready
	yield uwsgi.wait_fd_write(fd, 30)

	# send request
	uwsgi.async_send_message(fd, 0, 0, env)

	# send the http body
	# ready body in async mode and resend to fd	

	while 1:
		# wait for response
		yield uwsgi.wait_fd_read(fd, 30)

		# recv the data, if it returns None the callable will end
		yield uwsgi.recv(fd)

	uwsgi.close(fd)
	
