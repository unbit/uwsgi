def application(environ, start_response):

	start_response('200 OK', [('Content-Type', 'image/png')])
	fd = open('logo_uWSGI.png','r')
	yield environ['wsgi.file_wrapper'](fd, 4096)
