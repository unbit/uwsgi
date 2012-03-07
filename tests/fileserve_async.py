import sys
import mimetypes

basedir = sys.argv[1]
mimetypes.init()


def application(environ, start_response):
	
	filename = basedir + environ['PATH_INFO']
	(content_type, encoding) = mimetypes.guess_type(filename)
	if not content_type:
		content_type = 'text/plain'

	start_response('200 OK', [('Content-Type', content_type)])
	fd = open(filename,'r')
	yield environ['wsgi.file_wrapper'](fd, 32*1024)
