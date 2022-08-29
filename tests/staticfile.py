import sys

content_type = 'image/png'
filename = 'logo_uWSGI.png'

try:
    filename = sys.argv[1]
except IndexError:
    pass

try:
    content_type = sys.argv[2]
except IndexError:
    pass


def application(environ, start_response):
    start_response('200 OK', [('Content-Type', content_type)])
    fd = open(filename)
    yield environ['wsgi.file_wrapper'](fd, 32*1024)
