import sys
import uwsgi

content_type = 'image/png'
filename = 'logo_uWSGI.png'

try:
    filename = sys.argv[1]
except:
    pass

try:
    content_type = sys.argv[2]
except:
    pass

def application(environ, start_response):
    start_response('200 OK', [('Content-Type', content_type)])
    fd = open(filename,'r')
    yield environ['wsgi.file_wrapper'](fd, 32*1024)
