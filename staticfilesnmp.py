import uwsgi
from os import path

uwsgi.snmp_set_counter64(1, 0)  # Number of requests
uwsgi.snmp_set_counter64(2, 0)  # Number of bytes

def application(environ, start_response):
    size = path.getsize('logo_uWSGI.png')
    start_response('200 OK', [('Content-Type', 'image/png'), ('Content-Length', str(size))] )
    fd = open('logo_uWSGI.png','r')
    uwsgi.snmp_incr_counter64(1)
    uwsgi.snmp_incr_counter64(2, size)
    return environ['wsgi.file_wrapper'](fd, 4096)
