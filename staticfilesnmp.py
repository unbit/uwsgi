import uwsgi

counter = 0
uwsgi.snmp_set_counter64(1, counter)

def application(environ, start_response):
    global counter

    start_response('200 OK', [('Content-Type', 'image/png')])
    fd = open('logo_uWSGI.png','r')
    counter = counter+1
    uwsgi.snmp_set_counter64(1, counter)
    return environ['wsgi.file_wrapper'](fd, 4096)
