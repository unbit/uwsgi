import uwsgi

uwsgi.log("I am uWSGI %s" % uwsgi.version)


def application(env, start_response):
    start_response('200 OK', [('Content-Type', 'text/html')])
    uwsgi.log(str(env))

    if env['PATH_INFO'] == '/logme':
        uwsgi.log_this_request()
    return "log written"
