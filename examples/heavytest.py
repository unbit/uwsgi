import uwsgi
import werkzeug.testapp

uwsgi.cache_set("/cache/get", "HTTP 1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>I am the uWSGI cache</h1>")


def app001(env, start_response):
    start_response('200 OK', [('Content-Type', 'text/html')])
    return "PATH_INFO=%s" % env['PATH_INFO']


def app002(env, start_response):
    start_response('200 OK', [('Content-Type', 'text/html')])
    return "requests: %d" % uwsgi.total_requests()

uwsgi.applications = {
    '': werkzeug.testapp.test_app,
    '/app001': app001,
    '/app002': app002
}
