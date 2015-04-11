import werkzeug
import uwsgi


def zero_app(e, s):
    s('200 OK', [('Content-Type', 'text/plain')])
    return "0"


def not_found(e, s):
    s('404 Not Found', [('Content-Type', 'text/plain')])
    return ""


def wsgi_app(e, s):
    s('200 OK', [('Content-Type', 'text/plain')])
    yield "I am a WSGI app\n"


def internal_server_error(e, s):
    s('500 Internal Server Error', [('Content-Type', 'text/plain')])
    return ""

uwsgi.applications = {
    '/wsgi': wsgi_app,
    '/test': werkzeug.test_app,
    '/zero': zero_app,
    '/notfound': not_found,
    '/ise': internal_server_error
}
