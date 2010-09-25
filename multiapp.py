import werkzeug

def web3_app(environ):
    status = b'200 OK'
    headers = [(b'Content-type', b'text/plain')]
    body = [b'I am a Web3 app\n']
    return body, status, headers

def zero_app(e,s):
    s('200 OK', [ ('Content-Type', 'text/plain') ])
    return ""

def not_found(e,s):
    s('404 Not Found', [ ('Content-Type', 'text/plain') ])
    return ""


def wsgi_app(e, s):
    s('200 OK', [ ('Content-Type', 'text/plain') ])
    yield "I am a WSGI app\n"


def internal_server_error(e, s):
    s('500 Internal Server Error', [ ('Content-Type', 'text/plain') ])
    return ""

applications = {'':web3_app, '/wsgi':wsgi_app, '/test':werkzeug.test_app, '/zero':zero_app, '/notfound':not_found, '/ise':internal_server_error}
