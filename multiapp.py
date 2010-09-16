import werkzeug

def web3_app(environ):
    status = b'200 OK'
    headers = [(b'Content-type', b'text/plain')]
    body = [b'I am a Web3 app\n']
    return body, status, headers


def wsgi_app(e, s):
    s('200 OK', [ ('Content-Type', 'text/plain') ])
    yield "I am a WSGI app\n"

applications = {'':web3_app, '/wsgi':wsgi_app, '/test':werkzeug.test_app}
