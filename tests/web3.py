class AppClass(object):

    def __call__(self, environ):
        status = b'200 OK'
        headers = [(b'Content-type', b'text/plain')]
        body = [b'Hello world!\n']
        return body, status, headers

application = AppClass()
