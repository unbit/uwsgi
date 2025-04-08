import uwsgi


def app1(e, sr):
    print(e)
    sr('200 Ok', [('Content-Type', 'text/plain')])
    return b'i Am a Python 3.x bytestring'


def app2(e, sr):
    print(e)
    sr('404 Not Found', [('Content-Type', 'text/plain')])
    return b'i Am a Python 3.x Not Found page'

uwsgi.applications = {b'': app1, b'/test': app2}
