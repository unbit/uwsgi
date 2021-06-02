import sys


def application(e, sr):
    sr('200 OK', [('Content-Type', 'text/html')])
    print(sys.gettotalrefcount())
    yield '%s' % sys.gettotalrefcount()
