# uwsgi --env foo=bar --env foo2=bar --http :8080 --wsgi-file t/python/testmultipleenv.py
import os

assert os.getenv('foo') == 'bar'
assert os.getenv('foo2') == 'bar'

print os.getenv('foo')
print os.getenv('foo2')

def application(e, sr):
    sr('200 OK', [('Content-Type', 'text/html')])
    return b'Hello world'
