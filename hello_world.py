import uwsgi
if uwsgi.loop == 'gevent':
    import gevent

from threading import Thread
import time
from uwsgidecorators import postfork

def foobar():
    while True:
        time.sleep(3)
        print "threee second elapsed in worker %d" % uwsgi.worker_id()

@postfork
def spawn_thread():
    t = Thread(target=foobar)
    t.daemon = True
    t.start()

@postfork
def spawn_thread2():
    t = Thread(target=foobar)
    t.daemon = True
    t.start()

def gl_func():
    while True:
        gevent.sleep(2)
        print "i am a greenltet running in worker %d" % uwsgi.worker_id()

@postfork
def spawn_greenlet():
    gevent.spawn(gl_func)

print uwsgi.version
print uwsgi.workers()
try:
    uwsgi.cache_set('foo', "Hello World from cache")
except:
    pass
def application(env, start_response):
    print env['wsgi.input'].read()
    if uwsgi.loop == 'gevent':
        gevent.sleep()
    start_response('200 OK', [('Content-Type', 'text/html')])
    yield "foobar<br/>"
    if uwsgi.loop == 'gevent':
        gevent.sleep(3)
    yield str(env['wsgi.input'].fileno())
    yield "<h1>Hello World</h1>"
    try:
        yield uwsgi.cache_get('foo')
    except:
        pass
