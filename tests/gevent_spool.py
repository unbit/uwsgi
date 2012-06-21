from uwsgidecorators import *
import gevent

@spool
def longtask(*args):
    print args
    return uwsgi.SPOOL_OK

def level2():
    longtask.spool(foo='bar',test1='test2')

def level1():
    gevent.spawn(level2)

def application(environ, start_response):
    start_response('200 OK', [('Content-Type', 'text/html')])

    gevent.spawn(level1)

    for i in range(100):
        yield "counter: %d<br/>" % i
