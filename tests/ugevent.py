import gevent
import gevent.socket
import sys
import uwsgi
from uwsgidecorators import *

if 'gettotalrefcount' in sys.__dict__:
    REFCNT = True
else:
    REFCNT = False

@signal(17)
def hello(signum):
    print "hello i am signal %d, i am here because the background job is finished" % signum
    if REFCNT:
        print sys.gettotalrefcount()

@timer(10)
def ten_seconds(signum):
    print "10 seconds elapsed, signal %d raised" % signum
    if REFCNT:
        print sys.gettotalrefcount()

@filemon('/tmp')
def tmp_modified(signum):
    print "/tmp has been touched, i am the greenlet %s running on worker %d" % (gevent.getcurrent(), uwsgi.worker_id())
    if REFCNT:
        print sys.gettotalrefcount()

def bg_task():
    for i in range(1,10):
        print "background task", i
        gevent.sleep(1)

    # task ended raise a signal !!!
    uwsgi.signal(17)

def long_task():
    for i in range(1,10):
        print i
        gevent.sleep()

def application(e, sr):

    sr('200 OK', [('Content-Type','text/html')])

    t = gevent.spawn(long_task)

    t.join()

    yield "sleeping for 3 seconds...<br/>"

    gevent.sleep(3)

    yield "done<br>"

    yield "getting some ips...<br/>"

    urls = ['www.google.com', 'www.example.com', 'www.python.org', 'projects.unbit.it']
    jobs = [gevent.spawn(gevent.socket.gethostbyname, url) for url in urls]
    gevent.joinall(jobs, timeout=2)

    for j in jobs:
        yield "ip = %s<br/>" % j.value

    if REFCNT:
        print sys.gettotalrefcount()
        yield "%d" % sys.gettotalrefcount()

    # this task will goes on after request end
    gevent.spawn(bg_task)
