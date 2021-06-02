# uwsgi -s :3031 -M -p 4 --plugin gevent --loop gevent --async 1000 --enable-threads -w tests.testgevent
from threading import Thread
import gevent
import uwsgi
import time


def microtask(wid):
    print("i am a gevent task")
    gevent.sleep(10)
    print("10 seconds elapsed in worker id %d" % wid)


def athread():
    while True:
        time.sleep(1)
        print("i am the thread 1")


def athread2():
    while True:
        time.sleep(1)
        print("i am the thread 2")

t1 = Thread(target=athread)
t1.daemon = True
t1.start()

t2 = Thread(target=athread2)
t2.daemon = True
t2.start()


def application(environ, start_response):

    gevent.sleep()
    start_response('200 OK', [('Content-Type', 'text/html')])
    yield "sleeping for 3 seconds...<br/>"
    gevent.sleep(3)
    yield "done<br/>"
    gevent.spawn(microtask, uwsgi.worker_id())
    yield "microtask started<br/>"
