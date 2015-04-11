import uwsgi
from uwsgidecorators import *


@signal(17, target='workers')
def hello(signum):
    print("I AM THE WORKER %d" % uwsgi.worker_id())


@signal(30, target='worker2')
def hello2(signum):
    print("I AM THE WORKER 2")


@postfork
def wait_for_signal():
    if uwsgi.worker_id() != 2:
        print("waiting for a signal...")
        uwsgi.signal_wait()
        print("signal %d received" % uwsgi.signal_received())


def application(e, s):
    s('200 OK', [('Content-Type', 'text/html')])
    if e['PATH_INFO'] == '/30':
        uwsgi.signal(30)
        uwsgi.signal(100)
    else:
        uwsgi.signal(17)
    return "Signal raised"
