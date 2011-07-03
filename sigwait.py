import uwsgi
from uwsgidecorators import *

@postfork
def wait_for_signal():
    if uwsgi.worker_id() == 2:
        print("waiting for a signal...")
        uwsgi.signal_wait()
        print("signal %d received" % uwsgi.signal_received())
    elif uwsgi.worker_id() == 3:
        print("waiting for signal 30...")
        uwsgi.signal_wait(30)
        print("signal %d received" % uwsgi.signal_received())


def application(e, s):
    s('200 OK', [('Content-Type', 'text/html')])
    if e['PATH_INFO'] == '/30':
        uwsgi.signal(30)
    else:
        uwsgi.signal(17)
    return "Signal raised"
   
