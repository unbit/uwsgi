import uwsgi
import threading
import time


def foo():
    while True:
        time.sleep(1)
        print("ciao, sono un thread")

t = threading.Thread(target=foo)
t.daemon = True
t.start()


def application(e, s):
    s('200 OK', [('Content-Type', 'text/html')])
    for i in range(0, 3):
        yield uwsgi.async_sleep(1)
        yield "iter: %d<br/>" % i
