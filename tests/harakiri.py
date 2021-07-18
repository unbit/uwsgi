import time
import uwsgi
import signal
import sys
import atexit

def sig_handler(n, fp):
    print("[Python App] attempting graceful shutdown triggered by harakiri (signal %d)" % n)
    exit(1)

def application(e, s):
    print("[Python App] sleeping")
    time.sleep(3)
    s('200 OK', [('Content-Type', 'text/html')])
    return [b"OK"]


def exit_handler():
    time.sleep(3)
    # Should not reach this line (graceful harakiri deadline expired)
    print("[Python App] exiting now")

atexit.register(exit_handler)
signal.signal(signal.SIGSYS, sig_handler)
