import time
import uwsgi
def application(e,s):
    print "locking"
    uwsgi.lock()
    print "locked"
    time.sleep(3)
    uwsgi.unlock()
    print "UN-locked"
    s('200 OK', [('Content-Type','text/html')])
    return "slow"

