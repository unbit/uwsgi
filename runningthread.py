from threading import Thread
import time
import uwsgi

def mess():
    while True:
        for i in xrange(0, 100):
            if uwsgi.ready():
                uwsgi.signal(17)
            print(i)
            time.sleep(0.1)

t = Thread(target=mess)
t.daemon = True
t.start()

print("thread started")
