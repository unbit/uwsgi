from threading import Thread
import time

def mess():
    while True:
        for i in xrange(0, 100):
            print(i)
            time.sleep(0.1)

t = Thread(target=mess)
t.daemon = True
t.start()

print("thread started")
