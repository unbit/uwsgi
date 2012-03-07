import uwsgi
import threading
import time
import sys

def monitor1():
	while 1:
		time.sleep(1)
		print("i am the monitor 1")

def monitor2():
	while 1:
		time.sleep(2)
		print("i am the monitor 2")
		print(sys.modules)

def monitor3():
	while 1:
		time.sleep(5)
		print("5 seconds elapsed")
		#reload(fake)
    
def spawn_my_magic_threads():
	print("^^^ spawning magic threads ^^^")
	t = threading.Thread(target=monitor1).start()
	t2 = threading.Thread(target=monitor2).start()
	t3 = threading.Thread(target=monitor3).start()

uwsgi.post_fork_hook = spawn_my_magic_threads


def application(e, s):
	s('200 Ok', [('Content-Type','text/html')])
	return "Hello Threaded World !!!"
