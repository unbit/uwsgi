import Queue
from threading import Thread
import uwsgi

CONSUMERS = 4

def consumer(q):
    while True:
        item = q.get()
        print(item)
        #... DO A HEAVY TASK HERE ...
        q.task_done()

def spawn_consumers():
    global q
    q = Queue.Queue()
    for i in range(CONSUMERS):
        t = Thread(target=consumer,args=(q,))
        t.daemon = True
        t.start()
        print("consumer %d on worker %d started" % (i, uwsgi.worker_id()))
    

uwsgi.post_fork_hook = spawn_consumers


def application(env, start_response):
    global q

    # we pass a copy of the env dictionary as it gets cleared after yield/return
    q.put(env.copy())

    start_response('200 OK', [('Content-Type', 'text/html')])

    yield "Task enqueued"
    
