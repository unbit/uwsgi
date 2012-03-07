from uwsgidecorators import *
import Queue
from threading import Thread

queues = {}

class queueconsumer(object):

    def __init__(self, name, num=1, **kwargs):
        self.name = name
	self.num = num
        self.queue = Queue.Queue()
	self.threads = []
	self.func = None
	queues[self.name] = self


    @staticmethod
    def consumer(self):
        while True:
	    req = self.queue.get()
            print req
	    self.func(req)
	    self.queue.task_done()

    def __call__(self, f):
        self.func = f
	for i in range(self.num):
	    t = Thread(target=self.consumer,args=(self,))	
	    self.threads.append(t)
	    t.daemon = True
	    t.start()

@spool
def spooler_enqueuer(arguments):
    if 'queue' in arguments:
        queue = arguments['queue']
        queues[queue].queue.put(arguments)
    else:
        raise Exception("You have to specify a queue name")


def enqueue(*args, **kwargs):
    return spooler_enqueuer.spool(*args, **kwargs)
