#!./uwsgi --import decoratortest -s :3035 -M --spooler myspool --enable-threads -p 8 --spooler-ordered
import uwsgi

from uwsgidecorators import *

from uwsgicc import app as application

import time


# register rpc function helloworld
@rpc("helloworld")
def hello_world():
    return "Hello World"

# register signal 1
@signal(1)
def what_time_is_it(num):
    print(time.asctime())

# register signal 100
@signal(100, target='workers')
def what_time_is_it(num):
    print("*** I AM THE WORKER %d AT %s ***" % (uwsgi.worker_id(), time.asctime()))


# a 3 seconds timer
@timer(3)
def salut(num):
    print("Salut !!! 3 seconds elapsed and signal %d raised" % num)

# a 10 seconds red black timer (executed by the spooler)
@rbtimer(10, target='spooler')
def tenseconds(num):
    print("red black timer !!! 10 seconds elapsed and signal %d raised" % num)

# monitor /tmp directory
@filemon("/tmp")
def tmpmodified(num):
    print("/tmp has been modified")


# spool a long running task
@spool
def a_long_task(args):
    for i in xrange(1,10):
        print("%s = %d" % ( str(args), i))
        time.sleep(1)

# continuosly spool a long running task
@spoolforever
def an_infinite_task(args):
    for i in xrange(1,4):
        print("infinite: %d %s" % (i, str(args)))
        time.sleep(1)


# spool a task after 60 seconds
@spool
def delayed_task(args):
    print("*** I am a delayed spool job. It is %s [%s]***" % (time.asctime(), str(args)))
    # send a signal to all workers
    uwsgi.signal(100)

@spool
def big_body_task(args):
    print("*** managing a task with a body of %d bytes ***" % len(args['body']))
    print(args['body'].swapcase()) 

# run a task every hour
@cron(59, -1, -1, -1, -1)
def one_hour_passed(num):
    print("received signal %d after 1 hour" % num)

@thread
def a_running_thread():
    while True:
        time.sleep(2)
        print("i am a no-args thread")

@thread
def a_running_thread_with_args(who):
    while True:
        time.sleep(2)
        print("Hello %s (from arged-thread)" % who)

@postfork
@thread
def a_post_fork_thread():
    while True:
        time.sleep(3)
        print("Hello from a thread in worker %d" % uwsgi.worker_id())

@postfork
def fork_happened():
    print("fork() has been called [1]")

@postfork
def fork_happened2():
    print("waiting for a signal...")
    uwsgi.signal_wait()
    print("signal received: %d" % uwsgi.signal_received())
    print("fork() has been called [2] wid: %d" % uwsgi.worker_id())

@postfork
@lock
def locked_func():
    print("starting locked function on worker %d" % uwsgi.worker_id())
    for i in xrange(1, 100):
        time.sleep(0.2)
        print("[locked %d] waiting..." % uwsgi.worker_id())
    print("done with locked function on worker %d" % uwsgi.worker_id())

spool_filename = a_long_task.spool({'foo':'bar'}, hello='world')
print("spool filename = %s" % spool_filename)
an_infinite_task.spool(foo='bar', priority=3)
delayed_task.spool(foo2='bar2', at=time.time()+60)
a_running_thread()
a_running_thread_with_args("uWSGI")
uwsgi_source_file = open('uwsgi.c','r')
print(big_body_task.spool(priority=9,filename='uwsgi.c',body=uwsgi_source_file.read()))
uwsgi_source_file.close()
