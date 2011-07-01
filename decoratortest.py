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

# run a task every hour
@cron(59, -1, -1, -1, -1)
def one_hour_passed(num):
    print("received signal %d after 1 hour" % num)


@postfork
def fork_happened():
    print("fork() has been called [1]")

@postfork
def fork_happened2():
    print("fork() has been called [2] wid: %d" % uwsgi.worker_id())

a_long_task.spool({'foo':'bar'}, hello='world')
an_infinite_task.spool(foo='bar')
