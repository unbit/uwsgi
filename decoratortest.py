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

# a 10 seconds red black timer
@rbtimer(10)
def tenseconds(num):
    print("red black timer !!! 10 seconds elapsed and signal %d raised" % num)

# monitor /tmp directory
@filemon("/tmp")
def tmpmodified(num):
    print("/tmp has been modified")


# spool a long running task
@spool
def a_long_task(vars):
    for i in xrange(1,10):
        print(i)
        time.sleep(1)

# continuosly spool a long task
@spoolforever
def an_infinite_task(vars):
    for i in xrange(1,4):
        print("infinite: %d" % i)
        time.sleep(1)


a_long_task.spool(foo='bar')
an_infinite_task.spool(foo='bar')
