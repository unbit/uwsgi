import uwsgi
from uwsgidecorators import *

from uwsgicc import app as application

import time


@rpc("helloworld")
def hello_world():
    return "Hello World"

@signal(1)
def what_time_is_it(num):
    print(time.asctime())


@timer(2, 3)
def salut(num):
    print("Salut !!! 3 seconds elapsed and signal %d raised" % num)

@rbtimer(3, 10)
def tenseconds(num):
    print("red black timer !!! 10 seconds elapsed and signal %d raised" % num)

@filemon(4, "/tmp")
def tmpmodified(num):
    print("/tmp has been modified")
