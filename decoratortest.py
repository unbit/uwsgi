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

