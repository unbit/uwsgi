# uswgi

from uwsgidecorators import spoolraw, muleloop

import uwsgi
import time
import collections
import random
import os

@muleloop(1)
def reader():
    c = collections.Counter()

    for file in os.listdir("myspool"):
        try:
            c[uwsgi.spooler_get_task("myspool/" + file)["dest"]] += 1
        except Exception:
            pass

    print(c)
    time.sleep(5)

projects = ["uwsgi", "python", "ruby", "nginx", "memcache"]

@muleloop(2)
def producer():
    uwsgi.spool(ud_spool_func="consumer", dest=random.choice(projects))
    time.sleep(2)

@spoolraw
def consumer(args):
    print("project : " + args["dest"])
    time.sleep(3)
    return uwsgi.SPOOL_OK
