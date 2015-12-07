# uwsgi --spooler-external ../other_app/myspool --mule --mule --wsgi-file t/spooler/read.py --http :8080

from uwsgidecorators import spoolraw, muleloop

import uwsgi
import time
import collections
import random
import os

spooling_directory = "../other_app/myspool"

@muleloop(1)
def reader():
    c = collections.Counter()

    for file in os.listdir(spooling_directory):
        try:
            c[uwsgi.spooler_get_task(spooling_directory + "/" + file)["dest"]] += 1
        except Exception as e:
            print(e)

    print(c)
    time.sleep(5)

projects = ["uwsgi", "python", "ruby", "nginx", "memcache"]

@muleloop(2)
def producer():
    uwsgi.spool(ud_spool_func="consumer", dest=random.choice(projects))
    time.sleep(2)
