# uwsgi --spooler spool1 --spooler spool2 --spooler-cheap --spooler-frequency 5 --spooler-processes 4 --mule --shared-py-import=t/spooler/cheap.py --stats :5000
from uwsgidecorators import *
import time
import random
import os

def fake(args):
    time.sleep(6)
    return uwsgi.SPOOL_OK

uwsgi.spooler = fake

base = os.getcwd()
spoolers = [base + '/spool1', base + '/spool2']

@mule(1)
def spooler_enqueuer():
    while True:
        print("enqueuing task...")
        uwsgi.spool({'one':'two', 'spooler': random.choice(spoolers)})
        time.sleep(random.randrange(1, 15))
