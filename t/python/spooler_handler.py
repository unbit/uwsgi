#! /usr/bin/env python2
# coding = utf-8

from __future__ import print_function
from constants import tasks, LOGFILE
from os import remove
import uwsgi

counter = 0


def spoolerHandler(env):
    global counter
    # Spooler is handling a task
    with open(LOGFILE, "a") as log:
        print("%s" % (env['name']), file=log)

    counter += 1

    if counter == len(tasks):
        # Each task has been processed.
        uwsgi.signal(17)

    # Spooler has done handling the task
    return uwsgi.SPOOL_OK

uwsgi.spooler = spoolerHandler

# Clear the logfile
try:
    remove(LOGFILE)
except OSError, e:  # log does not exist
    pass
    # print(e)
