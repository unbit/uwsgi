# See spooler_decorator_tests

from uwsgidecorators import *
import uwsgi

ghostpath = "/tmp/ghost"


@spool
def controlled_task(arguments):
    if arguments['arg'] != 'alive' and 'ghost' in arguments:
        print("We have a problem!")
        open(ghostpath, 'w').close()
    uwsgi.signal(20)


@spoolraw
def controlled_raw_task(arguments):
    if arguments['arg'] != 'alive' and 'ghost' in arguments:
        print("We have a problem!")
        open(ghostpath, 'w').close()
    uwsgi.signal(20)
    return uwsgi.SPOOL_OK
