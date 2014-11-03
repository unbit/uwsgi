# See spooler_decorator_tests

from uwsgidecorators import *
import uwsgi

ghostpath = "/tmp/ghost"


@spool(pass_arguments=True)
def controlled_arguments_task(*args, **kwargs):
    if args != ({'key': 'value'}, 2) or kwargs != {'key1': 'value1'}:
        print("We have a problem!")
        open(ghostpath, 'w').close()
    uwsgi.signal(20)


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
