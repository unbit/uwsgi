from __future__ import print_function

from tasksconsumer import queueconsumer


@queueconsumer('fast', 4)
def fast_queue(arguments):
    print("fast", arguments)


@queueconsumer('slow')
def slow_queue(arguments):
    print("foobar", arguments)
