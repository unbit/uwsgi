# run it with:
# export SPOOLER_DIR=t/python/spooler_priority/temporary_spooler; # or your spooler dir
# ./uwsgi t/python/spooler_decorators/spooler_decorator_test.ini

import unittest
import uwsgi
import spooler_handlers
from os import remove, path


class BitmapTest(unittest.TestCase):

    def setUp(self):
        try:
            remove(spooler_handlers.ghostpath)
        except OSError:  # file does not exist
            pass

        spooler_handlers.controlled_task.spool(arg='alive', ghost='world')
        spooler_handlers.controlled_task.spool(arg='barbis')
        spooler_handlers.controlled_raw_task.spool(arg='alive', ghost='world')
        spooler_handlers.controlled_raw_task.spool(arg='barbis')
        spooler_handlers.controlled_arguments_task.spool(
            {'key': 'value'}, 2, key1='value1')

        for i in range(5):
            uwsgi.signal_wait(20)
        print("Signal received!")

    def test_spooler(self):
        self.assertFalse(path.exists(spooler_handlers.ghostpath))

unittest.main()
