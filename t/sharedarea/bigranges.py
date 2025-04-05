import uwsgi
import unittest

class SharedareaTest(unittest.TestCase):

    def test_32(self):
        pos = 2 * (1024 ** 3)
        uwsgi.sharedarea_write32(0, pos, 17)
        self.assertEqual(uwsgi.sharedarea_read32(0, pos), 17)

    def test_64(self):
        pos = 2 * (1024 ** 3)
        uwsgi.sharedarea_write64(0, pos, 30)
        self.assertEqual(uwsgi.sharedarea_read64(0, pos), 30)

unittest.main()
