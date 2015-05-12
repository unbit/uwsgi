import uwsgi
import unittest

class SharedareaTest(unittest.TestCase):

    def setUp(self):
        uwsgi.sharedarea_write(0, 0, '\0' * 64)

    def test_32(self):
        uwsgi.sharedarea_write32(0, 0, 17)
        self.assertEqual(uwsgi.sharedarea_read32(0, 0), 17)

    def test_inc32(self):
        uwsgi.sharedarea_write32(0, 4, 30)
        uwsgi.sharedarea_inc32(0, 4, 3)
        self.assertEqual(uwsgi.sharedarea_read32(0, 4), 33)

    def test_dec32(self):
        uwsgi.sharedarea_write32(0, 5, 30)
        uwsgi.sharedarea_dec32(0, 5, 4)
        self.assertEqual(uwsgi.sharedarea_read32(0, 5), 26)

    def test_inc64(self):
        uwsgi.sharedarea_write64(0, 8, 17 * (1024 ** 5))
        uwsgi.sharedarea_inc64(0, 8, 1)
        self.assertEqual(uwsgi.sharedarea_read64(0, 8), 17 * (1024 ** 5) + 1)

    def test_dec64(self):
        uwsgi.sharedarea_write64(0, 8, 30 * (1024 ** 5))
        uwsgi.sharedarea_dec64(0, 8, 30 * (1024 ** 5) - 1)
        self.assertEqual(uwsgi.sharedarea_read64(0, 8), 1)
    

unittest.main()
