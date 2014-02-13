import uwsgi
import unittest

class BitmapTest(unittest.TestCase):

    __caches__ = ['items_1', 'items_2', 'items_3', 'items_4']

    def setUp(self):
        for cache in self.__caches__:
            uwsgi.cache_clear(cache)

    def test_failed_by_one(self):
        self.assertFalse(uwsgi.cache_update('key1', 'HELLO', 0, 'items_1'))

    def test_ok_four_bytes(self):
        self.assertTrue(uwsgi.cache_update('key1', 'HELL', 0, 'items_1'))

    def test_two_items_using_four_blocks(self):
        self.assertTrue(uwsgi.cache_update('key1', 'HE', 0, 'items_2'))
        self.assertTrue(uwsgi.cache_update('key2', 'LL', 0, 'items_2'))
        self.assertTrue(uwsgi.cache_del('key1', 'items_2'))
        self.assertFalse(uwsgi.cache_update('key1', 'HEL', 0, 'items_2'))
        self.assertTrue(uwsgi.cache_update('key1', 'HE', 0, 'items_2'))

    def test_overlapping(self):
        self.assertTrue(uwsgi.cache_update('key1', 'HE', 0, 'items_2'))
        self.assertFalse(uwsgi.cache_update('key1', 'HELL', 0, 'items_2'))
        self.assertTrue(uwsgi.cache_del('key1', 'items_2')) 
        self.assertTrue(uwsgi.cache_update('key1', 'HELL', 0, 'items_2'))


unittest.main()
