import uwsgi
import unittest
import random
import string


class BitmapTest(unittest.TestCase):

    __caches__ = [
        'items_1',
        'items_2',
        'items_3',
        'items_4',
        'items_17',
        'items_4_10',
        'items_1_100000',
        'items_non_bitmap',
        'items_lru'
    ]

    def setUp(self):
        for cache in self.__caches__:
            uwsgi.cache_clear(cache)

    def test_failed_by_one(self):
        self.assertIsNone(uwsgi.cache_update('key1', 'HELLO', 0, 'items_1'))

    def test_ok_four_bytes(self):
        self.assertTrue(uwsgi.cache_update('key1', 'HELL', 0, 'items_1'))

    def test_two_items_using_four_blocks(self):
        self.assertTrue(uwsgi.cache_update('key1', 'HE', 0, 'items_2'))
        self.assertTrue(uwsgi.cache_update('key2', 'LL', 0, 'items_2'))
        self.assertTrue(uwsgi.cache_del('key1', 'items_2'))
        self.assertIsNone(uwsgi.cache_update('key1', 'HEL', 0, 'items_2'))
        self.assertTrue(uwsgi.cache_update('key1', 'HE', 0, 'items_2'))

    def test_overlapping(self):
        self.assertTrue(uwsgi.cache_update('key1', 'HE', 0, 'items_2'))
        self.assertIsNone(uwsgi.cache_update('key1', 'HELL', 0, 'items_2'))
        self.assertTrue(uwsgi.cache_del('key1', 'items_2'))
        self.assertTrue(uwsgi.cache_update('key1', 'HELL', 0, 'items_2'))

    def test_big_item(self):
        self.assertIsNone(uwsgi.cache_update('key1', 'HELLOHELLOHELLOHEL', 0, 'items_17'))
        self.assertTrue(uwsgi.cache_update('key1', 'HELLOHELLOHELLOHE', 0, 'items_17'))

    def test_set(self):
        self.assertTrue(uwsgi.cache_set('key1', 'HELLO', 0, 'items_17'))
        self.assertIsNone(uwsgi.cache_set('key1', 'HELLO', 0, 'items_17'))
        self.assertTrue(uwsgi.cache_del('key1', 'items_17'))
        self.assertTrue(uwsgi.cache_set('key1', 'HELLO', 0, 'items_17'))
        self.assertIsNone(uwsgi.cache_set('key1', 'HELLO', 0, 'items_17'))

    def test_too_much_items(self):
        self.assertTrue(uwsgi.cache_set('key1', 'HELLO', 0, 'items_4_10'))
        self.assertTrue(uwsgi.cache_set('key2', 'HELLO', 0, 'items_4_10'))
        self.assertTrue(uwsgi.cache_set('key3', 'HELLO', 0, 'items_4_10'))
        self.assertTrue(uwsgi.cache_set('key4', 'HELLO', 0, 'items_4_10'))
        self.assertIsNone(uwsgi.cache_set('key5', 'HELLO', 0, 'items_4_10'))

    def test_big_delete(self):
        self.assertTrue(uwsgi.cache_set('key1', 'X' * 50, 0, 'items_4_10'))
        self.assertTrue(uwsgi.cache_del('key1', 'items_4_10'))
        self.assertTrue(uwsgi.cache_set('key1', 'HELLOHELLO', 0, 'items_4_10'))
        self.assertTrue(uwsgi.cache_set('key2', 'HELLOHELLO', 0, 'items_4_10'))
        self.assertTrue(uwsgi.cache_set('key3', 'HELLOHELLO', 0, 'items_4_10'))
        self.assertTrue(uwsgi.cache_set('key4', 'HELLOHELLO', 0, 'items_4_10'))
        self.assertIsNone(uwsgi.cache_set('key5', 'HELLOHELLO', 0, 'items_4_10'))

    def test_big_update(self):
        self.assertTrue(uwsgi.cache_set('key1', 'X' * 40, 0, 'items_4_10'))
        self.assertTrue(uwsgi.cache_update('key1', 'X' * 10, 0, 'items_4_10'))
        self.assertTrue(uwsgi.cache_del('key1', 'items_4_10'))
        self.assertIsNone(uwsgi.cache_update('key1', 'X' * 51, 0, 'items_4_10'))
        self.assertTrue(uwsgi.cache_update('key1', 'X' * 50, 0, 'items_4_10'))

    def test_multi_clear(self):
        for i in range(0, 100):
            self.assertTrue(uwsgi.cache_clear('items_4_10'))

    def test_multi_delete(self):
        for i in range(0, 100):
            self.assertTrue(uwsgi.cache_set('key1', 'X' * 50, 0, 'items_4_10'))
            self.assertTrue(uwsgi.cache_del('key1', 'items_4_10'))

        for i in range(0, 100):
            self.assertIsNone(uwsgi.cache_set('key1', 'X' * 51, 0, 'items_4_10'))
            self.assertIsNone(uwsgi.cache_del('key1', 'items_4_10'))

        for i in range(0, 100):
            self.assertTrue(uwsgi.cache_set('key1', 'X' * 50, 0, 'items_4_10'))
            self.assertTrue(uwsgi.cache_del('key1', 'items_4_10'))

    def test_big_key(self):
        self.assertTrue(uwsgi.cache_set('K' * 2048, 'X' * 50, 0, 'items_4_10'))
        self.assertIsNone(uwsgi.cache_set('K' * 2049, 'X' * 50, 0, 'items_4_10'))

    def rand_blob(self, n=32):
        return ''.join(random.choice(string.ascii_letters + string.digits) for x in range(n))

    def test_big_random(self):
        blob = self.rand_blob(100000)
        self.assertTrue(uwsgi.cache_set('KEY', blob, 0, 'items_1_100000'))
        get_blob = uwsgi.cache_get('KEY', 'items_1_100000')
        self.assertEqual(blob, get_blob)
        self.assertTrue(uwsgi.cache_del('KEY', 'items_1_100000'))
        self.assertIsNone(uwsgi.cache_set('KEY', 'X' * 100001, 0, 'items_1_100000'))
        self.assertTrue(uwsgi.cache_set('KEY', 'X' * 10000, 0, 'items_1_100000'))

    def test_non_bitmap(self):
        self.assertTrue(uwsgi.cache_set('KEY', 'X' * 20, 0, 'items_non_bitmap'))
        self.assertTrue(uwsgi.cache_del('KEY', 'items_non_bitmap'))
        self.assertIsNone(uwsgi.cache_set('KEY', 'X' * 21, 0, 'items_non_bitmap'))
        self.assertTrue(uwsgi.cache_set('KEY', 'X' * 20, 0, 'items_non_bitmap'))

    def test_lru(self):
        self.assertTrue(uwsgi.cache_set('KEY1', 'X' * 20, 0, 'items_lru'))
        self.assertTrue(uwsgi.cache_set('KEY2', 'X' * 20, 0, 'items_lru'))
        self.assertTrue(uwsgi.cache_set('KEY3', 'Y' * 20, 0, 'items_lru'))
        self.assertIsNone(uwsgi.cache_get('KEY1', 'items_lru'))
        uwsgi.cache_get('KEY3', 'items_lru')
        for i in range(4, 100):
            self.assertTrue(uwsgi.cache_set('KEY%d' % i, 'Y' * 20, 0, 'items_lru'))
            self.assertIsNone(uwsgi.cache_get('KEY%d' % (i-2), 'items_lru'))

unittest.main()
