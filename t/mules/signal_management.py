import unittest
import subprocess
import time

class SignalHandlingTest(unittest.TestCase):

    def test_int_mercyless(self):
        started_at = int(time.time())
        ret = subprocess.call(['./uwsgi', '--master', '--mule=t/mules/mulebrain.py', '--py-call-osafterfork', '--socket=:0', '--mule-reload-mercy=1'])
        self.assertEqual(ret, 0)
        self.assertLess(int(time.time()) - started_at, 6)

    def test_int(self):
        started_at = int(time.time())
        ret = subprocess.call(['./uwsgi', '--set=test_mule_timeout=3', '--master', '--mule=t/mules/mulebrain.py', '--py-call-osafterfork', '--socket=:0'])
        self.assertEqual(ret, 0)
        self.assertLess(int(time.time()) - started_at, 8)

    def test_hup(self):
        started_at = int(time.time())
        ret = subprocess.call(['./uwsgi', '--set=test_signal=1', '--set=test_mule_timeout=3', '--exit-on-reload', '--master', '--mule=t/mules/mulebrain.py', '--py-call-osafterfork', '--socket=:0'])
        self.assertEqual(ret, 0)
        self.assertLess(int(time.time()) - started_at, 8)

    def test_int_with_threads(self):
        started_at = int(time.time())
        ret = subprocess.call(['./uwsgi', '--enable-threads', '--set=test_mule_timeout=3', '--master', '--mule=t/mules/mulebrain.py', '--py-call-osafterfork', '--socket=:0'])
        self.assertEqual(ret, 0)
        self.assertLess(int(time.time()) - started_at, 8)
        

if __name__ == '__main__':
    unittest.main()
