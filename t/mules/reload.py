import os
import unittest
import time
from subprocess import Popen, PIPE


def touch(fname):
    with open(fname, 'a'):
        os.utime(fname, None)
    return


def pgrep_mules():
    cmd = ["pgrep", "-f", "uWSGI mule"]
    proc = Popen(cmd, stdout=PIPE)
    rv = set(map(int, proc.stdout.readlines()))
    proc.terminate()
    return rv


class MuleReloadingTest(unittest.TestCase):

    def test_reloading(self):
        try:
            uwsgi = Popen(["./uwsgi", "--master", "--mule", "--touch-mules-reload=/tmp/reload", "--socket=:0", "--auto-procname"])
            subprocesses = pgrep_mules()
            touch("/tmp/reload")
            time.sleep(1)
            new_subprocesses = pgrep_mules()
            proc_intersect = subprocesses.intersection(new_subprocesses)
            self.assertFalse(proc_intersect)
        finally:
            uwsgi.terminate()


if __name__ == "__main__":
    unittest.main()
