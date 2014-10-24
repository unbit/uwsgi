#! /usr/bin/env python3
# coding = utf-8
# author = Adriano Di Luzio

# I require requests!

"""
First run:
    $ ./uwsgi t/python/manage_script_name/manage_script_name_test.ini

Then run me!
"""

import unittest
import requests

HOST = "http://127.0.0.1:8080"


class ManageScriptNameTest(unittest.TestCase):

    def test_classic_mountpoints(self):
        mps = {
            "/foo",
            "/foobis/",
            "/footris/"
        }

        for mp in mps:
            # Requests to /foo should kick-in the managed script name.
            r = requests.get(HOST + mp)
            self.assertEqual(r.text, mp)

            ends = mp.endswith("/")

            # And equally requests to /foo/
            r = requests.get(
                HOST + mp + "/") if not ends else requests.get(HOST + mp[:-1])
            self.assertEqual(r.text, mp)

            # Or correct requests (/foo/resource)
            r = requests.get(
                HOST + mp + "/" + "resource") if not ends else requests.get(HOST + mp + "resource")
            self.assertEqual(r.text, mp)

    def test_intriguing_mountpoints(self):
        mps = {
            "/fooanything",
            "/foobisis/",
            "/foofighters",
        }

        for mp in mps:
            r = requests.get(HOST + mp)
            self.assertEqual(r.text, "")


if __name__ == '__main__':
    unittest.main(verbosity=2)
