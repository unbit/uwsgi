#! /usr/bin/env python2
# coding = utf-8

import uwsgi
import unittest
import os
import fcntl
from shutil import rmtree
import time


def spoolersTaskList():
	# Get the list of tasks
	tasks = [
			os.path.join(s, fn)
			for s in uwsgi.spoolers
			for fn in os.listdir(s)
		]

	for t in tasks[:]:
		if os.path.isdir(t):
			tasks += [os.path.join(t, fn) for fn in os.listdir(t)]
			tasks.remove(t)

	return tasks


def is_locked(filepath):
	# Check if file is locked
	with open(filepath, "a+") as f:
		try:
			fcntl.lockf(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
			is_locked = False
		except IOError:
			is_locked = True
	return is_locked


def lockedTasks(tasklist):
	# List of locked tasks
	return [fp for fp in spoolersTaskList() if is_locked(fp)]


def taskParameters(filepath):
	# Retrieve parameters
	return uwsgi.parsefile(filepath)


def cleanTasks():
	# Clean the spooler (debug)
	for s in uwsgi.spoolers:
		for f in os.listdir(s):
			path = os.path.join(s, f)
			if os.path.isdir(path):
				rmtree(os.path.join(s, f))
			else:
				os.remove(path)


class BitmapTest(unittest.TestCase):

	__priorities__ = [
		(101, "101"),
		(101, "101Bis"),
		(2, "2"),
		(1, "1"),
		(0, "0"),
		(None, "NoPriority")
	]

	def setUp(self):
		for priority, name in self.__priorities__:
			task = {'name': name}
			if priority is not None:
				task['priority'] = str(priority)

			uwsgi.spool(task, at=int(time.time() + 5))

	def test_priority(self):
		# maxPriority = lambda prioritiesList: min([p for p, n in prioritiesList if p])

		for i in self.__priorities__:
			uwsgi.signal_wait(17)
			print("Signal received")

			# TODO
			# Check the task priority and then unlock (missing code) the spooler handler to complete the task
			# @Roberto: I had this part implemented, but I removed it in order to debug the "lock"
			self.assertTrue(True)

unittest.main()

# This is an example of log I get, and then it stalls.
# [uWSGI] getting INI configuration from t/python/spooler.ini
# *** Starting uWSGI 2.0.7 (64bit) on [Thu Sep 11 12:57:53 2014] ***
# compiled with version: 4.2.1 Compatible Apple LLVM 5.1 (clang-503.0.40) on 10 September 2014 15:37:37
# os: Darwin-13.3.0 Darwin Kernel Version 13.3.0: Tue Jun  3 21:27:35 PDT 2014; root:xnu-2422.110.17~1/RELEASE_X86_64
# nodename: AldursMacbook.local
# machine: x86_64
# clock source: unix
# pcre jit disabled
# detected number of CPU cores: 4
# current working directory: /Users/aldur/Lavoro/uWSGI/uwsgi-git
# detected binary path: /Users/aldur/Lavoro/uWSGI/uwsgi-git/uwsgi
# your processes number limit is 709
# your memory page size is 4096 bytes
# detected max file descriptor number: 256
# lock engine: OSX spinlocks
# thunder lock: disabled (you can enable it with --thunder-lock)
# uwsgi socket 0 bound to UNIX address /tmp/temporary-socket fd 3
# Python version: 2.7.8 (default, Aug 24 2014, 21:26:19)  [GCC 4.2.1 Compatible Apple LLVM 5.1 (clang-503.0.40)]
# *** Python threads support is disabled. You can enable it with --enable-threads ***
# Python main interpreter initialized at 0x7fcd6be01270
# your mercy for graceful operations on workers is 60 seconds
# mapped 145520 bytes (142 KB) for 1 cores
# *** Operational MODE: command ***
# *** uWSGI is running in multiple interpreter mode ***
# spawned uWSGI master process (pid: 82412)
# spawned the uWSGI spooler on dir /Users/aldur/Lavoro/uWSGI/uwsgi-git/t/python/temporary-spooler with pid 82413
# spawned uWSGI worker 1 (pid: 82414, cores: 1)
# [spooler] written 30 bytes to file /Users/aldur/Lavoro/uWSGI/uwsgi-git/t/python/temporary-spooler/101/uwsgi_spoolfile_on_AldursMacbook.local_82414_1_1425796099_1410433073_757564
# [spooler] written 33 bytes to file /Users/aldur/Lavoro/uWSGI/uwsgi-git/t/python/temporary-spooler/101/uwsgi_spoolfile_on_AldursMacbook.local_82414_2_1732502667_1410433073_758202
# [spooler /Users/aldur/Lavoro/uWSGI/uwsgi-git/t/python/temporary-spooler pid: 82413] managing request uwsgi_spoolfile_on_AldursMacbook.local_82414_1_1425796099_1410433073_757564 ...
# [spooler] written 26 bytes to file /Users/aldur/Lavoro/uWSGI/uwsgi-git/t/python/temporary-spooler/2/uwsgi_spoolfile_on_AldursMacbook.local_82414_3_441554596_1410433073_758481
# [spooler] written 26 bytes to file /Users/aldur/Lavoro/uWSGI/uwsgi-git/t/python/temporary-spooler/1/uwsgi_spoolfile_on_AldursMacbook.local_82414_4_1652094587_1410433073_758799
# [spooler] written 26 bytes to file /Users/aldur/Lavoro/uWSGI/uwsgi-git/t/python/temporary-spooler/0/uwsgi_spoolfile_on_AldursMacbook.local_82414_5_1937651646_1410433073_759068
# [spooler] written 22 bytes to file /Users/aldur/Lavoro/uWSGI/uwsgi-git/t/python/temporary-spooler/uwsgi_spoolfile_on_AldursMacbook.local_82414_6_1669191214_1410433073_759288
# 101
# [spooler /Users/aldur/Lavoro/uWSGI/uwsgi-git/t/python/temporary-spooler pid: 82413] done with task uwsgi_spoolfile_on_AldursMacbook.local_82414_1_1425796099_1410433073_757564 after 0 seconds
# Signal received
# [spooler /Users/aldur/Lavoro/uWSGI/uwsgi-git/t/python/temporary-spooler pid: 82413] managing request uwsgi_spoolfile_on_AldursMacbook.local_82414_2_1732502667_1410433073_758202 ...
# 101Bis
# [spooler /Users/aldur/Lavoro/uWSGI/uwsgi-git/t/python/temporary-spooler pid: 82413] done with task uwsgi_spoolfile_on_AldursMacbook.local_82414_2_1732502667_1410433073_758202 after 0 seconds
# Signal received
# XXX: Stall here!
