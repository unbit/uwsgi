#! /usr/bin/env python2
# coding = utf-8

import uwsgi
import unittest
import os
import fcntl
from shutil import rmtree
import time
import constants
from signal import *


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
	# Clean any remaining task
	for s in uwsgi.spoolers:
		for f in os.listdir(s):
			path = os.path.join(s, f)
			if os.path.isdir(path):
				rmtree(os.path.join(s, f))
			else:
				os.remove(path)


class BitmapTest(unittest.TestCase):

	def setUp(self):
		self.addCleanup(cleanTasks)
		for priority, name in constants.tasks:
			task = {'name': name, 'at': int(time.time() + 10)}
			if priority is not None:
				task['priority'] = str(priority)
			uwsgi.spool(task)

	def test_priority(self):
		uwsgi.signal_wait(17)
		print("Signal received.")

		with open(constants.LOGFILE, "r") as log:
			# Check logging ordering.
			loglines = [line.rstrip() for line in log]
			self.assertEqual(loglines, constants.ordered_tasks)

signal(SIGINT, cleanTasks)
unittest.main()

