#! /usr/bin/env python2
# coding = utf-8

from __future__ import print_function
import uwsgi


def spoolerHandler(env):
	# Spooler is handling a task
	uwsgi.signal(17)
	print("%s" % env['name'])

	# Spooler has done handling the task
	return uwsgi.SPOOL_OK

uwsgi.spooler = spoolerHandler
