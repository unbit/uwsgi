import os
import sys
import uwsgiconfig as uc
import shutil

from distutils.core import setup, Distribution
from distutils.command.install import install
from distutils.command.build_ext import build_ext


def is_yes(x, d):
	if x is None:
		x = d
	if x == 'y' or x == 'Y':
		return True
	return False

class uWSGIBuilder(build_ext):

	def run(self):
		uc.XML = is_yes( raw_input("enable XML ? y/n [y]>"), 'y' )
		uc.SNMP = is_yes( raw_input("enable SNMP ? y/n [n]>"), 'n' )
		uc.SPOOLER = is_yes( raw_input("enable SPOOLER ? y/n [y]>"), 'y' )
		uc.EMBEDDED = is_yes( raw_input("enable EMBEDDED uwsgi module ? y/n [y]>"), 'y' )
		uc.UDP = is_yes( raw_input("enable UDP ? y/n [y]>"), 'y' )
		uc.THREADING = is_yes( raw_input("enable THREADING ? y/n [y]>"), 'y' )
		uc.SENDFILE = is_yes( raw_input("enable SENDFILE ? y/n [y]>"), 'y' )
		uc.PROFILER = is_yes( raw_input("enable PROFILER ? y/n [y]>"), 'y' )
		uc.NAGIOS = is_yes( raw_input("enable NAGIOS ? y/n [y]>"), 'y' )
		uc.PROXY = is_yes( raw_input("enable PROXY ? y/n [y]>"), 'y' )
		uc.ERLANG = is_yes( raw_input("enable ERLANG ? y/n [n]>"), 'n' )
		uc.SCTP = is_yes( raw_input("enable *experimental* SCTP ? y/n [n]>"), 'n' )
		uc.parse_vars()
		uc.build_uwsgi(sys.prefix + '/bin/' + uc.UWSGI_BIN_NAME, uc.uver, uc.cflags, uc.ldflags)


class uWSGIInstall(install):

	def run(self):
		uc.parse_vars()
		uc.build_uwsgi(sys.prefix + '/bin/' + uc.UWSGI_BIN_NAME, uc.uver, uc.cflags, uc.ldflags)

class uWSGIDistribution(Distribution):

	def __init__(self, *attrs):
		Distribution.__init__(self, *attrs)
		self.cmdclass['install'] = uWSGIInstall
		self.cmdclass['build_ext'] = uWSGIBuilder
		


setup(name='uWSGI',
      version='0.9.5',
      description='The uWSGI server',
      author='Unbit',
      author_email='info@unbit.it',
      url='http://projects.unbit.it/uwsgi/',
      license='GPL2',
      distclass = uWSGIDistribution,
     )



