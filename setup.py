import os
import sys
import uwsgiconfig as uc
import shutil

from distutils.core import setup, Distribution
from distutils.command.install import install
from distutils.command.build_ext import build_ext


def is_yes(name, d):
	sys.stderr.write("enable %s ? y/n [%s]>\n" % (name, d))
	x = raw_input()
	if x is None:
		x = d
	if x == 'y' or x == 'Y':
		return True
	return False

class uWSGIBuilder(build_ext):

	def run(self):
		uc.XML = is_yes( "XML", 'y' )
		uc.SNMP = is_yes( "SNMP", 'n' )
		uc.SPOOLER = is_yes( "SPOOLER", 'y' )
		uc.EMBEDDED = is_yes( "EMBEDDED uwsgi module", 'y' )
		uc.UDP = is_yes( "UDP", 'y' )
		uc.THREADING = is_yes( "THREADING", 'y' )
		uc.SENDFILE = is_yes( "SENDFILE", 'y' )
		uc.PROFILER = is_yes( "PROFILER", 'y' )
		uc.NAGIOS = is_yes( "NAGIOS", 'y' )
		uc.PROXY = is_yes( "PROXY", 'y' )
		uc.ERLANG = is_yes( "ERLANG", 'n' )
		uc.SCTP = is_yes( "experimental SCTP", 'n' )
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



