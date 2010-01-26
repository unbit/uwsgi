import os
import sys

print "ARGV:",sys.argv
version = sys.version_info

if version[0] > 2:
	print("python 3.x is not supported")
	sys.exit()

print("detected python version %d.%d" % (version[0], version[1]))

uver = "%d%d" % (version[0], version[1])
bin_name = "uwsgi"
make_cmd = "make"

if uver != "25":
	bin_name = "%s%s" % (bin_name, uver)
	make_cmd = "%s -f Makefile.Py%s" % (make_cmd, uver) 

from distutils.core import setup
from distutils.command.build import build as _build
from distutils.command.install import install as _install
from distutils.command.install_data import install_data


print "PREFIX:",sys.prefix

class install(_install):
	def run(self):
		os.system(make_cmd)

os.system(make_cmd)

class build(_build):
	def run(self):
		os.system(make_cmd)

datafiles = [ ('bin', [bin_name]) ]



setup(name='uWSGI',
      version='0.9.4',
      description='The uWSGI server',
      author='Roberto De Ioris',
      author_email='roberto@unbit.it',
      url='http://projects.unbit.it/uwsgi/',
      license='GPL2',
      data_files = datafiles,	
      cmdclass = { 'build': build, 'install': install  }
     )



