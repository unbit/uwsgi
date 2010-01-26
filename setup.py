import os
import sys
import shutil

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

os.system(make_cmd)

shutil.copy(bin_name, sys.prefix + '/bin')

setup(name='uWSGI',
      version='0.9.4',
      description='The uWSGI server',
      author='Roberto De Ioris',
      author_email='roberto@unbit.it',
      url='http://projects.unbit.it/uwsgi/',
      license='GPL2',
     )



