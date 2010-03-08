import os
import sys
import uwsgiconfig as uc
import shutil

print "SETUP.PY"
print sys.argv
print "SETUP.PY"

from distutils.core import setup

uc.build_uwsgi(uc.UWSGI_BIN_NAME, uc.uver, uc.cflags, uc.ldflags)

shutil.copy(uc.UWSGI_BIN_NAME, sys.prefix + '/bin')

setup(name='uWSGI',
      version='0.9.5',
      description='The uWSGI server',
      author='Unbit',
      author_email='info@unbit.it',
      url='http://projects.unbit.it/uwsgi/',
      license='GPL2',
     )



