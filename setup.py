import os

os.system("make")

from distutils.core import setup

setup(name='uWSGI',
      version='0.9.4',
      description='The uWSGI server',
      author='Roberto De Ioris',
      author_email='roberto@unbit.it',
      url='http://projects.unbit.it/uwsgi/',
      license='GPL2',
      scripts=['uwsgi'],
     )



