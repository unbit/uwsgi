import os
import sys
import uwsgiconfig as uc
import shutil

from setuptools import setup
from setuptools.dist import Distribution
from setuptools.command.install import install
from setuptools.command.build_ext import build_ext


def patch_bin_path(cmd, conf):

    bin_name = conf.get('bin_name')

    try:
        if not os.path.exists(cmd.install_scripts):
            os.makedirs(cmd.install_scripts)
        if not os.path.isabs(bin_name):
            print('Patching "bin_name" to properly install_scripts dir')
            conf.set('bin_name', os.path.join(cmd.install_scripts, conf.get('bin_name')))
    except:
        conf.set('bin_name', sys.prefix + '/bin/' + bin_name)


class uWSGIBuilder(build_ext):

    def run(self):
        conf = uc.uConf('buildconf/default.ini')
        patch_bin_path(self, conf)
        uc.build_uwsgi( conf )


class uWSGIInstall(install):

    def run(self):
        # hack, hack and still hack. We need to find a solution...
        if self.record:
            record_file = open(self.record,'w')

        conf = uc.uConf('buildconf/default.ini')
        patch_bin_path(self, conf)
        uc.build_uwsgi( conf )

class uWSGIDistribution(Distribution):

    def __init__(self, *attrs):
        Distribution.__init__(self, *attrs)
        self.cmdclass['install'] = uWSGIInstall
        self.cmdclass['build_ext'] = uWSGIBuilder


setup(name='uWSGI',
      version='0.9.7.2',
      description='The uWSGI server',
      author='Unbit',
      author_email='info@unbit.it',
      url='http://projects.unbit.it/uwsgi/',
      license='GPL2',
      distclass = uWSGIDistribution,
     )

