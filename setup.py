import os
import sys
import uwsgiconfig as uc

from setuptools import setup
from setuptools.dist import Distribution
from setuptools.command.install import install
from setuptools.command.install_lib import install_lib
from setuptools.command.build_ext import build_ext

try:
    from wheel.bdist_wheel import bdist_wheel
    HAS_WHEEL = True
except ImportError:
    HAS_WHEEL = False

"""
This is a hack allowing you installing
uWSGI and uwsgidecorators via pip and easy_install
since 1.9.11 it automatically detects pypy
"""

uwsgi_compiled = False


def get_profile():
    is_pypy = False
    try:
        import __pypy__  # NOQA
        is_pypy = True
    except ImportError:
        pass
    if is_pypy:
        profile = os.environ.get('UWSGI_PROFILE', 'buildconf/pypy.ini')
    else:
        profile = os.environ.get('UWSGI_PROFILE', 'buildconf/default.ini')
    if not profile.endswith('.ini'):
        profile = "%s.ini" % profile
    if '/' not in profile:
        profile = "buildconf/%s" % profile

    return profile


def patch_bin_path(cmd, conf):

    bin_name = conf.get('bin_name')

    if not os.path.isabs(bin_name):
        if conf.get('as_shared_library'):
            print('Patching "bin_name" to properly install_platlib dir')
            target_dir = cmd.install_platlib
        else:
            print('Patching "bin_name" to properly install_scripts dir')
            target_dir = cmd.install_scripts
        try:
            if not os.path.exists(target_dir):
                os.makedirs(target_dir)
            conf.set('bin_name',
                     os.path.join(target_dir, conf.get('bin_name')))
        except Exception:
            conf.set('bin_name', sys.prefix + '/bin/' + bin_name)


class uWSGIBuilder(build_ext):

    def run(self):
        global uwsgi_compiled
        if not uwsgi_compiled:
            conf = uc.uConf(get_profile())
            patch_bin_path(self, conf)
            uc.build_uwsgi(conf)
            uwsgi_compiled = True


class uWSGIInstall(install):

    def run(self):
        global uwsgi_compiled
        if not uwsgi_compiled:
            conf = uc.uConf(get_profile())
            patch_bin_path(self, conf)
            uc.build_uwsgi(conf)
            uwsgi_compiled = True
        install.run(self)


class uWSGIInstallLib(install_lib):

    def run(self):
        global uwsgi_compiled
        if not uwsgi_compiled:
            conf = uc.uConf(get_profile())
            patch_bin_path(self, conf)
            uc.build_uwsgi(conf)
            uwsgi_compiled = True
        install_lib.run(self)


if HAS_WHEEL:
    class uWSGIWheel(bdist_wheel):
        def finalize_options(self):
            bdist_wheel.finalize_options(self)
            self.root_is_pure = False


class uWSGIDistribution(Distribution):

    def __init__(self, *attrs):
        Distribution.__init__(self, *attrs)
        self.cmdclass['install'] = uWSGIInstall
        self.cmdclass['install_lib'] = uWSGIInstallLib
        self.cmdclass['build_ext'] = uWSGIBuilder
        if HAS_WHEEL:
            self.cmdclass['bdist_wheel'] = uWSGIWheel

    def is_pure(self):
        return False


def get_extra_require():
    req = []
    conf = uc.uConf(get_profile())
    plugins = conf.get('main_plugin')
    if plugins:
        plugins = plugins.split(',')
        if 'greenlet' in plugins:
            req.append('greenlet')

    return req

setup(
    name='uWSGI',
    version=uc.uwsgi_version,
    description='The uWSGI server',
    author='Unbit',
    author_email='info@unbit.it',
    license='GPLv2+',
    py_modules=['uwsgidecorators'],
    distclass=uWSGIDistribution,
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    ],
    install_requires=get_extra_require()
)
