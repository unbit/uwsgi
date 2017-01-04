# encoding: utf-8

"""
This is a hack allowing you installing
uWSGI and uwsgidecorators via pip and easy_install
since 1.9.11 it automatically detects pypy
"""

import os
import sys
import errno
import shlex
import uwsgiconfig

from setuptools import setup
from setuptools.command.build_ext import build_ext
from distutils.core import Extension


class uWSGIBuildExt(build_ext):

    UWSGI_NAME = 'uwsgi'
    UWSGI_PLUGIN = 'pyuwsgi'

    def build_extensions(self):
        self.uwsgi_setup()
        # XXX: needs uwsgiconfig fix
        self.uwsgi_build()
        if 'UWSGI_USE_DISTUTILS' not in os.environ:
            # XXX: needs uwsgiconfig fix
            # uwsgiconfig.build_uwsgi(self.uwsgi_config)
            return

        else:
            # XXX: needs uwsgiconfig fix
            os.unlink(self.uwsgi_config.get('bin_name'))

        # FIXME: else build fails :(
        for baddie in set(self.compiler.compiler_so) & set(('-Wstrict-prototypes',)):
            self.compiler.compiler_so.remove(baddie)

        build_ext.build_extensions(self)

    def uwsgi_setup(self):
        default = 'pypy' if '__pypy__' in sys.builtin_module_names else 'default'
        profile = os.environ.get('UWSGI_PROFILE') or 'buildconf/%s.ini' % default

        if not profile.endswith('.ini'):
            profile = profile + '.ini'
        if '/' not in profile:
            profile = 'buildconf/' + profile

        # FIXME: update uwsgiconfig to properly set _EVERYTHING_!
        config = uwsgiconfig.uConf(profile)
        # insert in the beginning so UWSGI_PYTHON_NOLIB is exported
        # before the python plugin compiles
        ep = config.get('embedded_plugins').split(',')
        if self.UWSGI_PLUGIN in ep:
            ep.remove(self.UWSGI_PLUGIN)
        ep.insert(0, self.UWSGI_PLUGIN)
        config.set('embedded_plugins', ','.join(ep))
        config.set('as_shared_library', 'true')
        config.set('bin_name', self.get_ext_fullpath(self.UWSGI_NAME))
        try:
            os.makedirs(os.path.dirname(config.get('bin_name')))
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise

        self.uwsgi_profile = profile
        self.uwsgi_config = config

    def uwsgi_build(self):
        uwsgiconfig.build_uwsgi(self.uwsgi_config)

        # XXX: merge uwsgi_setup (see other comments)
        for ext in self.extensions:
            if ext.name == self.UWSGI_NAME:
                ext.sources = [s + '.c' for s in self.uwsgi_config.gcc_list]
                ext.library_dirs = self.uwsgi_config.include_path[:]
                ext.libraries = list()
                ext.extra_compile_args = list()

                for x in uwsgiconfig.uniq_warnings(
                    self.uwsgi_config.ldflags + self.uwsgi_config.libs,
                ):
                    for y in shlex.split(x):
                        if y.startswith('-l'):
                            ext.libraries.append(y[2:])
                        elif y.startswith('-L'):
                            ext.library_dirs.append(y[2:])

                for x in self.uwsgi_config.cflags:
                    for y in shlex.split(x):
                        if y:
                            ext.extra_compile_args.append(y)


setup(
    name='uWSGI',
    license='GPL2',
    version=uwsgiconfig.uwsgi_version,
    author='Unbit',
    author_email='info@unbit.it',
    description='The uWSGI server',
    cmdclass={
        'build_ext': uWSGIBuildExt,
        },
    py_modules=[
        'uwsgidecorators',
        ],
    ext_modules=[
        Extension(uWSGIBuildExt.UWSGI_NAME, sources=[]),
        ],
    entry_points={
        'console_scripts': ['uwsgi=%s:run' % uWSGIBuildExt.UWSGI_NAME],
        },
    )
