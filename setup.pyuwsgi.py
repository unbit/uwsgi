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

    UWSGI_NAME = 'pyuwsgi'
    UWSGI_PLUGIN = 'pyuwsgi'
    UWSGI_PROFILE = 'pyuwsgi'

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
        profile = os.environ.get('UWSGI_PROFILE') or 'buildconf/%s.ini' % self.UWSGI_PROFILE

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


LONG_DESCRIPTION = """
# The uWSGI server as a Python module

## Install

```
pip install pyuwsgi
```

## Run

The installed script, `pyuwsgi`, is a drop-in replacement for the `uwsgi` script.

You can also call it directly in your Python code with a list of valid uWSGI options:

```python
import pyuwsgi
pyuwsgi.run(["--help"])
```

## Differences from uWSGI

This is built from uWSGI's source without any modifications.
A different [`setup.py`](https://github.com/unbit/uwsgi/blob/uwsgi-2.0/setup.pyuwsgi.py)
is used to make the project a friendlier part of the Python ecosystem. It allows it
to be imported as a Python module and distributed using the
[wheel format](https://www.python.org/dev/peps/pep-0427/).

The full uWSGI documentation can be found at
[https://uwsgi-docs.readthedocs.org](https://uwsgi-docs.readthedocs.org).

---

[![Lincoln Loop](https://cldup.com/gyNz5rfTkR.png)](https://lincolnloop.com)

`pyuwsgi` is sponsored by [Lincoln Loop](https://lincolnloop.com).

[![Unbit](https://cldup.com/TTNag1Zlcw.png)](http://unbit.com/)

`uwsgi` is the creation of [Unbit](http://unbit.com/).

"""

setup(
    name='pyuwsgi',
    license='GPL2',
    version=uwsgiconfig.uwsgi_version,
    author='Unbit',
    author_email='info@unbit.it',
    description='The uWSGI server',
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    cmdclass={
        'build_ext': uWSGIBuildExt,
        },
    py_modules=[
        'uwsgidecorators',
        ],
    ext_modules=[
        Extension('pyuwsgi', sources=[]),
        ],
    entry_points={
        'console_scripts': ['pyuwsgi=pyuwsgi:run'],
        },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Web Environment",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: WSGI",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Server",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        ]
    )
