NAME = "cffi"

import os.path
import sys
from distutils import sysconfig
import subprocess

subprocess.check_call(["make"], cwd="plugins/cffi")


def get_python_version():
    version = sysconfig.get_config_var("VERSION")
    try:
        version = version + sys.abiflags
    except Exception:
        pass
    return version


GCC_LIST = ["cffi_plugin"]

if sys.implementation.name == "pypy":

    CFLAGS = [
        "-pthread",
        "-DNDEBUG",
        f"-I{sys.base_exec_prefix}/include",
        f"-I{sys.prefix}/include",
        "-fvisibility=hidden",
    ]

    if sys.platform == "linux":
        LDFLAGS = [f"-L{sys.prefix}/bin/", f"-Wl,-rpath={sys.prefix}/bin/", "-lpypy3-c"]
    else:
        LDFLAGS = [f"-L{sys.prefix}/bin/", "-lpypy3-c"]
    LIBS = []

    def post_build(config):
        # How to detect embedded or shared object?
        # find pypy3-c on osx
        if sys.platform == "darwin":
            rpath = os.path.dirname(sys.executable)
            subprocess.check_call(
                ["install_name_tool", "-add_rpath", rpath, "cffi_plugin.so"]
            )


else:
    # copied from plugins/python

    CFLAGS = [
        "-I" + sysconfig.get_python_inc(),
        "-I" + sysconfig.get_python_inc(plat_specific=True),
    ]
    LDFLAGS = []

    if "UWSGI_PYTHON_NOLIB" not in os.environ:
        LIBS = (
            sysconfig.get_config_var("LIBS").split()
            + sysconfig.get_config_var("SYSLIBS").split()
        )
        # check if it is a non-shared build (but please, add --enable-shared to your python's ./configure script)
        if not sysconfig.get_config_var("Py_ENABLE_SHARED"):
            libdir = sysconfig.get_config_var("LIBPL")
            # libdir does not exists, try to get it from the venv
            version = get_python_version()
            if not os.path.exists(libdir):
                libdir = "%s/lib/python%s/config" % (sys.prefix, version)
            # try skipping abiflag
            if not os.path.exists(libdir) and version.endswith("m"):
                version = version[:-1]
                libdir = "%s/lib/python%s/config" % (sys.prefix, version)
            # try 3.x style config dir
            if not os.path.exists(libdir):
                libdir = "%s/lib/python%s/config-%s" % (
                    sys.prefix,
                    version,
                    get_python_version(),
                )

            # get cpu type
            uname = os.uname()
            if uname[4].startswith("arm"):
                libpath = "%s/%s" % (libdir, sysconfig.get_config_var("LIBRARY"))
                if not os.path.exists(libpath):
                    libpath = "%s/%s" % (libdir, sysconfig.get_config_var("LDLIBRARY"))
            else:
                libpath = "%s/%s" % (libdir, sysconfig.get_config_var("LDLIBRARY"))
                if not os.path.exists(libpath):
                    libpath = "%s/%s" % (libdir, sysconfig.get_config_var("LIBRARY"))
            if not os.path.exists(libpath):
                libpath = "%s/libpython%s.a" % (libdir, version)
            LIBS.append(libpath)
            # hack for messy linkers/compilers
            if "-lutil" in LIBS:
                LIBS.append("-lutil")
        else:
            try:
                libdir = sysconfig.get_config_var("LIBDIR")
            except Exception:
                libdir = "%s/lib" % sysconfig.PREFIX

            LDFLAGS.append("-L%s" % libdir)
            LDFLAGS.append("-Wl,-rpath,%s" % libdir)

            os.environ["LD_RUN_PATH"] = "%s" % libdir

            LIBS.append("-lpython%s" % get_python_version())
    else:
        LIBS = []
