import os,sys

from distutils import sysconfig

def get_python_version():
    version = sysconfig.get_config_var('VERSION')
    try:
        version = version + sys.abiflags
    except:
        pass
    return version

NAME='python'
GCC_LIST = ['python_plugin', 'pyutils', 'pyloader', 'wsgi_handlers', 'wsgi_headers', 'wsgi_subhandler', 'web3_subhandler', 'pump_subhandler', 'gil', 'uwsgi_pymodule', 'profiler', 'symimporter', 'tracebacker', 'raw']

CFLAGS = ['-I' + sysconfig.get_python_inc(), '-I' + sysconfig.get_python_inc(plat_specific=True) ] 
LDFLAGS = []

if not 'UWSGI_PYTHON_NOLIB' in os.environ:
    LIBS = sysconfig.get_config_var('LIBS').split() + sysconfig.get_config_var('SYSLIBS').split()
    # check if it is a non-shared build (but please, add --enable-shared to your python's ./configure script)
    if not sysconfig.get_config_var('Py_ENABLE_SHARED'):
        libdir = sysconfig.get_config_var('LIBPL')
        # libdir does not exists, try to get it from the venv
        version = get_python_version()
        if not os.path.exists(libdir):
            libdir = '%s/lib/python%s/config' % (sys.prefix, version)
        # try skipping abiflag
        if not os.path.exists(libdir) and version.endswith('m'):
            version = version[:-1]
            libdir = '%s/lib/python%s/config' % (sys.prefix, version)
        # try 3.x style config dir
        if not os.path.exists(libdir):
            libdir = '%s/lib/python%s/config-%s' % (sys.prefix, version, get_python_version())

        # get cpu type
        uname = os.uname()
        if uname[4].startswith('arm'):
            libpath = '%s/%s' % (libdir, sysconfig.get_config_var('LIBRARY'))
            if not os.path.exists(libpath): 
                libpath = '%s/%s' % (libdir, sysconfig.get_config_var('LDLIBRARY'))
        else:
            libpath = '%s/%s' % (libdir, sysconfig.get_config_var('LDLIBRARY'))
            if not os.path.exists(libpath): 
                libpath = '%s/%s' % (libdir, sysconfig.get_config_var('LIBRARY'))
        if not os.path.exists(libpath): 
            libpath = '%s/libpython%s.a' % (libdir, version)
        LIBS.append(libpath)
        # hack for messy linkers/compilers
        if '-lutil' in LIBS:
            LIBS.append('-lutil')
    else:
        try:
            libdir = sysconfig.get_config_var('LIBDIR')
        except:
            libdir = "%s/lib" % sysconfig.PREFIX

        LDFLAGS.append("-L%s" % libdir)
        LDFLAGS.append("-Wl,-rpath,%s" % libdir)

        os.environ['LD_RUN_PATH'] = "%s" % libdir

        LIBS.append('-lpython%s' % get_python_version())
else:
    LIBS = []
