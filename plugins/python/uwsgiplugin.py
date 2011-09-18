import os,sys

from distutils import sysconfig

NAME='python'
GCC_LIST = ['python_plugin', 'pyutils', 'pyloader', 'wsgi_handlers', 'wsgi_headers', 'wsgi_subhandler', 'web3_subhandler', 'pump_subhandler', 'gil', 'uwsgi_pymodule', 'profiler', 'symimporter']
#OBJ_LIST = ['/usr/lib/libpython2.6.a']

CFLAGS = ['-I' + sysconfig.get_python_inc(), '-I' + sysconfig.get_python_inc(plat_specific=True) ] 

if 'pypy_version_info' in sys.__dict__:
    CFLAGS.append('-DUWSGI_PYPY')

LDFLAGS = []

if not 'UWSGI_PYTHON_NOLIB' in os.environ:
    LIBS = sysconfig.get_config_var('LIBS').split() + sysconfig.get_config_var('SYSLIBS').split()
    if not sysconfig.get_config_var('Py_ENABLE_SHARED'):
        LIBS.append('-L' + sysconfig.get_config_var('LIBPL'))
    else:
        try:
            LDFLAGS.append("-L%s" % sysconfig.get_config_var('LIBDIR'))
            os.environ['LD_RUN_PATH'] = "%s" % (sysconfig.get_config_var('LIBDIR'))
        except:
            LDFLAGS.append("-L%s/lib" % sysconfig.PREFIX)
            os.environ['LD_RUN_PATH'] = "%s/lib" % sysconfig.PREFIX


    version = sysconfig.get_config_var('VERSION')
    try:
        version = version + sys.abiflags
    except:
        pass
    LIBS.append('-lpython' + version)
else:
    LIBS = []

#if str(PYLIB_PATH) != '':
#                libs.insert(0,'-L' + PYLIB_PATH)
#                os.environ['LD_RUN_PATH'] = PYLIB_PATH
