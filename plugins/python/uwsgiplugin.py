import os,sys

from distutils import sysconfig

NAME='python'
GCC_LIST = ['python_plugin', 'pyutils', 'pyloader', 'wsgi_handlers', 'wsgi_headers', 'wsgi_subhandler', 'gil', 'uwsgi_pymodule', 'profiler', 'symimporter']

CFLAGS = ['-I' + sysconfig.get_python_inc(), '-I' + sysconfig.get_python_inc(plat_specific=True) ] 
LDFLAGS = []

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

#if str(PYLIB_PATH) != '':
#                libs.insert(0,'-L' + PYLIB_PATH)
#                os.environ['LD_RUN_PATH'] = PYLIB_PATH
