import os

NAME='php'

ld_run_path = None
PHPPATH = 'php-config'

try:
    phpdir = os.environ['UWSGICONFIG_PHPDIR']
    ld_run_path = "%s/lib" % phpdir
    PHPPATH = "%s/bin/php-config" % phpdir
except:
    pass

try:
    PHPPATH = os.environ['UWSGICONFIG_PHPPATH']
except:
    pass

CFLAGS = [os.popen(PHPPATH + ' --includes').read().rstrip(), '-Wno-error=sign-compare']

LDFLAGS = os.popen(PHPPATH + ' --ldflags').read().rstrip().split()
if ld_run_path:
    LDFLAGS.append('-L%s' % ld_run_path)
    os.environ['LD_RUN_PATH'] = ld_run_path

LIBS = [os.popen(PHPPATH + ' --libs').read().rstrip(), '-lphp5']

GCC_LIST = ['php_plugin']
