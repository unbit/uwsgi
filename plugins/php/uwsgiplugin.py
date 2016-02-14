import os

NAME='php'

ld_run_path = None
PHPPATH = 'php-config'

phpdir = os.environ.get('UWSGICONFIG_PHPDIR')
if phpdir:
    ld_run_path = "%s/lib" % phpdir
    PHPPATH = "%s/bin/php-config" % phpdir

PHPPATH = os.environ.get('UWSGICONFIG_PHPPATH', PHPPATH)

php_version = os.popen(PHPPATH + ' --version').read().rstrip().split('.')[0]

CFLAGS = [os.popen(PHPPATH + ' --includes').read().rstrip(), '-Wno-sign-compare']
LDFLAGS = os.popen(PHPPATH + ' --ldflags').read().rstrip().split()

if ld_run_path:
    LDFLAGS.append('-L%s' % ld_run_path)
    os.environ['LD_RUN_PATH'] = ld_run_path

LIBS = [os.popen(PHPPATH + ' --libs').read().rstrip(), '-lphp' + php_version]

phplibdir = os.environ.get('UWSGICONFIG_PHPLIBDIR')
if phplibdir:
    LIBS.append('-Wl,-rpath,%s' % phplibdir)

GCC_LIST = ['php_plugin', 'session']
