PHP_ARG_WITH(uwsgi,,
[  --with-uwsgi=UWSGISRCDIR    Build PHP as a uWSGI plugin (UNIX/POSIX only)], no, no)

AC_MSG_CHECKING([for UWSGI])
if test "$PHP_UWSGI" != "no"; then

  INSTALL_IT="\$(INSTALL) -m 0755 $SAPI_SHARED $PHP_UWSGI/php_plugin.so"

  UWSGI_CFLAGS=`cd $PHP_UWSGI ; python uwsgiconfig.py --cflags`
  UWSGI_CFLAGS="$UWSGI_CFLAGS -I$PHP_UWSGI"

  PHP_SELECT_SAPI(uwsgi, shared, php_plugin.c, $UWSGI_CFLAGS)
  AC_MSG_RESULT([$PHP_UWSGI])
else
  AC_MSG_RESULT(no)
fi
