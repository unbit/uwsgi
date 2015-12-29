#include "php.h"
#include "SAPI.h"
#include "php_main.h"
#include "php_variables.h"

#if (PHP_MAJOR_VERSION < 7)
#include "ext/standard/php_smart_str.h"
#else
#define UWSGI_PHP7
#endif
#include "ext/standard/info.h"

#include "ext/session/php_session.h"

#include <uwsgi.h>

