#include "../../uwsgi.h"

#include <syslog.h>

struct uwsgi_syslog_facility {
	const char *name;
	int facility;
};
