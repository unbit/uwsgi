#ifdef UWSGI_PCRE

#include "uwsgi.h"

#include <pcre.h>

/*

void uwsgi_regexp_match(regexp, what) {

	int ret,i;

	for(i=0;i<uwsgi->nroutes;i++) {

		ret = pcre_exec(ur->pattern, ur->pattern_extra, wsgi_req->path_info, wsgi_req->path_info_len, 0, 0, wsgi_req->ovector, (ur->args+1)*3 );

		if (ret >= 0) {
			if (ur->action) {
				ur->action(uwsgi, wsgi_req, ur);
			}
			else {
				uwsgi_route_action_wsgi(uwsgi, wsgi_req, ur);
			}
		}

		// TODO check for errors if < 0 && != NO_MATCH
	}

	return;
}

*/


#endif
