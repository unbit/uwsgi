#ifdef UWSGI_PCRE
#include "uwsgi.h"

void uwsgi_regexp_build(char *re, pcre **pattern, pcre_extra **pattern_extra) {

	const char *errstr;
	int erroff;

	*pattern = pcre_compile( (const char *)re, 0, &errstr, &erroff, NULL);
        if (!*pattern) {
		uwsgi_log("pcre error: %s at offset %d\n", errstr, erroff);
		exit(1);
	}

	*pattern_extra = (pcre_extra *) pcre_study((const pcre*)*pattern, 0, &errstr);
        if (!*pattern_extra) {
		uwsgi_log("pcre (study) error: %s\n", errstr);
		exit(1);
	}

	
}

int uwsgi_regexp_match(pcre *pattern, pcre_extra *pattern_extra, char *subject, int length) {

	return pcre_exec((const pcre*)pattern, (const pcre_extra *)pattern_extra, subject, length, 0, 0, NULL, 0 );
}

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
