#ifdef UWSGI_PCRE
#include "uwsgi.h"

int uwsgi_regexp_build(char *re, pcre **pattern, pcre_extra **pattern_extra) {

	const char *errstr;
	int erroff;

	*pattern = pcre_compile( (const char *)re, 0, &errstr, &erroff, NULL);
        if (!*pattern) {
		uwsgi_log("pcre error: %s at offset %d\n", errstr, erroff);
		return -1;
	}

	*pattern_extra = (pcre_extra *) pcre_study((const pcre*)*pattern, 0, &errstr);
        if (!*pattern_extra) {
		pcre_free(*pattern);
		uwsgi_log("pcre (study) error: %s\n", errstr);
		return -1;
	}

	return 0;
	
}

int uwsgi_regexp_match(pcre *pattern, pcre_extra *pattern_extra, char *subject, int length) {

	return pcre_exec((const pcre*)pattern, (const pcre_extra *)pattern_extra, subject, length, 0, 0, NULL, 0 );
}

#endif
