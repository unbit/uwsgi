#ifdef UWSGI_PCRE
#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

void uwsgi_opt_pcre_jit(char *opt, char *value, void *foobar) {
#if defined(PCRE_STUDY_JIT_COMPILE) && defined(PCRE_CONFIG_JIT)
	int has_jit = 0, ret;
	ret = pcre_config(PCRE_CONFIG_JIT, &has_jit);
	if (ret != 0 || has_jit != 1)
		return;
	uwsgi.pcre_jit = PCRE_STUDY_JIT_COMPILE;
#endif
}

int uwsgi_regexp_build(char *re, pcre ** pattern, pcre_extra ** pattern_extra) {

	const char *errstr;
	int erroff;

	*pattern = pcre_compile((const char *) re, 0, &errstr, &erroff, NULL);
	if (!*pattern) {
		uwsgi_log("pcre error: %s at offset %d\n", errstr, erroff);
		return -1;
	}

	int opt = uwsgi.pcre_jit;

	*pattern_extra = (pcre_extra *) pcre_study((const pcre *) *pattern, opt, &errstr);
	if (*pattern_extra == NULL && errstr != NULL) {
		pcre_free(*pattern);
		uwsgi_log("pcre (study) error: %s\n", errstr);
		return -1;
	}

	return 0;

}

int uwsgi_regexp_match(pcre * pattern, pcre_extra * pattern_extra, char *subject, int length) {

	return pcre_exec((const pcre *) pattern, (const pcre_extra *) pattern_extra, subject, length, 0, 0, NULL, 0);
}

int uwsgi_regexp_match_ovec(pcre * pattern, pcre_extra * pattern_extra, char *subject, int length, int *ovec, int n) {

	if (n > 0) {
		return pcre_exec((const pcre *) pattern, (const pcre_extra *) pattern_extra, subject, length, 0, 0, ovec, (n + 1) * 3);
	}
	return pcre_exec((const pcre *) pattern, (const pcre_extra *) pattern_extra, subject, length, 0, 0, NULL, 0);
}

int uwsgi_regexp_ovector(pcre * pattern, pcre_extra * pattern_extra) {

	int n;

	if (pcre_fullinfo((const pcre *) pattern, (const pcre_extra *) pattern_extra, PCRE_INFO_CAPTURECOUNT, &n))
		return 0;

	return n;
}

char *uwsgi_regexp_apply_ovec(char *src, int src_n, char *dst, int dst_n, int *ovector, int n) {

	int i;
	int dollar = 0;

	size_t dollars = n;
	
	for(i=0;i<dst_n;i++) {
		if (dst[i] == '$') {
			dollars++;
		}
	}

	char *res = uwsgi_malloc(dst_n + (src_n * dollars) + 1);
	char *ptr = res;

	for (i = 0; i < dst_n; i++) {
		if (dollar) {
			if (isdigit((int) dst[i])) {
				int pos = (dst[i] - 48);
				if (pos <= n) {
					pos = pos * 2;
					memcpy(ptr, src + ovector[pos], ovector[pos + 1] - ovector[pos]);
					ptr += ovector[pos + 1] - ovector[pos];
				}
			}
			else {
				*ptr++ = '$';
				*ptr++ = dst[i];
			}
			dollar = 0;
		}
		else {
			if (dst[i] == '$') {
				dollar = 1;
			}
			else {
				*ptr++ = dst[i];
			}
		}
	}

	*ptr++ = 0;

	return res;
}

#endif
