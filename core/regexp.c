#if defined(UWSGI_PCRE) || defined(UWSGI_PCRE2)
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

#ifdef UWSGI_PCRE2
int uwsgi_regexp_build(char *re, pcre2_code ** pattern) {

	int errnbr;
	long unsigned int erroff;

	*pattern = pcre2_compile((const unsigned char *) re, PCRE2_ZERO_TERMINATED, 0, &errnbr, &erroff, NULL);
#else
int uwsgi_regexp_build(char *re, pcre ** pattern, pcre_extra ** pattern_extra) {

	const char *errstr;
	int erroff;

	*pattern = pcre_compile((const char *) re, 0, &errstr, &erroff, NULL);
#endif
	if (!*pattern) {
#ifdef UWSGI_PCRE2
		uwsgi_log("pcre error: code %d at offset %d\n", errnbr, erroff);
#else
		uwsgi_log("pcre error: %s at offset %d\n", errstr, erroff);
#endif
		return -1;
	}

#ifdef UWSGI_PCRE2
	if (uwsgi.pcre_jit) {
		errnbr = pcre2_jit_compile(*pattern, PCRE2_JIT_COMPLETE);
		if (errnbr) {
			uwsgi_log("pcre JIT compile error code %d\n", errnbr);
			return -1;
		}
#else
	int opt = uwsgi.pcre_jit;

	*pattern_extra = (pcre_extra *) pcre_study((const pcre *) *pattern, opt, &errstr);
	if (*pattern_extra == NULL && errstr != NULL) {
		pcre_free(*pattern);
		uwsgi_log("pcre (study) error: %s\n", errstr);
		return -1;
#endif
	}

	return 0;

}

#ifdef UWSGI_PCRE2
int uwsgi_regexp_match(pcre2_code *pattern, const char *subject, int length) {

	return pcre2_match(pattern, (const unsigned char *)subject, length, 0, 0, NULL, NULL);
#else
int uwsgi_regexp_match(pcre * pattern, pcre_extra * pattern_extra, char *subject, int length) {

	return pcre_exec((const pcre *) pattern, (const pcre_extra *) pattern_extra, subject, length, 0, 0, NULL, 0);
#endif
}

#ifdef UWSGI_PCRE2
int uwsgi_regexp_match_ovec(pcre2_code *pattern, const char *subject, int length, int *ovec, int n) {

	int rc;
	int i;
	pcre2_match_data *match_data;
	size_t *pcre2_ovec;

	match_data = pcre2_match_data_create_from_pattern(pattern, NULL);
	rc = pcre2_match(pattern, (const unsigned char *)subject, length, 0, 0, match_data, NULL);
#else
int uwsgi_regexp_match_ovec(pcre * pattern, pcre_extra * pattern_extra, char *subject, int length, int *ovec, int n) {
#endif

	if (n > 0) {
#ifdef UWSGI_PCRE2
		// copy pcre2 output vector to uwsgi output vector
		pcre2_ovec = pcre2_get_ovector_pointer(match_data);
		for (i=0;i<2*n+1;i++) {
			ovec[i] = pcre2_ovec[i];
		}
#else
		return pcre_exec((const pcre *) pattern, (const pcre_extra *) pattern_extra, subject, length, 0, 0, ovec, (n + 1) * 3);
#endif
	}

#ifdef UWSGI_PCRE2
	pcre2_match_data_free(match_data);

	return rc;
#else
	return pcre_exec((const pcre *) pattern, (const pcre_extra *) pattern_extra, subject, length, 0, 0, NULL, 0);
#endif
}

#ifdef UWSGI_PCRE2
int uwsgi_regexp_ovector(pcre2_code *pattern) {
#else
int uwsgi_regexp_ovector(pcre * pattern, pcre_extra * pattern_extra) {
#endif

	int n;
#ifdef UWSGI_PCRE2
	pcre2_match_data *match_data;

	match_data = pcre2_match_data_create_from_pattern(pattern, NULL);
	n = pcre2_get_ovector_count(match_data);
	pcre2_match_data_free(match_data);
#else
	if (pcre_fullinfo((const pcre *) pattern, (const pcre_extra *) pattern_extra, PCRE_INFO_CAPTURECOUNT, &n))
		return 0;
#endif

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
