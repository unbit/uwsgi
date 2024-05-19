#include <check.h>
#include "../uwsgi.h"


START_TEST(test_uwsgi_regexp_match)
{
	int result;
	uwsgi_pcre *pattern_all;
	uwsgi_pcre *pattern;

	result = uwsgi_regexp_build(".*", &pattern_all);
	ck_assert(result == 0);

	result = uwsgi_regexp_match(pattern_all, "/fooba", 6);
	ck_assert(result >= 0);

	result = uwsgi_regexp_build("/foobar/.*", &pattern);
	ck_assert(result == 0);

	result = uwsgi_regexp_match(pattern, "/fooba", 6);
	ck_assert(result < 0);

	result = uwsgi_regexp_match(pattern, "/foobar/baz", 11);
	ck_assert(result >= 0);

	pcre2_code_free(pattern_all);
	pcre2_code_free(pattern);
}
END_TEST

START_TEST(test_uwsgi_regexp_match_ovec)
{
	int result;
	uwsgi_pcre *pattern;
	int *ovec = calloc((2+1)*2, sizeof(int));
	char buf[20], sub[20];

	result = uwsgi_regexp_build("^/foo/(.*)\\.jpg\\?([0-9]{2})", &pattern);
	ck_assert(result == 0);
	result = uwsgi_regexp_ovector(pattern);
	ck_assert(result == 2);

	result = uwsgi_regexp_match_ovec(pattern, "/fooba", 6, ovec, 2);
	ck_assert(result < 0);

	strcpy(buf, "/foo/bar.jpg?422");
	result = uwsgi_regexp_match_ovec(pattern, buf, strlen(buf), ovec, 2);
	ck_assert(result >= 0);
	strncpy(sub, buf+ovec[0], ovec[1]-ovec[0]);
	sub[ovec[1]-ovec[0]] = '\0';
	ck_assert_str_eq(sub, "/foo/bar.jpg?42");
	strncpy(sub, buf+ovec[2], ovec[3]-ovec[2]);
	sub[ovec[3]-ovec[2]] = '\0';
	ck_assert_str_eq(sub, "bar");
	strncpy(sub, buf+ovec[4], ovec[5]-ovec[4]);
	sub[ovec[5]-ovec[4]] = '\0';
	ck_assert_str_eq(sub, "42");

	strcpy(sub, uwsgi_regexp_apply_ovec(buf, strlen(buf), "key=$1.$2.jpg", 13, ovec, 2));
	ck_assert_str_eq(sub, "key=bar.42.jpg");

	pcre2_code_free(pattern);
	free(ovec);
}
END_TEST

Suite *check_regexp(void)
{
	Suite *s = suite_create("uwsgi regexp");
	TCase *tc = tcase_create("regexp");

	suite_add_tcase(s, tc);
	tcase_add_test(tc, test_uwsgi_regexp_match);
	tcase_add_test(tc, test_uwsgi_regexp_match_ovec);
	return s;
}

int main(void)
{
	int nf;
	SRunner *r = srunner_create(check_regexp());
	srunner_run_all(r, CK_NORMAL);
	nf = srunner_ntests_failed(r);
	srunner_free(r);
	return (nf == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
