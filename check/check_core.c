#include <check.h>
#include "../uwsgi.h"


START_TEST(test_uwsgi_strncmp)
{
	int result;
        result = uwsgi_strncmp("test", 4, "test", 4);
	ck_assert(result == 0);

	result = uwsgi_strncmp("test", 4, "tes", 3);
	ck_assert(result == 1);

	result = uwsgi_strncmp("tes", 3, "test", 4);
	ck_assert(result == 1);

	result = uwsgi_strncmp("aaa", 3, "bbb", 3);
	ck_assert_msg(result < 0, "result: %d", result);

	result = uwsgi_strncmp("bbb", 3, "aaa", 3);
	ck_assert_msg(result > 0, "result: %d", result);
}
END_TEST

Suite *check_core_strings(void)
{
	Suite *s = suite_create("uwsgi strings");
	TCase *tc = tcase_create("strings");

	suite_add_tcase(s, tc);
	tcase_add_test(tc, test_uwsgi_strncmp);
	return s;
}

START_TEST(test_uwsgi_opt_set_int)
{
	int result;
	uwsgi_opt_set_int("", "true", &result);
	ck_assert(result == 0);

	uwsgi_opt_set_int("", "false", &result);
	ck_assert(result == 0);

	uwsgi_opt_set_int("", "0", &result);
	ck_assert(result == 0);

	uwsgi_opt_set_int("", "60", &result);
	ck_assert(result == 60);

	// When used with "optional_argument", value will be passed as NULL
	uwsgi_opt_set_int("", NULL, &result);
	ck_assert(result == 1);
}
END_TEST

Suite *check_core_opt_parsing(void)
{
	Suite *s = suite_create("uwsgi opt parsing");
	TCase *tc = tcase_create("opt_parsing");

	suite_add_tcase(s, tc);
	tcase_add_test(tc, test_uwsgi_opt_set_int);
	return s;
}

int main(void)
{
	int nf;
	SRunner *r = srunner_create(check_core_strings());
	srunner_add_suite(r, check_core_opt_parsing());
	srunner_run_all(r, CK_NORMAL);
	nf = srunner_ntests_failed(r);
	srunner_free(r);
	return (nf == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

