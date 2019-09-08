#include <check.h>
#include "../uwsgi.h"


START_TEST(test_uwsgi_mode_t)
{
	int result, error;
	result = uwsgi_mode_t("644", &error);
	ck_assert(result == 0644);
	ck_assert(error == 0);

	result = uwsgi_mode_t("0644", &error);
	ck_assert(result == 0644);
	ck_assert(error == 0);
}
END_TEST

START_TEST(test_uwsgi_mode_t_ignore_sbits)
{
	int error;
	int result = uwsgi_mode_t("7666", &error);
	ck_assert(result == 0666);
	ck_assert(error == 0);
}
END_TEST

START_TEST(test_uwsgi_mode_t_too_short)
{
	int error;
	int result = uwsgi_mode_t("A", &error);
	ck_assert(result == 0);
	ck_assert(error == 1);
}
END_TEST

START_TEST(test_uwsgi_mode_t_out_of_range)
{
	int error;
	int result = uwsgi_mode_t("AAA", &error);
	ck_assert(result == 0);
	ck_assert(error == 1);
}
END_TEST

Suite *check_utils(void)
{
	Suite *s = suite_create("utils");
	TCase *tc = tcase_create("mode_t");

	suite_add_tcase(s, tc);
	tcase_add_test(tc, test_uwsgi_mode_t);
	tcase_add_test(tc, test_uwsgi_mode_t_ignore_sbits);
	tcase_add_test(tc, test_uwsgi_mode_t_too_short);
	tcase_add_test(tc, test_uwsgi_mode_t_out_of_range);
	return s;
}

int main(void)
{
	int nf;
	SRunner *r = srunner_create(check_utils());
	srunner_run_all(r, CK_NORMAL);
	nf = srunner_ntests_failed(r);
	srunner_free(r);
	return (nf == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
