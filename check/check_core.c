#include <check.h>
#include "../uwsgi.h"


START_TEST(test_core_utils)
{
	int result = uwsgi_strncmp("test", 4, "test", 4);
	fail_unless(result == 0);
}
END_TEST

Suite *check_core_suite(void)
{
	Suite *s = suite_create("uwsgi core");
	TCase *tc = tcase_create("core");

	suite_add_tcase(s, tc);
	tcase_add_test(tc, test_core_utils);
	return s;
}

int main(void)
{
	int nf;
	Suite *s = check_core_suite();
	SRunner *r = srunner_create(s);
	srunner_run_all(r, CK_NORMAL);
	nf = srunner_ntests_failed(r);
	srunner_free(r);
	return (nf == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

