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

/* abstract socket tests */

START_TEST(test_uwsgi_connect_to_unix) {
	int sfd, cfd;
	// Normal abstract socket bind
	sfd = bind_to_unix("uwsgi_abs_test_socket", 10, 0, 1);
	ck_assert_msg(sfd > 0, "Failed to bind abstract socket");

	//Test open '@' prefix
	cfd = uwsgi_connect("@uwsgi_abs_test_socket", 0, 0);
	ck_assert_msg(cfd > 0, "Failed to connect with abstract socket with '@' prefix");
	close(cfd);

	//Test open '\\0' prefix
	cfd = uwsgi_connect("\\0uwsgi_abs_test_socket", 0, 0);
	ck_assert_msg(cfd > 0, "Failed to connect with abstract socket with \"\\0\" prefix");
	close(cfd);
	close(sfd);
}
END_TEST

START_TEST(test_uwsgi_bind_to_unix_normal) {
	int sfd, cfd;
	// Normal abstract socket bind
	sfd = bind_to_unix("uwsgi_abs_test_socket", 10, 0, 1);
	ck_assert_msg(sfd > 0, "Failed to bind abstract socket");

	//Test open '@' prefix
	cfd = uwsgi_connect("@uwsgi_abs_test_socket", 0, 0);
	ck_assert_msg(cfd > 0, "Failed to connect to abstract socket");

	close(cfd);
	close(sfd);
}
END_TEST

START_TEST(test_uwsgi_bind_to_unix_at) {
	int sfd, cfd;
	// Normal abstract socket bind
	sfd = bind_to_unix("@uwsgi_abs_test_socket", 10, 0, 0);
	ck_assert_msg(sfd > 0, "Failed to bind abstract socket");

	//Test open '@' prefix
	cfd = uwsgi_connect("@uwsgi_abs_test_socket", 0, 0);
	ck_assert_msg(cfd > 0, "Failed to connect to abstract socket");

	close(cfd);
	close(sfd);
}
END_TEST

START_TEST(test_uwsgi_bind_to_unix_null) {
	int sfd, cfd;
	// Normal abstract socket bind
	sfd = bind_to_unix("\\0uwsgi_abs_test_socket", 10, 0, 0);
	ck_assert_msg(sfd > 0, "Failed to bind abstract socket");

	//Test open '@' prefix
	cfd = uwsgi_connect("@uwsgi_abs_test_socket", 0, 0);
	ck_assert_msg(cfd > 0, "Failed to connect to abstract socket");

	close(cfd);
	close(sfd);
}
END_TEST


Suite *check_core_socket(void)
{
	Suite *s = suite_create("uwsgi socket");

	TCase *socket_tc = tcase_create("socket_tests");
	suite_add_tcase(s, socket_tc);

	tcase_add_test(socket_tc, test_uwsgi_connect_to_unix);
	tcase_add_test(socket_tc, test_uwsgi_bind_to_unix_normal);
	tcase_add_test(socket_tc, test_uwsgi_bind_to_unix_at);
	tcase_add_test(socket_tc, test_uwsgi_bind_to_unix_null);
	return s;
}

START_TEST(test_uwsgi_cron_task_needs_execution_handles_weekday_7_as_sunday)
{
	int result;
	struct tm *t;
	time_t now;

	now = time(NULL);
	t = localtime(&now);
	t->tm_wday= 0;

	result = uwsgi_cron_task_needs_execution(t, -1, -1, -1, -1, 0);
	ck_assert(result == 1);

	result = uwsgi_cron_task_needs_execution(t, -1, -1, -1, -1, 7);
	ck_assert(result == 1);

	result = uwsgi_cron_task_needs_execution(t, -1, -1, -1, -1, 1);
	ck_assert(result == 0);
}
END_TEST

Suite *check_core_cron(void)
{
	Suite *s = suite_create("uwsgi cron");
	TCase *tc = tcase_create("cron");

	suite_add_tcase(s, tc);
	tcase_add_test(tc, test_uwsgi_cron_task_needs_execution_handles_weekday_7_as_sunday);
	return s;
}

int main(void)
{
	int nf;
	SRunner *r = srunner_create(check_core_strings());
	srunner_add_suite(r, check_core_opt_parsing());
	srunner_add_suite(r, check_core_socket());
	srunner_add_suite(r, check_core_cron());
	srunner_run_all(r, CK_NORMAL);
	nf = srunner_ntests_failed(r);
	srunner_free(r);
	return (nf == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

