#include <check.h>
#include "../uwsgi.h"


START_TEST(test_check_hex)
{
    int result;

    result = check_hex("DEADBEEF", 8);
    ck_assert(result == 1);

    result = check_hex("test", 4);
    ck_assert(result == 0);

    result = check_hex("FF5733", 6);
    ck_assert(result == 1);

    result = check_hex("FF5T33", 6);
    ck_assert(result == 0);

    result = check_hex("fabe34aa", 6);
    ck_assert(result == 1);
}
END_TEST

Suite *check_utils_check_hex(void)
{
    Suite *s = suite_create("uwsgi utils check_hex");
    TCase *tc = tcase_create("check_hex");

    suite_add_tcase(s, tc);
    tcase_add_test(tc, test_check_hex);
    return s;
}

int main(void)
{
    int nf;
    SRunner *r = srunner_create(check_utils_check_hex());
    srunner_run_all(r, CK_NORMAL);
    nf = srunner_ntests_failed(r);
    srunner_free(r);
    return (nf == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
