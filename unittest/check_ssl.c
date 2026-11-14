#include <check.h>
#include "../uwsgi.h"


char* bin2hex(const unsigned char *digest, size_t digest_len, char *hexstr)
{
	for (unsigned int i = 0; i < digest_len; i++)
	{
		sprintf(hexstr + (i *2), "%02x", digest[i]);
	}
	hexstr[digest_len * 2] = '\0';
	return hexstr;
}


START_TEST(test_uwsgi_md5)
{
	char digest[16], hexstr[32];

	uwsgi_md5("foobar", 6, digest);
	ck_assert_str_eq(bin2hex(digest, 16, hexstr), "3858f62230ac3c915f300c664312c63f");
}
END_TEST

START_TEST(test_uwsgi_sha1)
{
	char digest[20], hexstr[40];

	uwsgi_sha1("foobar", 6, digest);
	ck_assert_str_eq(bin2hex(digest, 20, hexstr), "8843d7f92416211de9ebb963ff4ce28125932878");

	uwsgi_sha1_2n("foobar", 6, "foobaza", 7, digest);
	ck_assert_str_eq(bin2hex(digest, 20, hexstr), "7382902d76040590d7638c9f0928d8fef8326ec4");
}
END_TEST

Suite *check_ssl(void)
{
	Suite *s = suite_create("uwsgi ssl");
	TCase *tc = tcase_create("ssl");

	suite_add_tcase(s, tc);
	tcase_add_test(tc, test_uwsgi_md5);
	tcase_add_test(tc, test_uwsgi_sha1);
	return s;
}

int main(void)
{
	int nf;
	SRunner *r = srunner_create(check_ssl());
	srunner_run_all(r, CK_NORMAL);
	nf = srunner_ntests_failed(r);
	srunner_free(r);
	return (nf == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
