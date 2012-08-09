/*

	uWSGI pam plugin 20120809

	Credits:

	Harry Percival (PythonAnywhere.com)


*/
#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;

#include <security/pam_appl.h>

char *uwsgi_pam_service = NULL;
char *uwsgi_pam_user = NULL;

struct uwsgi_option uwsgi_pam_options[] = {
        {"pam", required_argument, 0, "set the pam service name to use", uwsgi_opt_set_str, &uwsgi_pam_service, 0},
        {"pam-user", required_argument, 0, "set a fake user for pam", uwsgi_opt_set_str, &uwsgi_pam_user, 0},
        {0, 0, 0, 0, 0, 0 ,0},

};

static int uwsgi_pam_conv(int num_msg, const struct pam_message **msg,
              struct pam_response **resp, void *appdata_ptr) {
	int i;
	for(i=0;i<num_msg;i++) {
		uwsgi_log("%s\n", msg[i]->msg);
	}
	return PAM_SUCCESS;
}

void uwsgi_setup_pam(void) {
	pam_handle_t *pamh = NULL;
	struct pam_conv pamc = { uwsgi_pam_conv, NULL };

	if (uwsgi_pam_service) {
		if (!uwsgi_pam_user) {
			if (!uwsgi.uid) {
				uwsgi_log("you cannot use pam for root !!!\n");
				exit(1);
			}			
			struct passwd *pwd = getpwuid(uwsgi.uid);
			if (!pwd) {
				uwsgi_error("getpwuid()");
				exit(1);
			}
			// no need to make a copy as we will use that only here
			uwsgi_pam_user = pwd->pw_name;
		}

		if (pam_start(uwsgi_pam_service, uwsgi_pam_user, &pamc, &pamh) != PAM_SUCCESS) {
			uwsgi_error("pam_start()");
			exit(1);
		}
		if (pam_open_session(pamh, 0) != PAM_SUCCESS) {
			uwsgi_error("pam_open_session()");
			exit(1);
		}
	}
}

struct uwsgi_plugin pam_plugin = {
	.name = "pam",
	.options = uwsgi_pam_options,
	.before_privileges_drop = uwsgi_setup_pam,
};
