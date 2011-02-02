#include "../../uwsgi.h"

#include <wordexp.h>

extern struct uwsgi_server uwsgi;

char *cgi_docroot;

#define LONG_ARGS_CGI_BASE	17000 + ((9 + 1) * 100)
#define LONG_ARGS_CGI		LONG_ARGS_CGI_BASE + 1

struct option uwsgi_cgi_options[] = {

        {"cgi", required_argument, 0, LONG_ARGS_CGI},
        {0, 0, 0, 0},

};

int uwsgi_cgi_init(){


	uwsgi_log("initialized CGI engine\n");

	return 1;

}

int uwsgi_cgi_request(struct wsgi_request *wsgi_req) {

	int i;
	pid_t cgi_pid;
	int waitpid_status;
	char *argv[2];
	char full_path[PATH_MAX];

	/* Standard CGI request */
	if (!wsgi_req->uh.pktsize) {
		uwsgi_log("Invalid CGI request. skip.\n");
		return -1;
	}


	if (uwsgi_parse_vars(wsgi_req)) {
		uwsgi_log("Invalid CGI request. skip.\n");
		return -1;
	}

	// check for file availability (and 'runnability')

	cgi_pid = fork();

	if (cgi_pid < 0) {
		uwsgi_error("fork()");
		return -1;
	}

	if (cgi_pid > 0) {
		// close input
		close(wsgi_req->poll.fd);
		wsgi_req->fd_closed = 1;

		// now wait for fd	
		if (waitpid(cgi_pid, &waitpid_status ,0) > 0) {
			uwsgi_log("CGI FINISHED\n");
		}
		return 0;
	}

	// close all the fd except wsgi_req->poll.fd and 2;

	for(i=0;i< (int)uwsgi.max_fd;i++) {
		if (i != wsgi_req->poll.fd && i != 2) {
			close(i);
		}
	}

	// now map wsgi_req->poll.fd to 0 && 1
	if (wsgi_req->poll.fd != 0) {
		dup2(wsgi_req->poll.fd, 0);
		close(wsgi_req->poll.fd);
	}

	dup2(0,1);
	

	// fill cgi env
	for(i=0;i<wsgi_req->var_cnt;i++) {
		// no need to free the putenv() memory
		if (putenv(uwsgi_concat3n(wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len, "=", 1, wsgi_req->hvec[i+1].iov_base, wsgi_req->hvec[i+1].iov_len))) {
			uwsgi_error("putenv()");
		}
		i++;
	}

	char *path_info = uwsgi_concat4n(cgi_docroot, strlen(cgi_docroot), "/", 1,wsgi_req->path_info, wsgi_req->path_info_len, "", 0);
	uwsgi_log("requested %s %s\n", path_info, realpath(path_info, full_path));

	argv[0] = full_path;
	argv[1] = NULL;
	if (execv(argv[0], argv)) {
		uwsgi_error("execv()");
	}

	// never here
	exit(1);

	return 0;
}


void uwsgi_cgi_after_request(struct wsgi_request *wsgi_req) {

	if (uwsgi.shared->options[UWSGI_OPTION_LOGGING])
		log_request(wsgi_req);
}

int uwsgi_cgi_manage_options(int i, char *optarg) {

        switch(i) {
                case LONG_ARGS_CGI:
                        cgi_docroot = optarg;
                        return 1;
        }

        return 0;
}


struct uwsgi_plugin cgi_plugin = {

	.name = "cgi",
	.modifier1 = 9,
	.init = uwsgi_cgi_init,
	.options = uwsgi_cgi_options,
	.manage_opt = uwsgi_cgi_manage_options,
	.request = uwsgi_cgi_request,
	.after_request = uwsgi_cgi_after_request,

};
