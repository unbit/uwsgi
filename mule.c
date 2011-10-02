/*

uWSGI mules are very simple workers only managing signals or running custom code in background.

By default they born in signal-only mode, but if you patch them (passing the script/code to run) they will became fully customized daemons.

*/

#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

void uwsgi_mule_handler(void);

void uwsgi_mule(int id) {

	int i;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, uwsgi.mules[id-1].signal_pipe)) {
        	uwsgi_error("socketpair()\n");
        }

	pid_t pid = fork();
	if (pid == 0) {
		uwsgi.muleid = id;
		uwsgi.signal_socket = uwsgi.mules[id-1].signal_pipe[1];

		uwsgi_close_all_sockets();

		for (i = 0; i < 0xFF; i++) {
                	if (uwsgi.p[i]->master_fixup) {
                		uwsgi.p[i]->master_fixup(1);
                	}
                }

		for (i = 0; i < 0xFF; i++) {
                        if (uwsgi.p[i]->post_fork) {
                                uwsgi.p[i]->post_fork();
                        }
                }


		uwsgi_mule_handler();
	}
	else if (pid > 0) {
		uwsgi.mules[id-1].id = id;
		uwsgi.mules[id-1].pid = pid;
		uwsgi_log("spawned uWSGI mule %d (pid: %d)\n", id, (int) pid);
		close(uwsgi.mules[id-1].signal_pipe[1]);
	}
}

void uwsgi_mule_handler() {
	
	ssize_t len;
	uint8_t uwsgi_signal;

	for(;;) {
		len = read(uwsgi.signal_socket, &uwsgi_signal, 1);
		if (len <= 0) {
                	uwsgi_log_verbose("uWSGI mule %d braying: my master died, i will follow him...\n", uwsgi.muleid);
                        end_me(0);
                }
#ifdef UWSGI_DEBUG
		uwsgi_log_verbose("master sent signal %d to mule %d\n", uwsgi_signal, uwsgi.muleid);
#endif
		if (uwsgi_signal_handler(uwsgi_signal)) {
                	uwsgi_log_verbose("error managing signal %d on mule %d\n", uwsgi_signal, uwsgi.mywid);
                }
	}

}
