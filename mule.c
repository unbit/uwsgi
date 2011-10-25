/*

uWSGI mules are very simple workers only managing signals or running custom code in background.

By default they born in signal-only mode, but if you patch them (passing the script/code to run) they will became fully customized daemons.

*/

#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

void uwsgi_mule_handler(void);

void uwsgi_mule(int id) {

	int i;

	pid_t pid = uwsgi_fork(uwsgi.mules[id-1].name);
	if (pid == 0) {
		uwsgi.muleid = id;
		// avoid race conditions
		uwsgi.mules[id-1].id = id;
		uwsgi.mules[id-1].pid = getpid();

		uwsgi_fixup_fds(0, id);

		uwsgi.my_signal_socket = uwsgi.mules[id-1].signal_pipe[1];
		uwsgi.signal_socket = uwsgi.shared->mule_signal_pipe[1];

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


		if (uwsgi.mules[id-1].patch) {
			for (i = 0; i < 0xFF; i++) {
                        	if (uwsgi.p[i]->mule) {
                                	if (uwsgi.p[i]->mule(uwsgi.mules[id-1].patch) == 1) {
						// never here
						break;
					}
				}
                        }
		}

		uwsgi_mule_handler();
	}
	else if (pid > 0) {
		uwsgi.mules[id-1].id = id;
		uwsgi.mules[id-1].pid = pid;
		uwsgi_log("spawned uWSGI mule %d (pid: %d)\n", id, (int) pid);
	}
}

int uwsgi_farm_has_mule(struct uwsgi_farm *farm, int muleid) {

	struct uwsgi_mule_farm *umf = farm->mules;

	while(umf) {
		if (umf->mule->id == muleid) {
			return 1;
		}
		umf = umf->next;
	}

	return 0;
}

int farm_has_signaled(int fd) {

	int i;
	for(i=0;i<uwsgi.farms_cnt;i++) {
		struct uwsgi_mule_farm *umf = uwsgi.farms[i].mules;
		while(umf) {
			if (umf->mule->id == uwsgi.muleid && uwsgi.farms[i].signal_pipe[1] == fd) {
				return 1;
			}
			umf = umf->next;
		}
	}
	
	return 0;
}

int farm_has_msg(int fd) {

        int i;
        for(i=0;i<uwsgi.farms_cnt;i++) {
                struct uwsgi_mule_farm *umf = uwsgi.farms[i].mules;
                while(umf) {
                        if (umf->mule->id == uwsgi.muleid && uwsgi.farms[i].queue_pipe[1] == fd) {
                                return 1;
                        }
                        umf = umf->next;
                }
        }

        return 0;
}


void uwsgi_mule_add_farm_to_queue(int queue) {

	int i;
	for(i=0;i<uwsgi.farms_cnt;i++) {
		if (uwsgi_farm_has_mule(&uwsgi.farms[i], uwsgi.muleid)) {
			event_queue_add_fd_read(queue, uwsgi.farms[i].signal_pipe[1]);	
			event_queue_add_fd_read(queue, uwsgi.farms[i].queue_pipe[1]);	
		}
	}
}

void uwsgi_mule_handler() {
	
	ssize_t len;
	uint8_t uwsgi_signal;
	int rlen;
	int interesting_fd;
	
	// this must be configurable
	char message[65536];

	int mule_queue = event_queue_init();

	event_queue_add_fd_read(mule_queue, uwsgi.signal_socket);
	event_queue_add_fd_read(mule_queue, uwsgi.my_signal_socket);
	event_queue_add_fd_read(mule_queue, uwsgi.mules[uwsgi.muleid-1].queue_pipe[1]);

	uwsgi_mule_add_farm_to_queue(mule_queue);

	for(;;) {
		rlen = event_queue_wait(mule_queue, -1, &interesting_fd);
		if (rlen <= 0) {
			continue;
		}

		if (interesting_fd == uwsgi.signal_socket || interesting_fd == uwsgi.my_signal_socket || farm_has_signaled(interesting_fd)) {
			len = read(interesting_fd, &uwsgi_signal, 1);
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
		else if (interesting_fd == uwsgi.mules[uwsgi.muleid-1].queue_pipe[1] || farm_has_msg(interesting_fd)) {
			len = read(interesting_fd, message, 65536);
			if (len < 0) {
				uwsgi_error("read()");
			}	
			else if (len == 0) {
				exit(1);
			}
			else {
				uwsgi_log("*** mule %d received a %d bytes message ***\n", uwsgi.muleid, len);
			}
		}
	}

}

struct uwsgi_mule *get_mule_by_id(int id) {

	int i;

	for(i=0;i<uwsgi.mules_cnt;i++) {
		if (uwsgi.mules[i].id == id) {
			return &uwsgi.mules[i];
		}
	}

	return NULL;
}

struct uwsgi_mule_farm *uwsgi_mule_farm_new(struct uwsgi_mule_farm **umf, struct uwsgi_mule *um) {

        struct uwsgi_mule_farm *uwsgi_mf = *umf, *old_umf;

        if (!uwsgi_mf) {
                *umf = uwsgi_malloc(sizeof(struct uwsgi_mule_farm));
                uwsgi_mf = *umf;
        }
        else {
                while(uwsgi_mf) {
                        old_umf = uwsgi_mf;
			uwsgi_mf = uwsgi_mf->next;
                }

                uwsgi_mf = uwsgi_malloc(sizeof(struct uwsgi_mule_farm));
                old_umf->next = uwsgi_mf;
        }

        uwsgi_mf->mule = um;
        uwsgi_mf->next = NULL;

        return uwsgi_mf;
}

