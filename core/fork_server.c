#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

/*

on connection retrieve the uid,gid and pid of the connecting process, in addition to up to 3
file descriptors (emperor pipe, emperor pipe_config, on_demand socket dup()'ed to 0)

if authorized, double fork, get the pid of the second child and exit()
its parent (this will force the Emperor to became its subreaper).

from now on, we can consider the new child as a full-featured vassal

*/

#define VASSAL_HAS_CONFIG 0x02
#define VASSAL_HAS_ON_DEMAND 0x04

static void parse_argv_hook(uint16_t item, char *value, uint16_t vlen, void *data) {
	struct uwsgi_string_list **usl = (struct uwsgi_string_list **) data;
	uwsgi_string_new_list(usl, uwsgi_concat2n(value, vlen, "", 0));
}


void uwsgi_fork_server(char *socket) {
	// map fd 0 to /dev/null to avoid mess
	uwsgi_remap_fd(0, "/dev/null");

	int fd = bind_to_unix(socket, uwsgi.listen_queue, uwsgi.chmod_socket, uwsgi.abstract_socket);
	if (fd < 0) exit(1);

	// automatically receive credentials (TODO make something useful with them, like checking the pid is from the Emperor)
	if (uwsgi_socket_passcred(fd)) exit(1);

	// initialize the event queue
	int eq = event_queue_init();
	if (uwsgi.has_emperor) {
		event_queue_add_fd_read(eq, uwsgi.emperor_fd);
	}
	event_queue_add_fd_read(eq, fd);

	// now start waiting for connections
	for(;;) {
		int interesting_fd = -1;
		int rlen = event_queue_wait(eq, -1, &interesting_fd);
		if (rlen <= 0) continue;
		if (uwsgi.has_emperor && interesting_fd == uwsgi.emperor_fd) {
			char byte;
        		ssize_t rlen = read(uwsgi.emperor_fd, &byte, 1);
        		if (rlen > 0) {
                		uwsgi_log_verbose("received message %d from emperor\n", byte);
			}
			exit(0);
		}
		if (interesting_fd != fd) continue;
		struct sockaddr_un client_src;
        	socklen_t client_src_len = 0;
        	int client_fd = accept(fd, (struct sockaddr *) &client_src, &client_src_len);
        	if (client_fd < 0) {
                	uwsgi_error("uwsgi_fork_server()/accept()");
			continue;
        	}
		char hbuf[4];
		pid_t ppid = -1;
		uid_t uid = -1;
		gid_t gid = -1;
		int fds_count = 8;
		size_t remains = 4;
		// we can receive up to 8 fds (generally from 1 to 3)
		int fds[8];
		// we only read 4 bytes header
		ssize_t len = uwsgi_recv_cred_and_fds(client_fd, hbuf, remains, &ppid, &uid, &gid, fds, &fds_count);
		uwsgi_log_verbose("[uwsgi-fork-server] connection from pid: %d uid: %d gid:%d fds:%d\n", ppid, uid, gid, fds_count);
		if (len <= 0 || fds_count < 1) {
			uwsgi_error("uwsgi_fork_server()/recvmsg()");
			goto end;
		}
		remains -= len;
	
		if (uwsgi_read_nb(client_fd, hbuf + (4-remains), remains, uwsgi.socket_timeout)) {
			uwsgi_error("uwsgi_fork_server()/uwsgi_read_nb()");
			goto end;
		}

		struct uwsgi_header *uh = (struct uwsgi_header *) hbuf;
		// this memory area must be freed in the right place !!!
		char *body_argv = uwsgi_malloc(uh->_pktsize);
		if (uwsgi_read_nb(client_fd, body_argv, uh->_pktsize, uwsgi.socket_timeout)) {
			free(body_argv);
                        uwsgi_error("uwsgi_fork_server()/uwsgi_read_nb()");
                        goto end;
                }

		pid_t pid = fork();
		if (pid < 0) {
			free(body_argv);
			int i;
			for(i=0;i<fds_count;i++) close(fds[i]);
			// error on fork()
			uwsgi_error("uwsgi_fork_server()/fork()");
			goto end;		
		}
		else if (pid > 0) {
			free(body_argv);
			// close inherited decriptors 
			int i;
			for(i=0;i<fds_count;i++) close(fds[i]);
			// wait for child death...
			waitpid(pid, NULL, 0);
			goto end;
		}
		else {
			// close Emperor channels
			// we do not close others file desctiptor as lot
			// of funny tricks could be accomplished with them
			if (uwsgi.has_emperor) {
				close(uwsgi.emperor_fd);
				if (uwsgi.emperor_fd_config > -1) close(uwsgi.emperor_fd_config);
			}
			
			// set EMPEROR_FD and FD_CONFIG env vars	
			char *uef = uwsgi_num2str(fds[0]);
        		if (setenv("UWSGI_EMPEROR_FD", uef, 1)) {
                		uwsgi_error("uwsgi_fork_server()/setenv()");
                		exit(1);
        		}
        		free(uef);

			int pipe_config = -1;
			int on_demand = -1;

			if (uh->modifier2 & VASSAL_HAS_CONFIG && fds_count > 1) {
				pipe_config = fds[1];	
				char *uef = uwsgi_num2str(pipe_config);
				if (setenv("UWSGI_EMPEROR_FD_CONFIG", uef, 1)) {
                                	uwsgi_error("uwsgi_fork_server()/setenv()");
                                	exit(1);
                        	}
                        	free(uef);
			}

			if (uh->modifier2 & VASSAL_HAS_ON_DEMAND && fds_count > 1) {
				if (pipe_config > -1) {
					if (fds_count > 2) {
						on_demand = fds[2];
					}
				}
				else {
					on_demand = fds[1];
				}
			}
			// dup the on_demand socket to 0 and close it
			if (on_demand > -1) {
				if (dup2(on_demand, 0) < 0) {
					uwsgi_error("uwsgi_fork_server()/dup2()");
					exit(1);
				}
				close(on_demand);
			}

			// now fork again and die
			pid_t new_pid = fork();
			if (new_pid < 0) {
                        	uwsgi_error("uwsgi_fork_server()/fork()");
				exit(1);
			}
			else if (new_pid > 0) {
				exit(0);
			}
			else {
				// send the pid to the client_fd and close it
				struct uwsgi_buffer *ub = uwsgi_buffer_new(uwsgi.page_size);
				// leave space for header
				ub->pos = 4;
				if (uwsgi_buffer_append_keynum(ub, "pid", 3, getpid())) exit(1); 
				// fix uwsgi header
        			if (uwsgi_buffer_set_uh(ub, 35, 0)) goto end;
				// send_pid()
				if (uwsgi_write_nb(client_fd, ub->buf, ub->pos, uwsgi.socket_timeout)) exit(1);
				close(client_fd);
				uwsgi_log("double fork() and reparenting successful (new pid: %d)\n", getpid());
				uwsgi_buffer_destroy(ub);


				// now parse the uwsgi packet array and build the argv
				struct uwsgi_string_list *usl = NULL, *usl_argv = NULL;
				uwsgi_hooked_parse_array(body_argv, uh->_pktsize, parse_argv_hook, &usl_argv);
				free(body_argv);

				// build new argc/argv
				uwsgi.new_argc = 0;
				size_t procname_len = 1;
				uwsgi_foreach(usl, usl_argv) {
					uwsgi.new_argc++;
					procname_len += usl->len + 1;
				}

				char *new_procname = uwsgi_calloc(procname_len);
				
				uwsgi.new_argv = uwsgi_calloc(sizeof(char *) * (uwsgi.new_argc + 1));
				int counter = 0;
				uwsgi_foreach(usl, usl_argv) {
					uwsgi.new_argv[counter] = usl->value;
					strcat(new_procname, usl->value);
					strcat(new_procname, " ");
					counter++;
				}
				// fix process name
				uwsgi_set_processname(new_procname);
				free(new_procname);
				// this is the only step required to have a consistent environment
				uwsgi.fork_socket = NULL;
				// this avoids the process to re-exec itself
				uwsgi.exit_on_reload = 1;
				// fixup the Emperor communication
				uwsgi_check_emperor();
				// continue with uWSGI startup
				return;
			}
		}	

end:
		close(client_fd);
		
	}
}
