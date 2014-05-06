#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

/*

on connection retrieve the uid,gid and pid of the connecting process, in addition to up to 3
file descriptors (emperor pipe, emperor pipe_config, on_demand socket dup()'ed to 0)

if authorized, double fork, get the pid of the second child and exit()
its parent (this will force the Emperor to became its subreaper).

from now on, we can consider the new child as a full-featured vassal

*/

void uwsgi_fork_server(char *socket) {
	// map fd 0 to /dev/null to avoid mess
	uwsgi_remap_fd(0, "/dev/null");

	int fd = bind_to_unix(socket, uwsgi.listen_queue, uwsgi.chmod_socket, uwsgi.abstract_socket);
	if (fd < 0) exit(1);

	// automatically receive credentials (TODO make something useful with them, like checking the pid is from the Emperor)
	if (uwsgi_socket_passcred(fd)) exit(1);

	// now start waiting for connections
	for(;;) {
		struct sockaddr_un client_src;
        	socklen_t client_src_len = 0;
        	int client_fd = accept(fd, (struct sockaddr *) &client_src, &client_src_len);
        	if (client_fd < 0) {
                	uwsgi_error("uwsgi_fork_server()/accept()");
			continue;
        	}
		char buf[4096];
		pid_t ppid = -1;
		uid_t uid = -1;
		gid_t gid = -1;
		int fds_count = 0;
		// we can receive upto 8 fds (generally from 1 to 3)
		int fds[8];
		ssize_t len = uwsgi_recv_cred_and_fds(client_fd, buf, 4096, &ppid, &uid, &gid, fds, &fds_count);
		uwsgi_log("RET = %d %d %d %d\n", len, ppid, uid, gid);

		pid_t pid = fork();
		if (pid < 0) {
			// error on fork()
			uwsgi_error("uwsgi_fork_server()/fork()");
			goto end;		
		}
		else if (pid > 0) {
			// wait for child death...
			waitpid(pid, NULL, 0);
			goto end;
		}
		else {
			// close everything excluded the passed fds and client_fd
			// set EMPEROR_FD and FD_CONFIG env vars	
			// dup the on_demand socket to 0 and close it

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
				// send_pid()
				close(client_fd);
				uwsgi_log("double fork() and reparenting successfull (new pid: %d)\n", getpid());


				// now parse the uwsgi packet array and build the argv
				uwsgi.new_argc = 6;
				// we do not free old uwsgi.argv as it could contains still used pointers
				uwsgi_log("%s\n", uwsgi.binary_path);
				uwsgi.new_argv = uwsgi_malloc(sizeof(char *) * (uwsgi.argc+1));
				uwsgi.new_argv[0] = uwsgi.binary_path;
				uwsgi.new_argv[1] = uwsgi_str("--http-socket");
				uwsgi.new_argv[2] = uwsgi_str(":1717");
				uwsgi.new_argv[3] = uwsgi_str("--master");
				uwsgi.new_argv[4] = uwsgi_str("--processes");
				uwsgi.new_argv[5] = uwsgi_str("8");
				uwsgi.new_argv[6] = NULL;

				// this is the only step required to have a consistent environment
				uwsgi.fork_socket = NULL;
				// continue with uWSGI startup
				return;
			}
		}	

end:
		close(client_fd);
		
	}
}
