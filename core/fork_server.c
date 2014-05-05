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
	int fd = bind_to_unix(socket, uwsgi.listen_queue, uwsgi.chmod_socket, uwsgi.abstract_socket);
	if (fd < 0) exit(1);

	if (uwsgi_socket_passcred(fd)) exit(1);

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
		ssize_t len = uwsgi_recv_cred2(client_fd, buf, 4096, &ppid, &uid, &gid);
		uwsgi_log("RET = %d %d %d %d\n", len, ppid, uid, gid);

		pid_t pid = fork();
		if (pid < 0) {
			uwsgi_error("uwsgi_fork_server()/fork()");
			goto end;		
		}
		else if (pid > 0) {
			waitpid(pid, NULL, 0);
			goto end;
		}
		else {
			// reparent the process
#ifdef __linux__
			if (prctl(PR_SET_CHILD_SUBREAPER, ppid, 0, 0, 0)) {
				uwsgi_error("uwsgi_fork_server()/fork()");
				exit(1);
			}
#endif
			// now fork again and kill
			pid_t new_pid = fork();
			if (new_pid < 0) {
                        	uwsgi_error("uwsgi_fork_server()/fork()");
				exit(1);
			}
			else if (new_pid > 0) {
				exit(0);
			}
			else {
				uwsgi_log("double fork() and reparenting successfull (new pid: %d)\n", getpid());
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
// on linux and sun we need to fix orig_argv
#if defined(__linux__) || defined(__sun__)
#endif

	
				// this is the only step required to have a consistent environment
				uwsgi.fork_socket = NULL;
				return;
			}
		}	

end:
		close(client_fd);
		
	}
}
