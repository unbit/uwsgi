#include <uwsgi.h>

/*

	The pipe logger

	Author: INADA Naoki

	every log line is sent to the stdin of an external process	

	Example:

		req-logger = pipe:/usr/local/bin/mylogger

*/

static ssize_t uwsgi_pipe_logger(struct uwsgi_logger *ul, char *message, size_t len) {
	if (!ul->configured) {
		if (ul->arg) {
			int pipefd[2];
			// retry later...
			if (pipe(pipefd) < 0) return -1;
			pid_t pid = fork();
			if (pid < 0) return -1;
			if (pid > 0) {
				close(pipefd[0]);
				ul->fd = pipefd[1];
			}
			else {
				// child
				if (setsid() < 0) {
					uwsgi_error("setsid()");
					exit(1);
				}
				close(pipefd[1]);
				dup2(pipefd[0], STDIN_FILENO);
				close(pipefd[0]);
				uwsgi_exec_command_with_args(ul->arg);
				exit(1);	// if here something seriously failed
			}
		}

		ul->configured = 1;
	}

	int err = write(ul->fd, message, len);
	// on failed writes, re-configure the logger
	if (err <= 0) {
		close(ul->fd);
		ul->configured = 0;
		return err;
	}
	return 0;
}

static void uwsgi_pipe_logger_register() {
	uwsgi_register_logger("pipe", uwsgi_pipe_logger);
}

struct uwsgi_plugin logpipe_plugin = {
	.name = "logpipe",
	.on_load = uwsgi_pipe_logger_register,
};
