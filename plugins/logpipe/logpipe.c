#include "../../uwsgi.h"

ssize_t uwsgi_pipe_logger(struct uwsgi_logger *ul, char *message, size_t len) {
    if (!ul->configured) {
        ul->configured = 1;
        if (ul->arg) {
            int pipefd[2];
            if (-1 == pipe(pipefd)) {
                perror("pipe");
                uwsgi_error("Can't create pipe");
                return 0;
            }
            if (fork()) {
                close(pipefd[0]);
                ul->fd = pipefd[1];
            } else {
                // child
                setsid();
                close(pipefd[1]);
                dup2(pipefd[0], STDIN_FILENO);
                close(pipefd[0]);
                uwsgi_exec_command_with_args(ul->arg);
                return 0; // don't come here.
            }
        }
    }

    if (ul->fd) {
        int err;
        err = write(ul->fd, message, len);
        if (err < 0) {
            perror("write");
            uwsgi_error("Can't write to pipe.");
            close(ul->fd);
            ul->fd = 0;
        }
        return err;
    }
    return 0;
}

void uwsgi_pipe_logger_register() {
    uwsgi_register_logger("pipe", uwsgi_pipe_logger);
}

struct uwsgi_plugin logpipe_plugin = {
    .name = "logpipe",
    .on_load = uwsgi_pipe_logger_register,
};
