#include <uwsgi.h>
#include <zmq.h>

extern struct uwsgi_server uwsgi;

static struct uwsgi_option uwsgi_zmq_logger_options[] = {
	{"log-zeromq", required_argument, 0, "send logs to a zeromq server", uwsgi_opt_set_logger, "zeromq", UWSGI_OPT_MASTER | UWSGI_OPT_LOG_MASTER},
	{NULL, 0, 0, NULL, NULL, NULL, 0}, 
};

// the zeromq logger
static ssize_t uwsgi_zeromq_logger(struct uwsgi_logger *ul, char *message, size_t len) {

        if (!ul->configured) {

                if (!ul->arg) {
                        uwsgi_log_safe("invalid zeromq syntax\n");
                        exit(1);
                }

                void *ctx = zmq_init(1);
		if (!ctx) exit(1);

                ul->data = zmq_socket(ctx, ZMQ_PUSH);
                if (ul->data == NULL) {
                        uwsgi_error_safe("zmq_socket()");
                        exit(1);
                }

                if (zmq_connect(ul->data, ul->arg) < 0) {
                        uwsgi_error_safe("zmq_connect()");
                        exit(1);
                }

                ul->configured = 1;
        }

        zmq_msg_t msg;
        if (zmq_msg_init_size(&msg, len) == 0) {
                memcpy(zmq_msg_data(&msg), message, len);
#if ZMQ_VERSION >= ZMQ_MAKE_VERSION(3,0,0)
                zmq_sendmsg(ul->data, &msg, 0);
#else
                zmq_send(ul->data, &msg, 0);
#endif
                zmq_msg_close(&msg);
        }

        return 0;
}

static void uwsgi_zmq_logger_register() {
        uwsgi_register_logger("zmq", uwsgi_zeromq_logger);
        uwsgi_register_logger("zeromq", uwsgi_zeromq_logger);
}

struct uwsgi_plugin logzmq_plugin = {
	.name = "logzmq",
	.options = uwsgi_zmq_logger_options,
	.on_load = uwsgi_zmq_logger_register,
};
