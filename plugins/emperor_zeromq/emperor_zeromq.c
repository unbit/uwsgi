/*

Emperor zeromq monitor

syntax: zmq://endpoint

The socket is of type ZMQ_PULL

The zeromq support must enabled in the core

Howto:

connect a PUSH zmq socket to the emperor zmq PULL socket.

Start sending multipart messages to govern vassals.

Each message need at least 2 parts:

command
name

where command is the action to trigger and name is the name of the instance

3 optional parts can be specified

config (a string containing the vassal config)
uid (the user id to drop priviliges to in case of tyrant mode)
gid (the group id to drop priviliges to in case of tyrant mode)

There are 2 kind of commands (for now):

touch
destroy

The first one is used for creating and reloading instances while the second is
for destroying. 

If you do not specify a config string, the Emperor will assume you are referring to a static file
available in the Emperor current directory.

A python example:

uwsgi --plugin emperor_zeromq --emperor zmq://tcp://127.0.0.1:5252

import zmq
c = zmq.Context()
s = zmq.Socket(c, zmq.PUSH)
s.connect('tcp://127.0.0.1:5252')
s.send_multipart(['touch','foo.ini',"[uwsgi]\nsocket=:4142"])



*/

#include <uwsgi.h>
#include <zmq.h>

extern struct uwsgi_server uwsgi;

// this is the command manager
static void uwsgi_imperial_monitor_zeromq_cmd(struct uwsgi_emperor_scanner *ues) {
	int64_t more = 0;
	size_t more_size = sizeof(more);
	int i;
        zmq_msg_t msg[6];

        zmq_msg_init(&msg[0]);
        zmq_msg_init(&msg[1]);
        zmq_msg_init(&msg[2]);
        zmq_msg_init(&msg[3]);
        zmq_msg_init(&msg[4]);
        zmq_msg_init(&msg[5]);

        for(i=0;i<6;i++) {
#if ZMQ_VERSION >= ZMQ_MAKE_VERSION(3,0,0)
        	zmq_recvmsg(ues->data, &msg[i], ZMQ_DONTWAIT);
#else
        	zmq_recv(ues->data, &msg[i], ZMQ_NOBLOCK);
#endif
                if (zmq_getsockopt(ues->data, ZMQ_RCVMORE, &more, &more_size)) {
                	uwsgi_error("zmq_getsockopt()");
                        break;
                }
                if (!more && i < 4) break;
	}

        if (i < 1) {
		uwsgi_log("[emperor-zeromq] bad message received (command and instance name required)\n");
		return;
	}

	char *ez_cmd = zmq_msg_data(&msg[0]);
        size_t ez_cmd_len = zmq_msg_size(&msg[0]);

	char *ez_name = zmq_msg_data(&msg[1]);
        size_t ez_name_len = zmq_msg_size(&msg[1]);

	char *ez_config = NULL;
        size_t ez_config_len = 0;

	char *ez_uid = NULL;
        size_t ez_uid_len = 0;

	char *ez_gid = NULL;
        size_t ez_gid_len = 0;

	char *ez_socket_name = NULL;
        size_t ez_socket_name_len = 0;

	char *socket_name = NULL;

	// config
	if (i > 1) {
		ez_config = zmq_msg_data(&msg[2]);	
		ez_config_len = zmq_msg_size(&msg[2]);
	}

	// uid
	if (i > 2) {
		ez_uid = zmq_msg_data(&msg[3]);	
		ez_uid_len = zmq_msg_size(&msg[3]);
	}

	// gid
	if (i > 3) {
		ez_gid = zmq_msg_data(&msg[4]);	
		ez_gid_len = zmq_msg_size(&msg[4]);
	}

	// gid
	if (i > 4) {
		ez_socket_name = zmq_msg_data(&msg[5]);	
		ez_socket_name_len = zmq_msg_size(&msg[5]);
	}

	char *name = uwsgi_concat2n(ez_name, ez_name_len, "", 0);

	// ok let's start checking commands
	if (!uwsgi_strncmp(ez_cmd, ez_cmd_len, "touch", 5)) {

		char *config = NULL;
		if (ez_config_len > 0) {
			config = uwsgi_concat2n(ez_config, ez_config_len, "", 0);
		}

		uid_t vassal_uid = 0;
		gid_t vassal_gid = 0;
		if (ez_uid_len > 0) {
			vassal_uid = uwsgi_str_num(ez_uid, ez_uid_len);
		}	
		if (ez_gid_len > 0) {
			vassal_gid = uwsgi_str_num(ez_gid, ez_gid_len);
		}	

		if (ez_socket_name) {
			socket_name = uwsgi_concat2n(ez_socket_name, ez_socket_name_len, "", 0);
		}
		uwsgi_emperor_simple_do(ues, name, config, uwsgi_now(), vassal_uid, vassal_gid, socket_name);
		if (config) {
			free(config);
		}
		if (socket_name) {
			free(socket_name);
		}
	}
	// destroy an instance
	else if (!uwsgi_strncmp(ez_cmd, ez_cmd_len, "destroy", 7)) {
		struct uwsgi_instance *ui = emperor_get(name);
		if (!ui) {
			uwsgi_log("[emperor-zeromq] unknown instance \"%s\"\n", name);
		}
		else {
			emperor_stop(ui);
		}
	}
	else {
		uwsgi_log("[emperor-zeromq] unknown command \"%.*s\"\n", (int)ez_cmd_len, ez_cmd);
	}

	free(name);

	zmq_msg_close(&msg[0]);
        zmq_msg_close(&msg[1]);
        zmq_msg_close(&msg[2]);
        zmq_msg_close(&msg[3]);
        zmq_msg_close(&msg[4]);
        zmq_msg_close(&msg[5]);
}

// this is the event manager
static void uwsgi_imperial_monitor_zeromq_event(struct uwsgi_emperor_scanner *ues) {

	for(;;) {
		uint32_t zmq_events = 0;
        	size_t opt_len = sizeof(uint32_t);

        	int ret = zmq_getsockopt(ues->data, ZMQ_EVENTS, &zmq_events, &opt_len);
        	if (ret < 0) {
                	uwsgi_error("zmq_getsockopt()");
                	return;
        	}

        	if (zmq_events & ZMQ_POLLIN) {
			uwsgi_imperial_monitor_zeromq_cmd(ues);			
			continue;
        	}
		break;
	}

}


// initialize the zmq PULL socket
static void uwsgi_imperial_monitor_zeromq_init(struct uwsgi_emperor_scanner *ues) {

	void *context = zmq_init(1);
	if (!context) {
		uwsgi_error("uwsgi_imperial_monitor_zeromq_init()/zmq_init()");
		exit(1);
	}
	
	ues->data = zmq_socket(context, ZMQ_PULL);
	if (!ues->data) {
		uwsgi_error("zmq_socket()");
		exit(1);
	}

	if (zmq_bind(ues->data, ues->arg+6)) {
		uwsgi_error("zmq_socket()");
		exit(1);
	}

	size_t zmq_socket_len = sizeof(int);
        if (zmq_getsockopt(ues->data, ZMQ_FD, &ues->fd, &zmq_socket_len) < 0) {
        	uwsgi_error("zmq_getsockopt()");
        	exit(1);
        }

	ues->event_func = uwsgi_imperial_monitor_zeromq_event;

        event_queue_add_fd_read(uwsgi.emperor_queue, ues->fd);
}


// noop
static void uwsgi_imperial_monitor_zeromq(struct uwsgi_emperor_scanner *ues) {
        return;
}


void emperor_zeromq_init(void) {
	uwsgi_register_imperial_monitor("zmq", uwsgi_imperial_monitor_zeromq_init, uwsgi_imperial_monitor_zeromq);
}



struct uwsgi_plugin emperor_zeromq_plugin = {
	.name = "emperor_zeromq",
	.on_load = emperor_zeromq_init,
};
