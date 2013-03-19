/*

Emperor AMQP monitor

syntax: amqp://[username:password@]host[/vhost]

*/

#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;

void uwsgi_imperial_monitor_amqp_init(struct uwsgi_emperor_scanner *);

void uwsgi_imperial_monitor_amqp_event(struct uwsgi_emperor_scanner *ues) {

	uint64_t msgsize;
	char *amqp_routing_key = NULL;
	struct uwsgi_instance *ui_current;
	struct stat st;

	char *config = uwsgi_amqp_consume(ues->fd, &msgsize, &amqp_routing_key);
				
	if (!config) {
		uwsgi_log("problem with RabbitMQ server, trying reconnection...\n");
		close(ues->fd);
		ues->fd = -1;
		return;
	}

	// having a routing key means the body will be mapped to a config chunk
	if (amqp_routing_key) {
		uwsgi_log("AMQP routing_key = %s\n", amqp_routing_key);

		ui_current = emperor_get(amqp_routing_key);

                if (ui_current) {
			// make a new config
			free(ui_current->config);
			ui_current->config = config;
			ui_current->config_len = msgsize;
			if (!msgsize) {
				emperor_stop(ui_current);
			}
			else {
                               	emperor_respawn(ui_current, uwsgi_now());
			}
			goto end0;
                }

		if (msgsize > 0) {
                	emperor_add(ues, amqp_routing_key, uwsgi_now(), config, msgsize, 0, 0, NULL);
		}

end0:
		free(config);
                free(amqp_routing_key);
                return;
	}


	// no routing key means the body contains a path to a config file
	if (msgsize >= 0xff || !msgsize) goto end;

	char *config_file = uwsgi_concat2n(config, msgsize, "", 0);

	ui_current = emperor_get(config_file);

	// if non-http check for file existance
	if (strncmp(config_file, "http://", 7)) {
		if (stat(config_file, &st)) {
			free(config_file);
			if (ui_current)
				emperor_stop(ui_current);
			goto end;
		}

		if (!S_ISREG(st.st_mode)) {
			free(config_file);
			if (ui_current)
				emperor_stop(ui_current);
			goto end;
		}
	}


	if (ui_current) {
		emperor_respawn(ui_current, uwsgi_now());
	}
	else {
		emperor_add(ues, config_file, uwsgi_now(), NULL, 0, 0, 0, NULL);
	}

	free(config_file);

end:
	free(config);

}


void uwsgi_imperial_monitor_amqp_init(struct uwsgi_emperor_scanner *ues) {

	char *vhost = "/";
	char *username = "guest";
	char *password = "guest";

        ues->fd = uwsgi_connect(ues->arg+7, -1, 0);
        if (ues->fd < 0) {
                uwsgi_log("unable to connect to AMQP server\n");
                return;
        }

        if (uwsgi_amqp_consume_queue(ues->fd, vhost, username, password, "", "uwsgi.emperor", "fanout") < 0) {
                close(ues->fd);
                ues->fd = -1;
                uwsgi_log("unable to subscribe to AMQP queue\n");
                return;
        }

	ues->event_func = uwsgi_imperial_monitor_amqp_event;

        event_queue_add_fd_read(uwsgi.emperor_queue, ues->fd);
}


void uwsgi_imperial_monitor_amqp(struct uwsgi_emperor_scanner *ues) {
	// try a reconnection
	if (ues->fd == -1) {
		uwsgi_imperial_monitor_amqp_init(ues);
	}
        return;
}


void emperor_amqp_init(void) {
	uwsgi_register_imperial_monitor("amqp", uwsgi_imperial_monitor_amqp_init, uwsgi_imperial_monitor_amqp);
}



struct uwsgi_plugin emperor_amqp_plugin = {
	.name = "emperor_amqp",
	.on_load = emperor_amqp_init,
};
