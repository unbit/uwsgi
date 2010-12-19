#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

int register_signal(uint8_t sig, char *payload) {

	switch(sig) {

		case 10:
			if (uwsgi.files_monitored_cnt < 64) {
				uwsgi.files_monitored[uwsgi.files_monitored_cnt].filename = uwsgi_concat2(payload,"");
				uwsgi.files_monitored[uwsgi.files_monitored_cnt].registered = 0;
				// master is not running
				if (uwsgi.master_queue != -1) {
					uwsgi.files_monitored[uwsgi.files_monitored_cnt].fd = event_queue_add_file_monitor(uwsgi.master_queue, payload, &uwsgi.files_monitored[uwsgi.files_monitored_cnt].id);
					uwsgi.files_monitored[uwsgi.files_monitored_cnt].registered = 1;
				}
				uwsgi.files_monitored_cnt++;
			}
			else {
				uwsgi_log("you can register max 64 file monitors !!!\n");
			}

		case 11:
			if (uwsgi.timers_cnt < 64) {
				uwsgi.timers[uwsgi.timers_cnt].value = atoi(payload);
				uwsgi.timers[uwsgi.timers_cnt].registered = 0;
				// master is not running
				if (uwsgi.master_queue != -1) {
					uwsgi.timers[uwsgi.timers_cnt].fd = event_queue_add_timer(uwsgi.master_queue, &uwsgi.timers[uwsgi.timers_cnt].id, uwsgi.timers[uwsgi.timers_cnt].value);
					uwsgi.timers[uwsgi.timers_cnt].registered = 1;
				}
				uwsgi.timers_cnt++;
			}
			else {
				uwsgi_log("you can register max 64 timers !!!\n");
			}
	}

	return 0;
}
