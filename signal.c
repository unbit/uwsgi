#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

int uwsgi_signal_handler(uint8_t sig) {

	struct uwsgi_signal_entry *use = NULL; 

	use = &uwsgi.shared->signal_table[sig];

	if (!use->kind) {
		return -1;
	}

	if (!uwsgi.p[use->modifier1]->signal_handler) {
		return -1;
	}	
	
	return uwsgi.p[use->modifier1]->signal_handler(sig, use->handler, use->payload, use->payload_size);
}

void uwsgi_register_signal(uint8_t sig, uint8_t kind, void *handler, uint8_t modifier1, char *payload, uint8_t payload_size) {

	struct uwsgi_signal_entry *use = NULL;

	uwsgi_lock(uwsgi.signal_table_lock);

	use = &uwsgi.shared->signal_table[sig];

	use->kind = kind;
	use->handler = handler;
	use->modifier1 = modifier1;
	
	memcpy(use->payload, payload, payload_size);

	use->payload_size = payload_size;

	/*
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
			break;
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
			break;
	}
	*/

	uwsgi_log("registered signal %d\n", sig);

	uwsgi_unlock(uwsgi.signal_table_lock);

}


void uwsgi_register_file_monitor(uint8_t sig, char *filename, uint8_t kind, void *handler, uint8_t modifier1) {

	if (strlen(filename) > (0xff-1)) {
		uwsgi_log("uwsgi_register_file_monitor: invalid filename length\n");
		return;
	}

	uwsgi_lock(uwsgi.fmon_table_lock);

	if (ushared->files_monitored_cnt < 64) {

		// fill the fmon table, the master will use it to add items to the event queue
		memcpy(ushared->files_monitored[ushared->files_monitored_cnt].filename, filename, strlen(filename));
                ushared->files_monitored[ushared->files_monitored_cnt].registered = 0;
		ushared->files_monitored[ushared->files_monitored_cnt].sig = sig;
		uwsgi_register_signal(sig, kind, handler, modifier1, filename, strlen(filename));
		ushared->files_monitored_cnt++;
	}
	else {
		uwsgi_log("you can register max 64 file monitors !!!\n");
	}

	uwsgi_unlock(uwsgi.fmon_table_lock);

}

void uwsgi_register_timer(uint8_t sig, int secs, uint8_t kind, void *handler, uint8_t modifier1) {

	uwsgi_lock(uwsgi.timer_table_lock);

	if (ushared->timers_cnt < 64) {

		// fill the timer table, the master will use it to add items to the event queue
		ushared->timers[ushared->timers_cnt].value = secs;
		snprintf(ushared->timers[ushared->timers_cnt].svalue, 0xff, "%d", secs);
		ushared->timers[ushared->timers_cnt].registered = 0;
		ushared->timers[ushared->timers_cnt].sig = sig;
		uwsgi_register_signal(sig, kind, handler, modifier1, ushared->timers[ushared->timers_cnt].svalue, strlen(ushared->timers[ushared->timers_cnt].svalue));
		ushared->timers_cnt++;
	}
	else {
		uwsgi_log("you can register max 64 timers !!!\n");
	}

	uwsgi_unlock(uwsgi.timer_table_lock);

}
