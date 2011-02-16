#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

int uwsgi_signal_handler(uint8_t sig) {

	struct uwsgi_signal_entry *use = NULL; 

	use = &uwsgi.shared->signal_table[sig];

	/*
	if (!use->kind) {
		return -1;
	}
	*/

	if (!uwsgi.p[use->modifier1]->signal_handler) {
		return -1;
	}	
	
	return uwsgi.p[use->modifier1]->signal_handler(sig, use->handler, use->payload, use->payload_size);
}

void uwsgi_register_signal(uint8_t sig, char *receiver, void *handler, uint8_t modifier1, char *payload, uint8_t payload_size) {

	struct uwsgi_signal_entry *use = NULL;

	uwsgi_lock(uwsgi.signal_table_lock);

	use = &uwsgi.shared->signal_table[sig];

	strcpy(use->receiver, receiver);
	use->handler = handler;
	use->modifier1 = modifier1;
	
	memcpy(use->payload, payload, payload_size);

	use->payload_size = payload_size;

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
	
		//uwsgi_register_signal(sig, kind, handler, modifier1, filename, strlen(filename));

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
		//uwsgi_register_signal(sig, kind, handler, modifier1, ushared->timers[ushared->timers_cnt].svalue, strlen(ushared->timers[ushared->timers_cnt].svalue));
		ushared->timers_cnt++;
	}
	else {
		uwsgi_log("you can register max 64 timers !!!\n");
	}

	uwsgi_unlock(uwsgi.timer_table_lock);

}


void uwsgi_route_signal(uint8_t sig) {

	struct uwsgi_signal_entry *use = &ushared->signal_table[sig];
	// send to all workers
	if (!strcmp(use->receiver, "workers")) {
		if (write(ushared->worker_signal_pipe[0], &sig, 1) != 1) {
			uwsgi_error("write()");
			uwsgi_log("could not deliver signal %d to workers pool\n", sig);
		}
	}
	// send to first available worker
	else if (!strcmp(use->receiver, "worker")) {
	}
	// loop back to master
	else if (!strcmp(use->receiver, "master")) {
	}
	// route to subscribed
	else if (!strcmp(use->receiver, "subscribed")) {
	}
	else {
		// unregistered signal, sending it to all the workers
		uwsgi_log("^^^ ROUTING UNREGISTERED SIGNAL ^^^\n");
		if (write(ushared->worker_signal_pipe[0], &sig, 1) != 1) {
                        uwsgi_error("write()");
                        uwsgi_log("could not deliver signal %d to workers pool\n", sig);
                }

	}
}
