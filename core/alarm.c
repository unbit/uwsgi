#include "../uwsgi.h"

extern struct uwsgi_server uwsgi;

// generate a uwsgi signal on alarm
void uwsgi_alarm_init_signal(struct uwsgi_alarm_instance *uai) {
	uai->data8 = atoi(uai->arg);
}

void uwsgi_alarm_func_signal(struct uwsgi_alarm_instance *uai, char *msg, size_t len) {
	uwsgi_route_signal(uai->data8);
}

// run a command on alarm
void uwsgi_alarm_init_cmd(struct uwsgi_alarm_instance *uai) {
	uai->data_ptr = uai->arg;
}

void uwsgi_alarm_func_cmd(struct uwsgi_alarm_instance *uai, char *msg, size_t len) {
	int pipe[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pipe)) {
		return;
	}
	uwsgi_socket_nb(pipe[0]);
	uwsgi_socket_nb(pipe[1]);
	if (write(pipe[1], msg, len) != (ssize_t) len) {
		close(pipe[0]);
		close(pipe[1]);
		return;
	}
	uwsgi_run_command(uai->data_ptr, pipe, -1);
	close(pipe[0]);
	close(pipe[1]);
}

// pass the log line to a mule

void uwsgi_alarm_init_mule(struct uwsgi_alarm_instance *uai) {
	uai->data32 = atoi(uai->arg);
	if (uai->data32 > (uint32_t) uwsgi.mules_cnt) {
		uwsgi_log_alarm("] invalid mule_id (%d mules available), fallback to 0\n", uwsgi.mules_cnt);
		uai->data32 = 0;
	}
}

void uwsgi_alarm_func_mule(struct uwsgi_alarm_instance *uai, char *msg, size_t len) {
	// skip if mules are not available
	if (uwsgi.mules_cnt == 0)
		return;
	int fd = uwsgi.shared->mule_queue_pipe[0];
	if (uai->data32 > 0) {
		int mule_id = uai->data32 - 1;
		fd = uwsgi.mules[mule_id].queue_pipe[0];
	}
	mule_send_msg(fd, msg, len);
}


// register a new alarm
void uwsgi_register_alarm(char *name, void (*init) (struct uwsgi_alarm_instance *), void (*func) (struct uwsgi_alarm_instance *, char *, size_t)) {
	struct uwsgi_alarm *old_ua = NULL, *ua = uwsgi.alarms;
	while (ua) {
		// skip already initialized alarms
		if (!strcmp(ua->name, name)) {
			return;
		}
		old_ua = ua;
		ua = ua->next;
	}

	ua = uwsgi_calloc(sizeof(struct uwsgi_alarm));
	ua->name = name;
	ua->init = init;
	ua->func = func;

	if (old_ua) {
		old_ua->next = ua;
	}
	else {
		uwsgi.alarms = ua;
	}
}

// register embedded alarms
void uwsgi_register_embedded_alarms() {
	uwsgi_register_alarm("signal", uwsgi_alarm_init_signal, uwsgi_alarm_func_signal);
	uwsgi_register_alarm("cmd", uwsgi_alarm_init_cmd, uwsgi_alarm_func_cmd);
	uwsgi_register_alarm("mule", uwsgi_alarm_init_mule, uwsgi_alarm_func_mule);
}

static int uwsgi_alarm_add(char *name, char *plugin, char *arg) {
	struct uwsgi_alarm *ua = uwsgi.alarms;
	while (ua) {
		if (!strcmp(ua->name, plugin)) {
			break;
		}
		ua = ua->next;
	}

	if (!ua)
		return -1;

	struct uwsgi_alarm_instance *old_uai = NULL, *uai = uwsgi.alarm_instances;
	while (uai) {
		old_uai = uai;
		uai = uai->next;
	}

	uai = uwsgi_calloc(sizeof(struct uwsgi_alarm_instance));
	uai->name = name;
	uai->alarm = ua;
	uai->arg = arg;
	uai->last_msg = uwsgi_malloc(uwsgi.log_master_bufsize);

	if (old_uai) {
		old_uai->next = uai;
	}
	else {
		uwsgi.alarm_instances = uai;
	}

	ua->init(uai);
	return 0;
}

// get an alarm instance by its name
static struct uwsgi_alarm_instance *uwsgi_alarm_get_instance(char *name) {
	struct uwsgi_alarm_instance *uai = uwsgi.alarm_instances;
	while (uai) {
		if (!strcmp(name, uai->name)) {
			return uai;
		}
		uai = uai->next;
	}
	return NULL;
}


static int uwsgi_alarm_log_add(char *alarms, char *regexp, int negate) {

	struct uwsgi_alarm_log *old_ual = NULL, *ual = uwsgi.alarm_logs;
	while (ual) {
		old_ual = ual;
		ual = ual->next;
	}

	ual = uwsgi_calloc(sizeof(struct uwsgi_alarm_log));
	if (uwsgi_regexp_build(regexp, &ual->pattern, &ual->pattern_extra)) {
		return -1;
	}
	ual->negate = negate;

	if (old_ual) {
		old_ual->next = ual;
	}
	else {
		uwsgi.alarm_logs = ual;
	}

	// map instances to the log
	char *list = uwsgi_str(alarms);
	char *p = strtok(list, ",");
	while (p) {
		struct uwsgi_alarm_instance *uai = uwsgi_alarm_get_instance(p);
		if (!uai)
			return -1;
		struct uwsgi_alarm_ll *old_uall = NULL, *uall = ual->alarms;
		while (uall) {
			old_uall = uall;
			uall = uall->next;
		}

		uall = uwsgi_calloc(sizeof(struct uwsgi_alarm_ll));
		uall->alarm = uai;
		if (old_uall) {
			old_uall->next = uall;
		}
		else {
			ual->alarms = uall;
		}
		p = strtok(NULL, ",");
	}
	return 0;
}

// initialize alarms, instances and log regexps
void uwsgi_alarms_init() {

	// first of all, create instance of alarms
	struct uwsgi_string_list *usl = uwsgi.alarm_list;
	while (usl) {
		char *line = uwsgi_str(usl->value);
		char *space = strchr(line, ' ');
		if (!space) {
			uwsgi_log("invalid alarm syntax: %s\n", usl->value);
			exit(1);
		}
		*space = 0;
		char *plugin = space + 1;
		char *colon = strchr(plugin, ':');
		if (!colon) {
			uwsgi_log("invalid alarm syntax: %s\n", usl->value);
			exit(1);
		}
		*colon = 0;
		char *arg = colon + 1;
		// here the alarm is mapped to a name and initialized
		if (uwsgi_alarm_add(line, plugin, arg)) {
			uwsgi_log("invalid alarm: %s\n", usl->value);
			exit(1);
		}
		usl = usl->next;
	}

	// then map log-alarm
	usl = uwsgi.alarm_logs_list;
	while (usl) {
		char *line = uwsgi_str(usl->value);
		char *space = strchr(line, ' ');
		if (!space) {
			uwsgi_log("invalid log-alarm syntax: %s\n", usl->value);
			exit(1);
		}
		*space = 0;
		char *regexp = space + 1;
		// here the log-alarm is created
		if (uwsgi_alarm_log_add(line, regexp, usl->custom)) {
			uwsgi_log("invalid log-alarm: %s\n", usl->value);
			exit(1);
		}

		usl = usl->next;
	}
}

// check if a log should raise an alarm
void uwsgi_alarm_log_check(char *msg, size_t len) {
	if (!uwsgi_strncmp(msg, len, "[uwsgi-alarm", 12))
		return;
	struct uwsgi_alarm_log *ual = uwsgi.alarm_logs;
	while (ual) {
		if (uwsgi_regexp_match(ual->pattern, ual->pattern_extra, msg, len) >= 0) {
			if (!ual->negate) {
				uwsgi_alarm_log_run(ual, msg, len);
			}
			else {
				break;
			}
		}
		ual = ual->next;
	}
}

// call the alarm func
void uwsgi_alarm_run(struct uwsgi_alarm_instance *uai, char *msg, size_t len) {
	time_t now = uwsgi_now();
	// avoid alarm storming/loop if last message is the same
	if (!uwsgi_strncmp(msg, len, uai->last_msg, uai->last_msg_size)) {
		if (now - uai->last_run < uwsgi.alarm_freq)
			return;
	}
	uai->alarm->func(uai, msg, len);
	uai->last_run = uwsgi_now();
	memcpy(uai->last_msg, msg, len);
	uai->last_msg_size = len;
}

// call the alarms mapped to a log line
void uwsgi_alarm_log_run(struct uwsgi_alarm_log *ual, char *msg, size_t len) {
	struct uwsgi_alarm_ll *uall = ual->alarms;
	while (uall) {
		uwsgi_alarm_run(uall->alarm, msg, len);
		uall = uall->next;
	}
}
