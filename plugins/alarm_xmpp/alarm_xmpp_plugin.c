#include "../../uwsgi.h"

void uwsgi_alarm_xmpp_loop(struct uwsgi_thread *);

static void uwsgi_alarm_xmpp_init(struct uwsgi_alarm_instance *uai) {

	struct uwsgi_thread *ut = uwsgi_thread_new_with_data(uwsgi_alarm_xmpp_loop, uai->arg);
	if (!ut) return;
	uai->data_ptr = ut;
}

// pipe the message into the thread;
static void uwsgi_alarm_xmpp_func(struct uwsgi_alarm_instance *uai, char *msg, size_t len) {
	struct uwsgi_thread *ut = (struct uwsgi_thread *) uai->data_ptr;
	ut->rlen = write(ut->pipe[0], msg, len);
}

static void uwsgi_alarm_xmpp_load(void) {
	uwsgi_register_alarm("xmpp", uwsgi_alarm_xmpp_init, uwsgi_alarm_xmpp_func);
}

struct uwsgi_plugin alarm_xmpp_plugin = {
	.name = "alarm_xmpp",
	.on_load = uwsgi_alarm_xmpp_load,
};
