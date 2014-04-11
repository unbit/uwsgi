#include <uwsgi.h>

void uwsgi_imperial_monitor_mongodb(struct uwsgi_emperor_scanner *);
void uwsgi_imperial_monitor_mongodb_init(struct uwsgi_emperor_scanner *);
void uwsgi_imperial_monitor_mongodb_init2(struct uwsgi_emperor_scanner *);

void emperor_mongodb_init(void) {
	uwsgi_register_imperial_monitor("mongodb", uwsgi_imperial_monitor_mongodb_init, uwsgi_imperial_monitor_mongodb);
	uwsgi_register_imperial_monitor("mongodb2", uwsgi_imperial_monitor_mongodb_init2, uwsgi_imperial_monitor_mongodb);
}

struct uwsgi_plugin emperor_mongodb_plugin = {

	.name = "emperor_mongodb",
	.on_load = emperor_mongodb_init,
};
