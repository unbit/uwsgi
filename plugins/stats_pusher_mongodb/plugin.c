#include <uwsgi.h>

void stats_pusher_mongodb(struct uwsgi_stats_pusher_instance *, time_t, char *, size_t);

static void stats_pusher_mongodb_init(void) {
        uwsgi_register_stats_pusher("mongodb", stats_pusher_mongodb);
}

struct uwsgi_plugin stats_pusher_mongodb_plugin = {

        .name = "stats_pusher_mongodb",
        .on_load = stats_pusher_mongodb_init,
};

