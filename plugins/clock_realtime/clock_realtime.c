#include "../../uwsgi.h"

// timespecs have nanoseconds resolution

time_t uwsgi_realtime_seconds() {
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return ts.tv_sec;
}

uint64_t uwsgi_realtime_microseconds() {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
	return ((uint64_t) ts.tv_sec * 1000000) + (ts.tv_nsec/1000);
}


static struct uwsgi_clock uwsgi_realtime_clock = {
	.name = "realtime",
	.seconds = uwsgi_realtime_seconds,
	.microseconds = uwsgi_realtime_microseconds,
};


void uwsgi_realtime_clock_load() {
	uwsgi_register_clock(&uwsgi_realtime_clock);
}

struct uwsgi_plugin clock_realtime_plugin = {
	.name = "clock_realtime",
	.on_load = uwsgi_realtime_clock_load
};
