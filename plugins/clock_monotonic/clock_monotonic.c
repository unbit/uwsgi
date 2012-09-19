#include "../../uwsgi.h"

// timespecs have nanoseconds resolution

time_t uwsgi_monotonic_seconds() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

uint64_t uwsgi_monotonic_microseconds() {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint64_t)ts.tv_sec * 1000000) + (ts.tv_nsec/1000);
}


static struct uwsgi_clock uwsgi_monotonic_clock = {
	.name = "monotonic",
	.seconds = uwsgi_monotonic_seconds,
	.microseconds = uwsgi_monotonic_microseconds,
};


void uwsgi_monotonic_clock_load() {
	uwsgi_register_clock(&uwsgi_monotonic_clock);
}

struct uwsgi_plugin clock_monotonic_plugin = {
	.name = "clock_monotonic",
	.on_load = uwsgi_monotonic_clock_load
};
