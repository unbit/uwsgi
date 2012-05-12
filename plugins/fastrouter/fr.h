#include "../corerouter/cr.h"

#define FASTROUTER_STATUS_RECV_VARS 10
#define FASTROUTER_STATUS_BUFFERING 11

struct uwsgi_fastrouter {

	struct uwsgi_corerouter cr;

};

struct fastrouter_session {

	struct corerouter_session crs;
        char buffer[UMAX16];
};

void uwsgi_fastrouter_switch_events(struct uwsgi_corerouter *, struct corerouter_session *, int interesting_fd);

