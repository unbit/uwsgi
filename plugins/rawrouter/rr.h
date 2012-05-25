#include "../corerouter/cr.h"


struct uwsgi_rawrouter {

	struct uwsgi_corerouter cr;

};

struct rawrouter_session {

	struct corerouter_session crs;
};

void uwsgi_rawrouter_switch_events(struct uwsgi_corerouter *, struct corerouter_session *, int interesting_fd);

