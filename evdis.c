#ifdef UWSGI_EVDIS

#include "uwsgi.h"

void evdis_loop(struct uwsgi_server *uwsgi) {

	// populate event list

	int kfd = kqueue();
	if (kfd < 0) {
		uwsgi_error("kqueue()");
		exit(1);
	}
	
	
}



#else
#warning "*** Event Dispatcher support is disabled ***"
#endif
