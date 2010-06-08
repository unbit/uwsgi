#ifdef UWSGI_EVDIS

#include "uwsgi.h"

void evdis_loop(struct uwsgi_server *uwsgi) {

	// populate event list
	
}



#else
#warning "*** Event Dispatcher support is disabled ***"
#endif
