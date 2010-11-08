#include "psgi.h"

extern struct uwsgi_server uwsgi;

#define psgi_xs(func) newXS("uwsgi::" #func, XS_##func, "uwsgi")

XS(XS_reload) {
    dXSARGS;
    items = 0;

    uwsgi_log("SENDING HUP TO %d\n", (int) uwsgi.workers[0].pid);
    if (kill(uwsgi.workers[0].pid, SIGHUP)) {
    	uwsgi_error("kill()");
        XSRETURN_NO;
    }
    XSRETURN_YES;
}


void init_perl_embedded_module() {
	psgi_xs(reload);
}

