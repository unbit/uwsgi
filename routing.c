#include "uwsgi.h"

void routing_setup(struct uwsgi_server *uwsgi) {

	int i;
	struct uwsgi_route *ur;
	int max_ovec = 0 ;

	for(i=0;i<uwsgi->routes;i++) {
		uwsgi_log("%d = %p\n", i, uwsgi->shared->routes[i].pattern);
		ur = &uwsgi->shared->routes[i];
		if (ur->args > max_ovec) {
			max_ovec = ur->args;
		}
	}

	uwsgi->async_ovector = malloc( sizeof(int *) * uwsgi->async);
        if (!uwsgi->async_ovector) {
                uwsgi_error("malloc()");
                exit(1);
        }

	uwsgi_log("max_ovec = %d\n", max_ovec);
	for(i=0;i<uwsgi->async;i++) {
                uwsgi->async_ovector[i] = malloc(sizeof(int) * ((max_ovec+1)*3));
                if (!uwsgi->async_ovector[i]) {
                        uwsgi_error("malloc()");
                        exit(1);
                }

	}

}

int check_route(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {

	int ret,i ;
	struct uwsgi_route *ur;

	for(i=0;i<uwsgi->routes;i++) {

		uwsgi_log("checking route %d\n", i);
		ur = &uwsgi->shared->routes[i];
		ret = pcre_exec(ur->pattern, ur->pattern_extra, wsgi_req->path_info, wsgi_req->path_info_len, 0, 0, wsgi_req->ovector, (ur->args+1)*3 );
	
		if (ret >= 0) {
			uwsgi_log("found route %d for PATH_INFO=%.*s\n", i, wsgi_req->path_info_len, wsgi_req->path_info);
			return i;
		}

		/* TODO check for errors if < 0 && != NO_MATCH */
	}

	return -1;
}
