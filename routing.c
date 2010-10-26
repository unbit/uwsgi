#ifdef UWSGI_ROUTING
#include "uwsgi.h"

void routing_setup(struct uwsgi_server *uwsgi) {

	int i;
	struct uwsgi_route *ur;
	int max_ovec = 0;

	for(i=0;i<uwsgi->nroutes;i++) {
		uwsgi_log("%d = %p\n", i, uwsgi->routes[i].pattern);
		ur = &uwsgi->routes[i];
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

void check_route(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {

	int ret,i;
	struct uwsgi_route *ur;

	for(i=0;i<uwsgi->nroutes;i++) {

		//uwsgi_log("checking route %d\n", i);
		ur = &uwsgi->routes[i];
		ret = pcre_exec(ur->pattern, ur->pattern_extra, wsgi_req->path_info, wsgi_req->path_info_len, 0, 0, wsgi_req->ovector, (ur->args+1)*3 );

		if (ret >= 0) {
			uwsgi_log("found route %d for PATH_INFO=%.*s\n", i, wsgi_req->path_info_len, wsgi_req->path_info);
			if (ur->action) {
				ur->action(uwsgi, wsgi_req, ur);
			}
			else {
				uwsgi_route_action_wsgi(uwsgi, wsgi_req, ur);
			}
		}

		/* TODO check for errors if < 0 && != NO_MATCH */
	}

	return;
}

void uwsgi_route_action_wsgi(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {

	int i;
	PyObject *route_py_callbase, *route_py_dict = NULL;

	uwsgi_log("managing WSGI route...\n");
	if (ur->callable == NULL) {
		if (ur->callbase) {
			route_py_callbase = PyImport_ImportModule(ur->callbase);
			if (route_py_callbase == NULL) {
				PyErr_Print();
			}
			else {
				uwsgi_log("callbase dict ok for %s\n", ur->call);
				route_py_dict = PyModule_GetDict(route_py_callbase);
			}
		}

		ur->callable = PyDict_GetItemString(route_py_dict, ur->call);
		if (ur->callable == NULL) {
			uwsgi_log("route_py_dict: %p call: %s\n", route_py_dict, ur->call);
			PyErr_Print();
		}
	}

	// TODO put regex captured groups in WSGI env

	PyObject *ra = PyTuple_New(ur->args);
	for (i=1;i<=ur->args;i++) {
		PyTuple_SetItem(ra, i-1, PyString_FromStringAndSize(
					wsgi_req->path_info + wsgi_req->ovector[i*2],
					wsgi_req->ovector[(i*2)+1] - wsgi_req->ovector[i*2]
					));
	}

	PyDict_SetItemString(wsgi_req->async_environ, "x-wsgiorg.uwsgi.route_args", ra);

	if (ur->callable) {
		wsgi_req->async_app = ur->callable;
	}
}

void uwsgi_route_action_uwsgi(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {
	PyObject *route_py_callbase, *route_py_dict = NULL;
	int i;

	uwsgi_log("managing uwsgi route...\n");
	if (ur->callable == NULL) {
		if (ur->callbase) {
			route_py_callbase = PyImport_ImportModule(ur->callbase);
			if (route_py_callbase == NULL) {
				PyErr_Print();
			}
			else {
				uwsgi_log("callbase dict ok for %s\n", ur->call);
				route_py_dict = PyModule_GetDict(route_py_callbase);
			}
		}

		ur->callable = PyDict_GetItemString(route_py_dict, ur->call);
		if (ur->callable == NULL) {
			uwsgi_log("route_py_dict: %p call: %s\n", route_py_dict, ur->call);
			PyErr_Print();
		}

		ur->callable_args = PyTuple_New(ur->args+1);
	}

	if (ur->callable) {
		uwsgi_log("route callable dict ok: %d\n", ur->args);
		wsgi_req->async_app = ur->callable;
		wsgi_req->async_args = ur->callable_args;

		for (i=1;i<=ur->args;i++) {
			uwsgi_log("%d\n", i);
			uwsgi_log("%d / %d\n", wsgi_req->ovector[i*2], wsgi_req->ovector[(i*2)+1]);
			uwsgi_log("%d = %.*s\n", i,wsgi_req->ovector[(i*2)+1] - wsgi_req->ovector[i*2],
					wsgi_req->path_info + wsgi_req->ovector[i*2]);
			PyTuple_SetItem(wsgi_req->async_args, i, PyString_FromStringAndSize(
						wsgi_req->path_info + wsgi_req->ovector[i*2],
						wsgi_req->ovector[(i*2)+1] - wsgi_req->ovector[i*2]
						));
		}
		uwsgi_log("route callable built\n");
	}
}

#endif
