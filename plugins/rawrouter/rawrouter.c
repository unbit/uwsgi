/*

   uWSGI rawrouter

   requires:

   - async
   - caching
   - pcre (optional)

*/

#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;

#include "rr.h"

struct uwsgi_rawrouter urr;


struct uwsgi_option rawrouter_options[] = {
	{"rawrouter", required_argument, 0, "run the rawrouter on the specified port", uwsgi_opt_corerouter, &urr, 0},
	{"rawrouter-processes", required_argument, 0, "prefork the specified number of rawrouter processes", uwsgi_opt_set_int, &urr.cr.processes, 0},
	{"rawrouter-workers", required_argument, 0, "prefork the specified number of rawrouter processes", uwsgi_opt_set_int, &urr.cr.processes, 0},
	{"rawrouter-zerg", required_argument, 0, "attach the rawrouter to a zerg server", uwsgi_opt_corerouter_zerg, &urr, 0 },
	{"rawrouter-use-cache", no_argument, 0, "use uWSGI cache as address->server mapper for the rawrouter", uwsgi_opt_true, &urr.cr.use_cache, 0},

	{"rawrouter-use-pattern", required_argument, 0, "use a pattern for rawrouter address->server mapping", uwsgi_opt_corerouter_use_pattern, &urr, 0},
	{"rawrouter-use-base", required_argument, 0, "use a base dir for rawrouter address->server mapping", uwsgi_opt_corerouter_use_base, &urr, 0},

	{"rawrouter-fallback", required_argument, 0, "fallback to the specified node in case of error", uwsgi_opt_add_string_list, &urr.cr.fallback, 0},
	
	{"rawrouter-use-cluster", no_argument, 0, "load balance to nodes subscribed to the cluster", uwsgi_opt_true, &urr.cr.use_cluster, 0},

	{"rawrouter-use-code-string", required_argument, 0, "use code string as address->server mapper for the rawrouter", uwsgi_opt_corerouter_cs, &urr, 0},
	{"rawrouter-use-socket", optional_argument, 0, "forward request to the specified uwsgi socket", uwsgi_opt_corerouter_use_socket, &urr, 0},
	{"rawrouter-to", required_argument, 0, "forward requests to the specified uwsgi server (you can specify it multiple times for load balancing)", uwsgi_opt_add_string_list, &urr.cr.static_nodes, 0},
	{"rawrouter-gracetime", required_argument, 0, "retry connections to dead static nodes after the specified amount of seconds", uwsgi_opt_set_int, &urr.cr.static_node_gracetime, 0},
	{"rawrouter-events", required_argument, 0, "set the maximum number of concurrent events", uwsgi_opt_set_int, &urr.cr.nevents, 0},
	{"rawrouter-quiet", required_argument, 0, "do not report failed connections to instances", uwsgi_opt_true, &urr.cr.quiet, 0},
	{"rawrouter-cheap", no_argument, 0, "run the rawrouter in cheap mode", uwsgi_opt_true, &urr.cr.cheap, 0},
	{"rawrouter-subscription-server", required_argument, 0, "run the rawrouter subscription server on the spcified address", uwsgi_opt_corerouter_ss, &urr, 0},

	{"rawrouter-timeout", required_argument, 0, "set rawrouter timeout", uwsgi_opt_set_int, &urr.cr.socket_timeout, 0},

	{"rawrouter-stats", required_argument, 0, "run the rawrouter stats server", uwsgi_opt_set_str, &urr.cr.stats_server, 0},
	{"rawrouter-stats-server", required_argument, 0, "run the rawrouter stats server", uwsgi_opt_set_str, &urr.cr.stats_server, 0},
	{"rawrouter-ss", required_argument, 0, "run the rawrouter stats server", uwsgi_opt_set_str, &urr.cr.stats_server, 0},

	{"rawrouter-harakiri", required_argument, 0, "enable rawrouter harakiri", uwsgi_opt_set_int, &urr.cr.harakiri, 0 },
	{0, 0, 0, 0, 0, 0, 0},
};

void rawrouter_alloc_session(struct uwsgi_corerouter *ucr, struct uwsgi_gateway_socket *ugs, struct corerouter_session *cs, struct sockaddr *sa, socklen_t s_len) {
}

int rawrouter_init() {

	urr.cr.session_size = sizeof(struct rawrouter_session);
	urr.cr.switch_events = uwsgi_rawrouter_switch_events;
	urr.cr.alloc_session = rawrouter_alloc_session;
	uwsgi_corerouter_init((struct uwsgi_corerouter *) &urr);	

	return 0;
}

void rawrouter_setup() {
	urr.cr.name = uwsgi_str("uWSGI rawrouter");
	urr.cr.short_name = uwsgi_str("rawrouter");
}


struct uwsgi_plugin rawrouter_plugin = {

	.name = "rawrouter",
	.options = rawrouter_options,
	.init = rawrouter_init,
	.on_load = rawrouter_setup
};
