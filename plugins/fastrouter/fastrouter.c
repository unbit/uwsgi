/*

   uWSGI fastrouter

   requires:

   - async
   - caching
   - pcre (optional)

*/

#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;

#include "fr.h"

struct uwsgi_fastrouter ufr;


struct uwsgi_option fastrouter_options[] = {
	{"fastrouter", required_argument, 0, "run the fastrouter on the specified port", uwsgi_opt_corerouter, &ufr, 0},
	{"fastrouter-processes", required_argument, 0, "prefork the specified number of fastrouter processes", uwsgi_opt_set_int, &ufr.cr.processes, 0},
	{"fastrouter-workers", required_argument, 0, "prefork the specified number of fastrouter processes", uwsgi_opt_set_int, &ufr.cr.processes, 0},
	{"fastrouter-zerg", required_argument, 0, "attach the fastrouter to a zerg server", uwsgi_opt_corerouter_zerg, &ufr, 0 },
	{"fastrouter-use-cache", no_argument, 0, "use uWSGI cache as hostname->server mapper for the fastrouter", uwsgi_opt_true, &ufr.cr.use_cache, 0},

	{"fastrouter-use-pattern", required_argument, 0, "use a pattern for fastrouter hostname->server mapping", uwsgi_opt_corerouter_use_pattern, &ufr, 0},
	{"fastrouter-use-base", required_argument, 0, "use a base dir for fastrouter hostname->server mapping", uwsgi_opt_corerouter_use_base, &ufr, 0},

	{"fastrouter-fallback", required_argument, 0, "fallback to the specified node in case of error", uwsgi_opt_add_string_list, &ufr.cr.fallback, 0},
	
	{"fastrouter-use-cluster", no_argument, 0, "load balance to nodes subscribed to the cluster", uwsgi_opt_true, &ufr.cr.use_cluster, 0},

	{"fastrouter-use-code-string", required_argument, 0, "use code string as hostname->server mapper for the fastrouter", uwsgi_opt_corerouter_cs, &ufr, 0},
	{"fastrouter-use-socket", optional_argument, 0, "forward request to the specified uwsgi socket", uwsgi_opt_corerouter_use_socket, &ufr, 0},
	{"fastrouter-to", required_argument, 0, "forward requests to the specified uwsgi server (you can specify it multiple times for load balancing)", uwsgi_opt_add_string_list, &ufr.cr.static_nodes, 0},
	{"fastrouter-gracetime", required_argument, 0, "retry connections to dead static nodes after the specified amount of seconds", uwsgi_opt_set_int, &ufr.cr.static_node_gracetime, 0},
	{"fastrouter-events", required_argument, 0, "set the maximum number of concurrent events", uwsgi_opt_set_int, &ufr.cr.nevents, 0},
	{"fastrouter-quiet", required_argument, 0, "do not report failed connections to instances", uwsgi_opt_true, &ufr.cr.quiet, 0},
	{"fastrouter-cheap", no_argument, 0, "run the fastrouter in cheap mode", uwsgi_opt_true, &ufr.cr.cheap, 0},
	{"fastrouter-subscription-server", required_argument, 0, "run the fastrouter subscription server on the spcified address", uwsgi_opt_corerouter_ss, &ufr, 0},
	{"fastrouter-subscription-slot", required_argument, 0, "*** deprecated ***", uwsgi_opt_deprecated, (void *) "useless thanks to the new implementation", 0},

	{"fastrouter-timeout", required_argument, 0, "set fastrouter timeout", uwsgi_opt_set_int, &ufr.cr.socket_timeout, 0},
	{"fastrouter-post-buffering", required_argument, 0, "enable fastrouter post buffering", uwsgi_opt_set_64bit, &ufr.cr.post_buffering, 0},
	{"fastrouter-post-buffering-dir", required_argument, 0, "put fastrouter buffered files to the specified directory", uwsgi_opt_set_str, &ufr.cr.pb_base_dir, 0},

	{"fastrouter-stats", required_argument, 0, "run the fastrouter stats server", uwsgi_opt_set_str, &ufr.cr.stats_server, 0},
	{"fastrouter-stats-server", required_argument, 0, "run the fastrouter stats server", uwsgi_opt_set_str, &ufr.cr.stats_server, 0},
	{"fastrouter-ss", required_argument, 0, "run the fastrouter stats server", uwsgi_opt_set_str, &ufr.cr.stats_server, 0},
	{"fastrouter-harakiri", required_argument, 0, "enable fastrouter harakiri", uwsgi_opt_set_int, &ufr.cr.harakiri, 0 },
	{0, 0, 0, 0, 0, 0, 0},
};

void fastrouter_alloc_session(struct uwsgi_corerouter *ucr, struct uwsgi_gateway_socket *ugs, struct corerouter_session *cs, struct sockaddr *sa, socklen_t s_len) {
}

int fastrouter_init() {

	ufr.cr.session_size = sizeof(struct fastrouter_session);
	ufr.cr.switch_events = uwsgi_fastrouter_switch_events;
	ufr.cr.alloc_session = fastrouter_alloc_session;
	uwsgi_corerouter_init((struct uwsgi_corerouter *) &ufr);	

	return 0;
}

void fastrouter_setup() {
	ufr.cr.name = uwsgi_str("uWSGI fastrouter");
	ufr.cr.short_name = uwsgi_str("fastrouter");
}


struct uwsgi_plugin fastrouter_plugin = {

	.name = "fastrouter",
	.options = fastrouter_options,
	.init = fastrouter_init,
	.on_load = fastrouter_setup
};
