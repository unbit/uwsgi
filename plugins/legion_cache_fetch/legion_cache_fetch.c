#include <uwsgi.h>


extern struct uwsgi_server uwsgi;


static int legion_action_cache_fetch_from_legion(struct uwsgi_legion *ul, char *arg) {
	uwsgi_log("[legion-cache-fetch] getting cache '%s' dump from legion '%s' nodes\n", arg, ul->legion);

	struct uwsgi_cache *uc = uwsgi_cache_by_name(arg);
	if (!uc) {
		uwsgi_log("[legion-cache-fetch] cannot sync, cache '%s' not found\n", arg);
		return 1;
	}

	struct uwsgi_string_list *dump_from_nodes = NULL;

	uwsgi_rlock(ul->lock);
	struct uwsgi_legion_node *legion_nodes = ul->nodes_head;
	while (legion_nodes) {
		char *dump_socket = NULL;
		if (uwsgi_kvlist_parse(legion_nodes->scroll, legion_nodes->scroll_len, ',', '=',
			"dump-socket", &dump_socket,
			NULL)) {
			uwsgi_log("[legion-cache-fetch] cannot sync from %.*s, cache socket address not found in legion scroll: %.*s\n",
				legion_nodes->name_len, legion_nodes->name, legion_nodes->scroll_len, legion_nodes->scroll);
		}
		else {
			if (dump_socket) {
				uwsgi_string_new_list(&dump_from_nodes, dump_socket);
			}
			else {
				uwsgi_log("[legion-cache-fetch] cannot sync from %.*s, cache socket address not found in legion scroll: %.*s\n",
				    legion_nodes->name_len, legion_nodes->name, legion_nodes->scroll_len, legion_nodes->scroll);
			}
		}
		legion_nodes = legion_nodes->next;
	}

	// update uc->sync_nodes list
	struct uwsgi_string_list *usl = uc->sync_nodes;
	struct uwsgi_string_list *next;
	while (usl) {
		next = usl->next;
		free(usl->value);
		free(usl);
		usl = next;
	}
	uwsgi_rwunlock(ul->lock);

	uwsgi_rlock(uc->lock);
	uc->sync_nodes = dump_from_nodes;
	uwsgi_rwunlock(uc->lock);

	// call sync
	uwsgi_cache_sync_from_nodes(uc);

	return 0;
}


static void legion_cache_register() {
	uwsgi_legion_action_register("legion-cache-fetch", legion_action_cache_fetch_from_legion);
}


struct uwsgi_plugin legion_cache_fetch_plugin = {
	.name = "legion_cache_fetch",
	.on_load = legion_cache_register,
};

