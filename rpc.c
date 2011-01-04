#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

int uwsgi_register_rpc(char *name, uint8_t modifier1, uint8_t args, void *func) {

	struct uwsgi_rpc *urpc;
	int ret = -1;

	uwsgi_lock(uwsgi.rpc_table_lock);

	if (uwsgi.shared->rpc_count < MAX_RPC) {
		urpc = &uwsgi.shared->rpc_table[uwsgi.shared->rpc_count];
	
		memcpy(urpc->name, name, strlen(name));
		urpc->modifier1 = modifier1;
		urpc->args = args;
		urpc->func = func;

		uwsgi.shared->rpc_count++;

		ret = 0;
		uwsgi_log("registered RPC function %s\n", name);
	}

	uwsgi_unlock(uwsgi.rpc_table_lock);

	return ret;
}

uint16_t uwsgi_rpc(char *name, uint8_t argc, char *argv[], char *output) {

	struct uwsgi_rpc *urpc = NULL;
	int i;
	uint16_t ret = 0;

	for(i=0;i<uwsgi.shared->rpc_count;i++) {
		if (uwsgi.shared->rpc_table[i].name[0] != 0) {
			if (!strcmp(uwsgi.shared->rpc_table[i].name, name)) {
				urpc = &uwsgi.shared->rpc_table[i];
				break;
			}
		}
	}

	if (urpc) {
		if (uwsgi.p[urpc->modifier1]->rpc) {
			ret = uwsgi.p[urpc->modifier1]->rpc(urpc->func, argc, argv, output);
		}
	}

	return ret;
}
