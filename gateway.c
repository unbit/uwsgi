#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

struct uwsgi_gateway *register_gateway(char *name, void (*loop)(void)) {

	pid_t gw_pid;
	pid_t orig_pid = getpid();
	struct uwsgi_gateway *ug;
	int num=1,i;

	if (uwsgi.gateways_cnt >= MAX_GATEWAYS) {
		uwsgi_log("you can register max %d gateways\n", MAX_GATEWAYS);
		return NULL;
	}

	for(i=0;i<uwsgi.gateways_cnt;i++) {
		if (!strcmp(name, uwsgi.gateways[i].name)) {
			num++;
		}
	}

	gw_pid = fork();
	if (gw_pid < 0) {
		uwsgi_error("fork()");
		return NULL;
	}

	if (!uwsgi.master_process) {
		if (gw_pid > 0) {
			loop();
			// never here !!! (i hope)
			exit(1);	
		}

		ug = &uwsgi.gateways[uwsgi.gateways_cnt];
		ug->pid = orig_pid;
	}
	else {
		if (gw_pid == 0) {
			loop();
			// never here !!! (i hope)
			exit(1);	
		}

		ug = &uwsgi.gateways[uwsgi.gateways_cnt];
		ug->pid = gw_pid;
	}


	ug->name = name;
	ug->loop = loop;
	ug->num = num;

	uwsgi_log( "spawned uWSGI %s %d (pid: %d)\n", ug->name, ug->num, (int) ug->pid);

	uwsgi.gateways_cnt++;

	return ug;
		
}

void gateway_respawn(int id) {

	pid_t gw_pid;
	struct uwsgi_gateway *ug = &uwsgi.gateways[id];
	
	gw_pid = fork();
	if (gw_pid < 0) {
                uwsgi_error("fork()");
		return;
	}

	if (gw_pid == 0) {
		ug->loop();
		// never here !!! (i hope)
		exit(1);	
	}

	ug->pid = gw_pid;
	uwsgi_log( "respawned uWSGI %s %d (pid: %d)\n", ug->name, ug->num, (int) gw_pid);
	
}
