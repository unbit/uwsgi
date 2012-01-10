#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

struct uwsgi_gateway *register_fat_gateway(char *name, void (*loop)(int)) {

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

        ug = &uwsgi.gateways[uwsgi.gateways_cnt];
        ug->pid = 0;
        ug->name = name;
        ug->loop = loop;
        ug->num = num;

        uwsgi.gateways_cnt++;

        return ug;
}

struct uwsgi_gateway *register_gateway(char *name, void (*loop)(int)) {

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

	if (uwsgi.master_process)
		uwsgi.shared->gateways_harakiri[uwsgi.gateways_cnt] = 0;

	gw_pid = uwsgi_fork(name);
	if (gw_pid < 0) {
		uwsgi_error("fork()");
		return NULL;
	}

	if (!uwsgi.master_process) {
		if (gw_pid > 0) {
#ifdef __linux__
                if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0,0,0)) {
                        uwsgi_error("prctl()");
                }
#endif

		if (!uwsgi.sockets) {
			// wait for child end
			//waitpid(-1, &i, 0);
		}
			loop(uwsgi.gateways_cnt);
			// never here !!! (i hope)
			exit(1);	
		}

		ug = &uwsgi.gateways[uwsgi.gateways_cnt];
		ug->pid = orig_pid;
	}
	else {
		if (gw_pid == 0) {
			if (uwsgi.master_as_root) uwsgi_as_root();
			loop(uwsgi.gateways_cnt);
			// never here !!! (i hope)
			exit(1);	
		}

		ug = &uwsgi.gateways[uwsgi.gateways_cnt];
		ug->pid = gw_pid;
	}


	ug->name = name;
	ug->loop = loop;
	ug->num = num;

	uwsgi_log( "spawned %s %d (pid: %d)\n", ug->name, ug->num, (int) ug->pid);

	uwsgi.gateways_cnt++;

	return ug;
		
}

void gateway_respawn(int id) {

	pid_t gw_pid;
	struct uwsgi_gateway *ug = &uwsgi.gateways[id];

	if (uwsgi.master_process)
		uwsgi.shared->gateways_harakiri[id] = 0;
	
	gw_pid = uwsgi_fork(ug->name);
	if (gw_pid < 0) {
                uwsgi_error("fork()");
		return;
	}

	if (gw_pid == 0) {
		if (uwsgi.master_as_root) uwsgi_as_root();
#ifdef __linux__
                if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0,0,0)) {
                        uwsgi_error("prctl()");
                }
#endif
		ug->loop(id);
		// never here !!! (i hope)
		exit(1);	
	}

	ug->pid = gw_pid;
	ug->respawns++;
	if (ug->respawns == 1) {
		uwsgi_log( "spawned %s %d (pid: %d)\n", ug->name, ug->num, (int) gw_pid);
	}
	else {
		uwsgi_log( "respawned %s %d (pid: %d)\n", ug->name, ug->num, (int) gw_pid);
	}
	
}
