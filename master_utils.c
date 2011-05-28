#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

void master_check_cluster_nodes() {

	int i;

	for (i = 0; i < MAX_CLUSTER_NODES; i++) {
                                struct uwsgi_cluster_node *ucn = &uwsgi.shared->nodes[i];

                                if (ucn->name[0] != 0 && ucn->type == CLUSTER_NODE_STATIC && ucn->status == UWSGI_NODE_FAILED) {
                                        // should i retry ?
                                        if (uwsgi.master_cycles % ucn->errors == 0) {
                                                if (!uwsgi_ping_node(i, uwsgi.wsgi_req)) {
                                                        ucn->status = UWSGI_NODE_OK;
                                                        uwsgi_log( "re-enabled cluster node %d/%s\n", i, ucn->name);
                                                }
                                                else {
                                                        ucn->errors++;
                                                }
                                        }
                                }
                                else if (ucn->name[0] != 0 && ucn->type == CLUSTER_NODE_DYNAMIC) {
                                        // if the last_seen attr is higher than 30 secs ago, mark the node as dead
                                        if ( (uwsgi.current_time - ucn->last_seen) > 30) {
                                                uwsgi_log_verbose("no presence announce in the last 30 seconds by node %s, i assume it is dead.\n", ucn->name);
                                                ucn->name[0] = 0 ;
                                        }
                                }
                        }
}


int uwsgi_respawn_worker(int wid) {

	int respawns = uwsgi.workers[wid].respawn_count;

	pid_t pid = fork();

                if (pid == 0) {
			uwsgi.mywid = wid;
                        // fix the communication pipe
                        close(uwsgi.shared->worker_signal_pipe[0]);
                        uwsgi.mypid = getpid();
                        uwsgi.workers[uwsgi.mywid].pid = uwsgi.mypid;
			uwsgi.workers[uwsgi.mywid].id = uwsgi.mywid;
                        uwsgi.workers[uwsgi.mywid].harakiri = 0;
                        uwsgi.workers[uwsgi.mywid].requests = 0;
                        uwsgi.workers[uwsgi.mywid].failed_requests = 0;
                        uwsgi.workers[uwsgi.mywid].respawn_count++;
                        uwsgi.workers[uwsgi.mywid].last_spawn = uwsgi.current_time;
                        uwsgi.workers[uwsgi.mywid].manage_next_request = 1;
			return 1;
                }
                else if (pid < 1) {
                        uwsgi_error("fork()");
                }
                else {
			if (respawns > 0) {
                        	uwsgi_log( "Respawned uWSGI worker %d (new pid: %d)\n", uwsgi.mywid, (int) pid);
			}
			else {
				uwsgi_log("spawned uWSGI worker %d (pid: %d, cores: %d)\n", wid, pid, uwsgi.cores);
			}
                }

	return 0;
}
