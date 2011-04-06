/*

 *** uWSGI ***

 Copyright (C) 2009-2011 Unbit S.a.s. <info@unbit.it>

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either version 2
 of the License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

*/


#include "uwsgi.h"

struct uwsgi_server uwsgi;

extern char **environ;

static char *short_options = NULL;

static char *base_short_options = "s:p:t:x:d:l:v:b:mcaCTiMhrR:z:A:Q:Ly:";

extern struct uwsgi_plugin uwsgi_cache_plugin;

UWSGI_DECLARE_EMBEDDED_PLUGINS

static struct option long_base_options[] = {
	{"socket", required_argument, 0, 's'},
	{"shared-socket", required_argument, 0, LONG_ARGS_SHARED_SOCKET},
	{"processes", required_argument, 0, 'p'},
	{"workers", required_argument, 0, 'p'},
	{"harakiri", required_argument, 0, 't'},
	{"harakiri-verbose", no_argument, &uwsgi.harakiri_verbose, 1},
#ifdef UWSGI_XML
	{"xmlconfig", required_argument, 0, 'x'},
	{"xml", required_argument, 0, 'x'},
#endif
	{"daemonize", required_argument, 0, 'd'},
	{"listen", required_argument, 0, 'l'},
	{"max-vars", required_argument, 0, 'v'},
	{"buffer-size", required_argument, 0, 'b'},
	{"memory-report", no_argument, 0, 'm'},
	{"cgi-mode", no_argument, 0, 'c'},
	{"abstract-socket", no_argument, 0, 'a'},
	{"chmod-socket", optional_argument, 0, 'C'},
	{"map-socket", required_argument, 0, LONG_ARGS_MAP_SOCKET},
	{"chmod", optional_argument, 0, 'C'},
#ifdef UWSGI_THREADING
	{"enable-threads", no_argument, 0, 'T'},
#endif
	{"single-interpreter", no_argument, 0, 'i'},
	{"master", no_argument, 0, 'M'},
	{"emperor", required_argument, 0, LONG_ARGS_EMPEROR},
	{"reload-mercy", required_argument, 0, LONG_ARGS_RELOAD_MERCY},
	{"exit-on-reload", no_argument, &uwsgi.exit_on_reload, 1},
	{"help", no_argument, 0, 'h'},
	{"reaper", no_argument, 0, 'r'},
	{"max-requests", required_argument, 0, 'R'},
	{"socket-timeout", required_argument, 0, 'z'},
	{"sharedarea", required_argument, 0, 'A'},
	{"cache", required_argument, 0, LONG_ARGS_CACHE},
	{"cache-blocksize", required_argument, 0, LONG_ARGS_CACHE_BLOCKSIZE},
	{"cache-store", required_argument, 0, LONG_ARGS_CACHE_STORE},
	{"cache-store-sync", required_argument, 0, LONG_ARGS_CACHE_STORE_SYNC},
	{"queue", required_argument, 0, LONG_ARGS_QUEUE},
	{"queue-blocksize", required_argument, 0, LONG_ARGS_QUEUE_BLOCKSIZE},
	{"queue-store", required_argument, 0, LONG_ARGS_QUEUE_STORE},
	{"queue-store-sync", required_argument, 0, LONG_ARGS_QUEUE_STORE_SYNC},
#ifdef UWSGI_SPOOLER
	{"spooler", required_argument, 0, 'Q'},
#endif
	{"disable-logging", no_argument, 0, 'L'},

	{"pidfile", required_argument, 0, LONG_ARGS_PIDFILE},
	{"pidfile2", required_argument, 0, LONG_ARGS_PIDFILE2},
	{"chroot", required_argument, 0, LONG_ARGS_CHROOT},
	{"gid", required_argument, 0, LONG_ARGS_GID},
	{"uid", required_argument, 0, LONG_ARGS_UID},
#ifdef UWSGI_INI
	{"ini", required_argument, 0, LONG_ARGS_INI},
#endif
#ifdef UWSGI_YAML
	{"yaml", required_argument, 0, 'y'},
	{"yml", required_argument, 0, 'y'},
#endif
#ifdef UWSGI_LDAP
	{"ldap", required_argument, 0, LONG_ARGS_LDAP},
	{"ldap-schema", no_argument, 0, LONG_ARGS_LDAP_SCHEMA},
	{"ldap-schema-ldif", no_argument, 0, LONG_ARGS_LDAP_SCHEMA_LDIF},
#endif
	{"no-server", no_argument, &uwsgi.no_server, 1},
	{"no-defer-accept", no_argument, &uwsgi.no_defer_accept, 1},
	{"limit-as", required_argument, 0, LONG_ARGS_LIMIT_AS},
	{"reload-on-as", required_argument, 0, LONG_ARGS_RELOAD_ON_AS},
	{"reload-on-rss", required_argument, 0, LONG_ARGS_RELOAD_ON_RSS},
	{"touch-reload", required_argument, 0, LONG_ARGS_TOUCH_RELOAD},
	{"limit-post", required_argument, 0, LONG_ARGS_LIMIT_POST},
	{"no-orphans", no_argument, &uwsgi.no_orphans, 1},
	{"prio", required_argument, 0, LONG_ARGS_PRIO},
	{"cpu-affinity", required_argument, 0, LONG_ARGS_CPU_AFFINITY},
	{"post-buffering", required_argument, 0, LONG_ARGS_POST_BUFFERING},
	{"post-buffering-bufsize", required_argument, 0, LONG_ARGS_POST_BUFFERING_SIZE},
	{"upload-progress", required_argument, 0, LONG_ARGS_UPLOAD_PROGRESS},
	{"no-default-app", no_argument, &uwsgi.no_default_app, 1},
	{"manage-script-name", no_argument, &uwsgi.manage_script_name, 1},
#ifdef UWSGI_UDP
	{"udp", required_argument, 0, LONG_ARGS_UDP},
#endif
#ifdef UWSGI_MULTICAST
	{"multicast", required_argument, 0, LONG_ARGS_MULTICAST},
	{"cluster", required_argument, 0, LONG_ARGS_CLUSTER},
	{"cluster-nodes", required_argument, 0, LONG_ARGS_CLUSTER_NODES},
#endif
	{"cluster-reload", required_argument, 0, LONG_ARGS_CLUSTER_RELOAD},
	{"cluster-log", required_argument, 0, LONG_ARGS_CLUSTER_LOG},
	{"subscribe-to", required_argument, 0, LONG_ARGS_SUBSCRIBE_TO},
#ifdef UWSGI_SNMP
	{"snmp", optional_argument, 0, LONG_ARGS_SNMP},
	{"snmp-community", required_argument, 0, LONG_ARGS_SNMP_COMMUNITY},
#endif
	{"check-interval", required_argument, 0, LONG_ARGS_CHECK_INTERVAL},

	{"binary-path", required_argument, 0, LONG_ARGS_BINARY_PATH},
#ifdef UWSGI_ASYNC
	{"async", required_argument, 0, LONG_ARGS_ASYNC},
#endif
	{"logto", required_argument, 0, LONG_ARGS_LOGTO},
	{"logfile-chown", no_argument, &uwsgi.logfile_chown, 1},
	{"log-syslog", optional_argument, 0, LONG_ARGS_LOG_SYSLOG},
	{"log-master", no_argument, 0, LONG_ARGS_LOG_MASTER},
	{"logdate", optional_argument, 0, LONG_ARGS_LOG_DATE},
	{"log-zero", no_argument, 0, LONG_ARGS_LOG_ZERO},
	{"log-slow", required_argument, 0, LONG_ARGS_LOG_SLOW},
	{"log-4xx", no_argument, 0, LONG_ARGS_LOG_4xx},
	{"log-5xx", no_argument, 0, LONG_ARGS_LOG_5xx},
	{"log-big", required_argument, 0, LONG_ARGS_LOG_BIG},
	{"log-sendfile", required_argument, 0, LONG_ARGS_LOG_SENDFILE},
	{"log-micros", no_argument, &uwsgi.log_micros, 1},
	{"master-as-root", no_argument, &uwsgi.master_as_root, 1},
	{"chdir", required_argument, 0, LONG_ARGS_CHDIR},
	{"chdir2", required_argument, 0, LONG_ARGS_CHDIR2},
	{"mount", required_argument, 0, LONG_ARGS_MOUNT},
	{"grunt", no_argument, &uwsgi.grunt, 1},
	{"threads", required_argument, 0, LONG_ARGS_THREADS},
	{"vhost", no_argument, &uwsgi.vhost, 1},
	{"vhost-host", no_argument, 0, LONG_ARGS_VHOSTHOST},
#ifdef UWSGI_ROUTING
	{"routing", no_argument, &uwsgi.routing, 1},
#endif
	{"check-static", required_argument, 0, LONG_ARGS_CHECK_STATIC},
	{"static-map", required_argument, 0, LONG_ARGS_STATIC_MAP},
	{"file-serve-mode", required_argument, 0, LONG_ARGS_FILE_SERVE_MODE},
	{"check-cache", no_argument, &uwsgi.check_cache, 1},
	{"close-on-exec", no_argument, &uwsgi.close_on_exec, 1},
	{"mode", required_argument, 0, LONG_ARGS_MODE},
	{"env", required_argument, 0, LONG_ARGS_ENV},
	{"vacuum", no_argument, &uwsgi.vacuum, 1},
#ifdef __linux__
	{"cgroup", required_argument, 0, LONG_ARGS_CGROUP},
	{"cgroup-opt", required_argument, 0, LONG_ARGS_CGROUP_OPT},
	{"namespace", required_argument, 0, LONG_ARGS_LINUX_NS},
	{"ns", required_argument, 0, LONG_ARGS_LINUX_NS},
	{"namespace-net", required_argument, 0, LONG_ARGS_LINUX_NS_NET},
	{"ns-net", required_argument, 0, LONG_ARGS_LINUX_NS_NET},
#endif
	{"loop", required_argument, 0, LONG_ARGS_LOOP},
	{"worker-exec", required_argument, 0, LONG_ARGS_WORKER_EXEC},
	{"attach-daemon", required_argument, 0, LONG_ARGS_ATTACH_DAEMON},
	{"plugins", required_argument, 0, LONG_ARGS_PLUGINS},
	{"allowed-modifiers", required_argument, 0, LONG_ARGS_ALLOWED_MODIFIERS},
	{"remap-modifier", required_argument, 0, LONG_ARGS_REMAP_MODIFIER},
	{"dump-options", no_argument, &uwsgi.dump_options, 1},
	{"show-config", no_argument, &uwsgi.show_config, 1},
	{"print", required_argument, 0, LONG_ARGS_PRINT},
	{"version", no_argument, 0, LONG_ARGS_VERSION},
	{0, 0, 0, 0}
};

int find_worker_id(pid_t pid)
{
	int i;
	for (i = 1; i <= uwsgi.numproc; i++) {
		if (uwsgi.workers[i].pid == pid)
			return i;
	}

	return -1;
}


void warn_pipe()
{
	struct wsgi_request *wsgi_req = current_wsgi_req();

	if (uwsgi.threads < 2 && wsgi_req->uri_len > 0) {
		uwsgi_log("SIGPIPE: writing to a closed pipe/socket/fd (probably the client disconnected) on request %.*s (ip %.*s) !!!\n", wsgi_req->uri_len, wsgi_req->uri, wsgi_req->remote_addr_len, wsgi_req->remote_addr);
	} else {
		uwsgi_log("SIGPIPE: writing to a closed pipe/socket/fd (probably the client disconnected) !!!\n");
	}
}

void gracefully_kill(int signum)
{
	uwsgi_log("Gracefully killing worker %d (pid: %d)...\n", uwsgi.mywid, uwsgi.mypid);
	if (UWSGI_IS_IN_REQUEST) {
		uwsgi.workers[uwsgi.mywid].manage_next_request = 0;
	} else {
		reload_me(0);
	}
}

void reload_me(int signum)
{
	exit(UWSGI_RELOAD_CODE);
}

void end_me(int signum)
{
	exit(UWSGI_END_CODE);
}

void goodbye_cruel_world()
{
	uwsgi.workers[uwsgi.mywid].manage_next_request = 0;
	uwsgi_log("...The work of process %d is done. Seeya!\n", getpid());
	exit(0);
}

void kill_them_all(int signum)
{
	int i;
	uwsgi.to_hell = 1;
	uwsgi_log("SIGINT/SIGQUIT received...killing workers...\n");
	for (i = 1; i <= uwsgi.numproc; i++) {
		if (uwsgi.workers[i].pid > 0)
		kill(uwsgi.workers[i].pid, SIGINT);
	}

	for (i = 0; i < uwsgi.shared->daemons_cnt; i++) {
		if (uwsgi.shared->daemons[i].pid > 0)
		kill(uwsgi.shared->daemons[i].pid, SIGKILL);
	}

	for (i = 0; i < uwsgi.gateways_cnt; i++) {
		if (uwsgi.gateways[i].pid > 0)
		kill(uwsgi.gateways[i].pid, SIGKILL);
	}
}

void grace_them_all(int signum)
{
	int i;
	uwsgi.to_heaven = 1;

	if (uwsgi.reload_mercy > 0) {
		uwsgi.master_mercy = time(NULL) + uwsgi.reload_mercy;
	}

	for (i = 0; i < uwsgi.shared->daemons_cnt; i++) {
		if (uwsgi.shared->daemons[i].pid > 0)
		kill(uwsgi.shared->daemons[i].pid, SIGKILL);
	}

	for (i = 0; i < uwsgi.gateways_cnt; i++) {
		if (uwsgi.gateways[i].pid > 0)
		kill(uwsgi.gateways[i].pid, SIGKILL);
	}


	uwsgi_log("...gracefully killing workers...\n");
	for (i = 1; i <= uwsgi.numproc; i++) {
		if (uwsgi.workers[i].pid > 0)
		kill(uwsgi.workers[i].pid, SIGHUP);
	}

}

void uwsgi_nuclear_blast() {
	
	if (!uwsgi.workers) {
		reap_them_all(0);	
	}
	else if (uwsgi.master_process) {
		if (getpid() == uwsgi.workers[0].pid) {
			reap_them_all(0);	
		}
	}

	exit(1);
}

void reap_them_all(int signum)
{
	int i;
	uwsgi.to_heaven = 1;

	for (i = 0; i < uwsgi.shared->daemons_cnt; i++) {
		if (uwsgi.shared->daemons[i].pid > 0)
		kill(uwsgi.shared->daemons[i].pid, SIGKILL);
	}

	for (i = 0; i < uwsgi.gateways_cnt; i++) {
		if (uwsgi.gateways[i].pid > 0)
		kill(uwsgi.gateways[i].pid, SIGKILL);
	}

	if (!uwsgi.workers) return;

	uwsgi_log("...brutally killing workers...\n");
	for (i = 1; i <= uwsgi.numproc; i++) {
		if (uwsgi.workers[i].pid > 0)
		kill(uwsgi.workers[i].pid, SIGTERM);
	}
}

void harakiri()
{

	uwsgi_log("\nF*CK !!! i must kill myself (pid: %d app_id: %d)...\n", uwsgi.mypid, uwsgi.wsgi_req->app_id);

	if (!uwsgi.master_process) {
		uwsgi_log("*** if you want your workers to be automatically respawned consider enabling the uWSGI master process ***\n");
	}
	exit(0);
}

void stats(int signum)
{
	//fix this for better logging(this cause races)
	struct uwsgi_app *ua = NULL;
	int i;

	uwsgi_log("*** pid %d stats ***\n", getpid());
	uwsgi_log("\ttotal requests: %llu\n", uwsgi.workers[0].requests);
	for (i = 0; i < uwsgi.apps_cnt; i++) {
		ua = &uwsgi.apps[i];
		if (ua) {
			uwsgi_log("\tapp %d requests: %d\n", i, ua->requests);
		}
	}
	uwsgi_log("\n");
}

void what_i_am_doing()
{

	struct wsgi_request *wsgi_req;
	int i;

	if (uwsgi.cores > 1) {
		for(i=0;i<uwsgi.cores;i++) {
			wsgi_req = uwsgi.wsgi_requests[i];
			if (wsgi_req->uri_len > 0) {
				if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0 && uwsgi.workers[uwsgi.mywid].harakiri < time(NULL)) {
					uwsgi_log("HARAKIRI: --- uWSGI worker %d core %d (pid: %d) WAS managing request %.*s since %.*s ---\n",
						(int) uwsgi.mywid, i, (int) uwsgi.mypid, wsgi_req->uri_len, wsgi_req->uri, 24, ctime((const time_t *) & wsgi_req->start_of_request.tv_sec));
				}
				else {
					uwsgi_log("SIGUSR2: --- uWSGI worker %d core %d (pid: %d) is managing request %.*s since %.*s ---\n",
						(int) uwsgi.mywid, i, (int) uwsgi.mypid, wsgi_req->uri_len, wsgi_req->uri, 24, ctime((const time_t *) & wsgi_req->start_of_request.tv_sec));
				}
			}
		}
	}
	else {
		wsgi_req = uwsgi.wsgi_requests[0];
		if (wsgi_req->uri_len > 0) {
			if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0 && uwsgi.workers[uwsgi.mywid].harakiri < time(NULL)) {
				uwsgi_log("HARAKIRI: --- uWSGI worker %d (pid: %d) WAS managing request %.*s since %.*s ---\n",
					(int) uwsgi.mywid, (int) uwsgi.mypid, wsgi_req->uri_len, wsgi_req->uri, 24, ctime((const time_t *) & wsgi_req->start_of_request.tv_sec));
			} else {
				uwsgi_log("SIGUSR2: --- uWSGI worker %d (pid: %d) is managing request %.*s since %.*s ---\n",
					(int) uwsgi.mywid, (int) uwsgi.mypid, wsgi_req->uri_len, wsgi_req->uri, 24, ctime((const time_t *) & wsgi_req->start_of_request.tv_sec));
			}
		}
	}
}


pid_t masterpid;
struct timeval last_respawn;


int unconfigured_hook(struct wsgi_request * wsgi_req)
{
	uwsgi_log("-- unavailable modifier requested: %d --\n", wsgi_req->uh.modifier1);
	return -1;
}

static void unconfigured_after_hook(struct wsgi_request * wsgi_req)
{
	return;
}

struct uwsgi_plugin unconfigured_plugin = {

	.name = "unconfigured",
	.request = unconfigured_hook,
	.after_request = unconfigured_after_hook,
};

static void vacuum(void)
{

	int i;

	if (uwsgi.vacuum) {
		if (getpid() == masterpid) {
			if (chdir(uwsgi.cwd)) {
				uwsgi_error("chdir()");
			}
			if (uwsgi.pidfile && !uwsgi.uid) {
				if (unlink(uwsgi.pidfile)) {
					uwsgi_error("unlink()");
				} else {
					uwsgi_log("VACUUM: pidfile removed.\n");
				}
			}
			if (uwsgi.pidfile2) {
				if (unlink(uwsgi.pidfile2)) {
					uwsgi_error("unlink()");
				} else {
					uwsgi_log("VACUUM: pidfile2 removed.\n");
				}
			}
			if (uwsgi.chdir) {
				if (chdir(uwsgi.chdir)) {
					uwsgi_error("chdir()");
				}
			}
			for (i = 0; i < uwsgi.sockets_cnt; i++) {
				if (uwsgi.sockets[i].family == AF_UNIX) {
					if (unlink(uwsgi.sockets[i].name)) {
						uwsgi_error("unlink()");
					} else {
						uwsgi_log("VACUUM: unix socket %s removed.\n", uwsgi.sockets[i].name);
					}
				}
			}
		}
	}
}

int main(int argc, char *argv[], char *envp[])
{

	int i, j;
	int rlen;

	FILE *pidfile;

	char *env_reloads;
	char env_reload_buf[11];
	
	char *plugins_requested;



#ifdef UNBIT
	//struct uidsec_struct us;
#endif

#ifdef UWSGI_DEBUG
	struct utsname uuts;
#endif

	char *emperor_env;
	char *magic_table[0xff];
	char *optname;

	
	signal(SIGHUP, SIG_IGN);
	signal(SIGTERM, SIG_IGN);

	init_magic_table(magic_table);
	//initialize masterpid with a default value
	masterpid = getpid();

	memset(&uwsgi, 0, sizeof(struct uwsgi_server));
	uwsgi.cwd = uwsgi_get_cwd();

	atexit(vacuum);


#ifdef UWSGI_DEBUG
#ifdef __sun__
	if (uname(&uuts) < 0) {
#else
	if (uname(&uuts)) {
#endif
		uwsgi_error("uname()");
	} else {
		uwsgi_log("SYSNAME: %s\nNODENAME: %s\nRELEASE: %s\nVERSION: %s\nMACHINE: %s\n",
			  uuts.sysname,
			  uuts.nodename,
			  uuts.release,
			  uuts.version,
			  uuts.machine);
	}
#endif


	uwsgi.shared = (struct uwsgi_shared *) mmap(NULL, sizeof(struct uwsgi_shared), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
	if (!uwsgi.shared) {
		uwsgi_error("mmap()");
		exit(1);
	}
	memset(uwsgi.shared, 0, sizeof(struct uwsgi_shared));

#ifdef UWSGI_SPOOLER
	//set the spooler frequency to 30 seconds by default
	uwsgi.shared->spooler_frequency = 30;
#endif

	for (i = 0; i < 0xFF; i++) {
		uwsgi.p[i] = &unconfigured_plugin;
	}

	uwsgi.master_queue = -1;

	uwsgi.emperor_fd_config = -1;

	uwsgi.cluster_fd = -1;
	uwsgi.cores = 1;

	uwsgi.apps_cnt = 0;
	uwsgi.default_app = -1;

	uwsgi.buffer_size = 4096;
	uwsgi.numproc = 1;

	uwsgi.async = 1;
	uwsgi.listen_queue = 100;

	uwsgi.max_vars = MAX_VARS;
	uwsgi.vec_size = 4 + 1 + (4 * MAX_VARS);

	uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT] = 4;
	uwsgi.shared->options[UWSGI_OPTION_LOGGING] = 1;


	gettimeofday(&uwsgi.start_tv, NULL);

	setlinebuf(stdout);

	uwsgi.rl.rlim_cur = 0;
	uwsgi.rl.rlim_max = 0;

	emperor_env = getenv("UWSGI_EMPEROR_FD");
	if (emperor_env) {
		uwsgi.has_emperor = 1;
		uwsgi.emperor_fd = atoi(emperor_env);
		uwsgi.master_process = 1;
		uwsgi.no_orphans = 1;
		uwsgi_log("*** has_emperor mode detected (fd: %d) ***\n", uwsgi.emperor_fd);

		if (getenv("UWSGI_EMPEROR_FD_CONFIG")) {
			uwsgi.emperor_fd_config = atoi(getenv("UWSGI_EMPEROR_FD_CONFIG"));
		}
	}

	env_reloads = getenv("UWSGI_RELOADS");
	if (env_reloads) {
		//convert env value to int
		uwsgi.reloads = atoi(env_reloads);
		uwsgi.reloads++;
		//convert reloads to string
		rlen = snprintf(env_reload_buf, 10, "%u", uwsgi.reloads);
		if (rlen > 0) {
			env_reload_buf[rlen] = 0;
			if (setenv("UWSGI_RELOADS", env_reload_buf, 1)) {
				uwsgi_error("setenv()");
			}
		}
		uwsgi.is_a_reload = 1;
	} else {
		if (setenv("UWSGI_RELOADS", "0", 1)) {
			uwsgi_error("setenv()");
		}
	}

	uwsgi.binary_path = argv[0];

	//initialize embedded plugins
	UWSGI_LOAD_EMBEDDED_PLUGINS

	// now a bit of magic, if the argv[0] contains a _ try to automatically load a plugin
	//uwsgi_log("executable name: %s\n", argv[0]);
	char *p = strtok(argv[0], "_");
	plugins_requested = NULL;
	while (p != NULL) {
		p = strtok(NULL, "_");
		if (p) plugins_requested = p;
	}
	
	if (plugins_requested) {
		uwsgi_log("plugin = %s\n", plugins_requested);
		uwsgi_load_plugin(0, plugins_requested, NULL, 0);
	}

	plugins_requested = getenv("UWSGI_PLUGINS");
	if (plugins_requested) {
		char *p = strtok(plugins_requested, ",");
		while (p != NULL) {
			uwsgi_load_plugin(-1, p, NULL, 0);
			p = strtok(NULL, ",");
		}
	}
	build_options();

	uwsgi.option_index = -1;
	while ((i = getopt_long(argc, argv, short_options, uwsgi.long_options, &uwsgi.option_index)) != -1) {

		if (uwsgi.option_index > -1) {
			optname = (char *)uwsgi.long_options[uwsgi.option_index].name;
		}
		else {
			optname = uwsgi_get_optname_by_index(i);
		}
		// is this a flagged option ?
		if (i == 0) {
			add_exported_option(optname, "1", 0);
		}
		else {
			add_exported_option(optname, optarg, 1);
			manage_opt(i, optarg);
		}
		uwsgi.option_index = -1;
	}

	   if (optind < argc) {
	   	char *lazy = argv[optind];
		if (lazy[0] != '[') {
			if (0) {}

#ifdef UWSGI_XML
			else if (!strcmp(lazy+strlen(lazy)-4, ".xml")) {
				uwsgi.xml_config = lazy;
			}
#endif
#ifdef UWSGI_INI
			else if (!strcmp(lazy+strlen(lazy)-4, ".ini")) {
				uwsgi.ini = lazy;
			}
#endif
#ifdef UWSGI_YAML
			else if (!strcmp(lazy+strlen(lazy)-4, ".yml")) {
				uwsgi.yaml = lazy;
			}
#endif
			// manage magic mountpoint
			else if ( (lazy[0] == '/' || strchr(lazy, '|')) && strchr(lazy,'=')) {
			}
			else {
				int magic = 0;
				for(i =0; i < uwsgi.gp_cnt; i++) {
                			if (uwsgi.gp[i]->magic) {
                        			if (uwsgi.gp[i]->magic(NULL, lazy)) {
							magic = 1;
							break;
						}
                			}
				}
				if (!magic) {
        				for (i = 0; i < 0xFF; i++) {
                				if (uwsgi.p[i]->magic) {
                        				if (uwsgi.p[i]->magic(NULL, lazy)) {
								magic = 1;
								break;
							}
                				}
        				}
				}
			}
		}
	}

	if (gethostname(uwsgi.hostname, 255)) {
		uwsgi_error("gethostname()");
	}
	uwsgi.hostname_len = strlen(uwsgi.hostname);


	magic_table['v'] = uwsgi.cwd;
	magic_table['h'] = uwsgi.hostname;

#ifdef UWSGI_XML
	if (uwsgi.xml_config != NULL) {
		magic_table['o'] = uwsgi.xml_config;
		if (uwsgi.xml_config[0] == '/') {
			magic_table['p'] = uwsgi.xml_config;
		}
		else {
			magic_table['p'] = uwsgi_concat3(uwsgi.cwd,"/",uwsgi.xml_config);
		}
		magic_table['s'] = uwsgi_get_last_char(magic_table['p'], '/')+1;
		magic_table['d'] = uwsgi_concat2n(magic_table['p'], magic_table['s']-magic_table['p'], "", 0);
		if (uwsgi_get_last_char(uwsgi.xml_config, '.')) magic_table['e'] = uwsgi_get_last_char(uwsgi.xml_config, '.')+1;
		if (uwsgi_get_last_char(magic_table['s'], '.')) magic_table['n'] = uwsgi_concat2n(magic_table['s'], uwsgi_get_last_char(magic_table['s'], '.')-magic_table['s'], "", 0) ;
		uwsgi_xml_config(uwsgi.wsgi_req, 0, magic_table);
		uwsgi.xml_config = magic_table['p'];
	}
#endif
#ifdef UWSGI_INI
	if (uwsgi.ini != NULL) {
		magic_table['o'] = uwsgi.ini;
		if (uwsgi.ini[0] == '/') {
			magic_table['p'] = uwsgi.ini;
		}
		else {
			magic_table['p'] = uwsgi_concat3(uwsgi.cwd,"/",uwsgi.ini);
		}

		magic_table['s'] = uwsgi_get_last_char(magic_table['p'], '/')+1;
		magic_table['d'] = uwsgi_concat2n(magic_table['p'], magic_table['s']-magic_table['p'], "", 0);
		if (uwsgi_get_last_char(uwsgi.ini, '.')) magic_table['e'] = uwsgi_get_last_char(uwsgi.ini, '.')+1;
		if (uwsgi_get_last_char(magic_table['s'], '.')) magic_table['n'] = uwsgi_concat2n(magic_table['s'], uwsgi_get_last_char(magic_table['s'], '.')-magic_table['s'], "", 0) ;
		uwsgi_ini_config(uwsgi.ini, magic_table);
	}
#endif
#ifdef UWSGI_YAML
	if (uwsgi.yaml != NULL) {
		magic_table['o'] = uwsgi.yaml;
		if (uwsgi.yaml[0] == '/') {
			magic_table['p'] = uwsgi.yaml;
		}
		else {
			magic_table['p'] = uwsgi_concat3(uwsgi.cwd,"/",uwsgi.yaml);
		}
		magic_table['s'] = uwsgi_get_last_char(magic_table['p'], '/')+1;
		magic_table['d'] = uwsgi_concat2n(magic_table['p'], magic_table['s']-magic_table['p'], "", 0);
		if (uwsgi_get_last_char(uwsgi.yaml, '.')) magic_table['e'] = uwsgi_get_last_char(uwsgi.yaml, '.')+1;
		if (uwsgi_get_last_char(magic_table['s'], '.')) magic_table['n'] = uwsgi_concat2n(magic_table['s'], uwsgi_get_last_char(magic_table['s'], '.')-magic_table['s'], "", 0) ;
		uwsgi_yaml_config(uwsgi.yaml, magic_table);
	}
#endif
#ifdef UWSGI_LDAP
	if (uwsgi.ldap != NULL) {
		uwsgi_ldap_config();
	}
#endif

	//parse environ
	parse_sys_envs(environ);


	// second pass
	for (i = 0; i < uwsgi.exported_opts_cnt; i++) {
		int has_percent = 0;
		char *magic_key = NULL;
		char *magic_val = NULL;
		if (uwsgi.exported_opts[i]->value && !uwsgi.exported_opts[i]->configured) {
			for(j=0;j<(int)strlen(uwsgi.exported_opts[i]->value);j++) {
				if (uwsgi.exported_opts[i]->value[j] == '%') {
					has_percent = 1;
				}
				else if (uwsgi.exported_opts[i]->value[j] == '(' && has_percent == 1) {
					has_percent = 2;
					magic_key = uwsgi.exported_opts[i]->value + j + 1;
				}
				else if (has_percent > 1) {
					if (uwsgi.exported_opts[i]->value[j] == ')') {
						if (has_percent <= 2) {
							magic_key = NULL;
							has_percent = 0;
							continue;
						}
#ifdef UWSGI_DEBUG
						uwsgi_log("need to interpret the %.*s tag\n", has_percent-2, magic_key);
#endif
						char *tmp_magic_key = uwsgi_concat2n(magic_key, has_percent-2, "", 0);
						magic_val = uwsgi_get_exported_opt(tmp_magic_key);
						free(tmp_magic_key);
						if (!magic_val) {
							magic_key = NULL;
							has_percent = 0;
							continue;
						}
						uwsgi.exported_opts[i]->value = uwsgi_concat4n(
									uwsgi.exported_opts[i]->value, (magic_key-2) - uwsgi.exported_opts[i]->value, 
									magic_val, strlen(magic_val),
									magic_key + (has_percent-1),
									strlen(magic_key + (has_percent-1)), "", 0);
#ifdef UWSGI_DEBUG
						uwsgi_log("computed new value = %s\n", uwsgi.exported_opts[i]->value);
#endif
						magic_key = NULL;
						has_percent = 0;
						j = 0;
					}
					else {
						has_percent++;
					}
				}
				else {
					has_percent = 0;
				}
			}
		}
	}


	// ok, the options dictionary is available, lets manage it

        struct option *lopt = uwsgi.long_options;
        struct option *aopt;
        char *val;

	for(i=0;i<uwsgi.exported_opts_cnt;i++) {

		if (uwsgi.exported_opts[i]->configured) continue;
		lopt = uwsgi.long_options;;
        	while ((aopt = lopt)) {
                	if (!aopt->name) break;

			if (!strcmp(aopt->name, uwsgi.exported_opts[i]->key)) {
                		val = uwsgi.exported_opts[i]->value;

                        	if (aopt->flag) *aopt->flag = aopt->val;
                        	else if (val) {
                                	if (aopt->has_arg == optional_argument) {
                                        	if (!strcasecmp("true", val)) {
                                                	val = NULL;
                                        	}
                                	}
                                	if (aopt->has_arg == no_argument) {
                                        	if (!strcasecmp("false", val) || val[0] == '0') {
                                                	lopt++;
                                                	continue;
                                        	}
                                	}
                                	manage_opt(aopt->val, val);
                       		}
			}
                	lopt++;
		}
        }


	/* uWSGI IS CONFIGURED !!! */

	if (uwsgi.dump_options) {
		struct option *lopt = uwsgi.long_options;
		while(lopt->name) {
			fprintf(stdout, "%s\n", lopt->name);
			lopt++;
		}	
		exit(0);
	}

	if (uwsgi.show_config) {
		fprintf(stdout, "\n;uWSGI instance configuration\n[uwsgi]\n");
		for(i=0;i<uwsgi.exported_opts_cnt;i++) {
			if (uwsgi.exported_opts[i]->value) {
				fprintf(stdout,"%s = %s\n", uwsgi.exported_opts[i]->key, uwsgi.exported_opts[i]->value);
			}
			else {
				fprintf(stdout,"%s = true\n", uwsgi.exported_opts[i]->key);
			}
		}
		fprintf(stdout, ";end of configuration\n\n");
	}


#ifdef UWSGI_UDP
        // get cluster configuration
	if (uwsgi.cluster != NULL) {
		// get multicast socket

		uwsgi.cluster_fd = uwsgi_cluster_join(uwsgi.cluster);

		uwsgi_log("JOINED CLUSTER: %s\n", uwsgi.cluster);
	
		// ask for cluster options only if bot pre-existent options are set
		if (uwsgi.exported_opts_cnt == 1 && !uwsgi.cluster_nodes) {
			// now wait max 60 seconds and resend multicast request every 10 seconds
			for(;;) {
				uwsgi_log("asking \"%s\" uWSGI cluster for configuration data:\n", uwsgi.cluster);
				if (uwsgi_send_empty_pkt(uwsgi.cluster_fd, uwsgi.cluster, 99, 0) < 0) {
					uwsgi_log("unable to send multicast message to %s\n", uwsgi.cluster);	
					continue;
				}
waitfd:
				rlen = uwsgi_waitfd(uwsgi.cluster_fd, 10);
				if (rlen < 0) {
					break;	
				}
				else if (rlen > 0) {
					// receive the packet
					char clusterbuf[4096];
					if (!uwsgi_hooked_parse_dict_dgram(uwsgi.cluster_fd, clusterbuf, 4096, 99, 1, manage_string_opt, NULL)) {
						goto options_parsed;
					}
					else {
						goto waitfd;
					}
				}
			}
		}
options_parsed:

		if (!uwsgi.cluster_nodes) uwsgi_cluster_add_me();	
	}
#endif

	//call after_opt hooks

	if (uwsgi.binary_path == argv[0]) {
		uwsgi.binary_path = uwsgi_malloc(strlen(argv[0]) + 1);
		memcpy(uwsgi.binary_path, argv[0], strlen(argv[0]) + 1);
	}

	if (!uwsgi.no_initial_output) {
		if (uwsgi.shared->options[UWSGI_OPTION_CGI_MODE] == 0) {
			uwsgi_log("*** Starting uWSGI %s (%dbit) on [%.*s] ***\n", UWSGI_VERSION, (int) (sizeof(void *)) * 8, 24, ctime((const time_t *) &uwsgi.start_tv.tv_sec));
		} else {
			uwsgi_log("*** Starting uWSGI %s (CGI mode) (%dbit) on [%.*s] ***\n", UWSGI_VERSION, (int) (sizeof(void *)) * 8, 24, ctime((const time_t *) &uwsgi.start_tv.tv_sec));
		}

#ifdef UWSGI_DEBUG
	uwsgi_log("***\n*** You are running a DEBUG version of uWSGI, please disable debug in your build profile and recompile it ***\n***\n");
#endif

	uwsgi_log("compiled with version: %s on %s\n", __VERSION__, UWSGI_BUILD_DATE);

#ifdef __BIG_ENDIAN__
	uwsgi_log("*** big endian arch detected ***\n");
#endif

	}

	if (uwsgi.pidfile && !uwsgi.is_a_reload) {
		uwsgi_log("writing pidfile to %s\n", uwsgi.pidfile);
		pidfile = fopen(uwsgi.pidfile, "w");
		if (!pidfile) {
			uwsgi_error_open(uwsgi.pidfile);
			exit(1);
		}
		if (fprintf(pidfile, "%d\n", (int) getpid()) < 0) {
			uwsgi_log("could not write pidfile.\n");
		}
		fclose(pidfile);
	}

	for (i = 0; i < uwsgi.shared_sockets_cnt; i++) {
        	char *tcp_port = strchr(uwsgi.shared_sockets[i].name, ':');
                if (tcp_port == NULL) {
                	uwsgi.shared_sockets[i].fd = bind_to_unix(uwsgi.shared_sockets[i].name, uwsgi.listen_queue, uwsgi.chmod_socket, uwsgi.abstract_socket);
                        uwsgi.shared_sockets[i].family = AF_UNIX;
                        uwsgi_log("uwsgi shared socket %d bound to UNIX address %s fd %d\n", i, uwsgi.shared_sockets[i].name, uwsgi.shared_sockets[i].fd);
                } else {
                	uwsgi.shared_sockets[i].fd = bind_to_tcp(uwsgi.shared_sockets[i].name, uwsgi.listen_queue, tcp_port);
                        uwsgi.shared_sockets[i].family = AF_INET;
                	uwsgi_log("uwsgi shared socket %d bound to TCP address %s fd %d\n", i, uwsgi.shared_sockets[i].name, uwsgi.shared_sockets[i].fd);
		}

		if (uwsgi.shared_sockets[i].fd < 0) {
			uwsgi_log("unable to create shared socket on: %s\n", uwsgi.shared_sockets[i].name);
			exit(1);
		}
		uwsgi.shared_sockets[i].bound = 1;
	}

	// call jail systems
	for(i =0; i < uwsgi.gp_cnt; i++) {
                if (uwsgi.gp[i]->jail) {
                        uwsgi.gp[i]->jail(uwsgi_start, argv);
                }
        }


#ifdef __linux__

#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS 0x04000000
#endif

#ifndef CLONE_NEWPID
#define CLONE_NEWPID 0x20000000
#endif

#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC 0x08000000
#endif

#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000
#endif

	if (uwsgi.ns) {
		for(;;) {
			char stack[PTHREAD_STACK_MIN];
			int waitpid_status;
			uwsgi_log("*** jailing uWSGI in %s ***\n", uwsgi.ns);
			int clone_flags = SIGCHLD|CLONE_NEWUTS|CLONE_NEWPID|CLONE_NEWIPC|CLONE_NEWNS;
			if (uwsgi.ns_net) {
				clone_flags |= CLONE_NEWNET;
			}
			pid_t pid = clone(uwsgi_start, stack+PTHREAD_STACK_MIN, clone_flags, (void *)argv);
			if (pid == -1) {
				uwsgi_error("clone()");
				exit(1);
			}
			uwsgi_log("waiting for jailed master (pid: %d) death...\n", (int) pid);
			pid = waitpid(pid, &waitpid_status, 0);
			if (pid < 0) {
				uwsgi_error("waitpid()");
				exit(1);
			}

			// in Linux this is reliable
			if (WIFEXITED(waitpid_status) && WEXITSTATUS(waitpid_status) == 1) {
				exit(1);
			}

			uwsgi_log("pid %d ended. Respawning...\n", (int) pid);	
		}
	}
	else {
#endif
		uwsgi_start((void *)argv);
#ifdef __linux__
	}
#endif


	// never here
	return 0;
}

int uwsgi_start(void *v_argv) {

	char **argv = v_argv;

#ifdef UWSGI_DEBUG
        int so_bufsize;
        socklen_t so_bufsize_len;
#endif


	pid_t pid;
	int i, j;

	union uwsgi_sockaddr usa;
        union uwsgi_sockaddr_ptr gsa, isa;
        socklen_t socket_type_len;

	int emperor_pipe[2];

#ifdef __linux__
	char *ns_tmp_mountpoint=NULL, *ns_tmp_mountpoint2=NULL;
	if (uwsgi.ns) {
	
		if (getpid() != 1) { 
			uwsgi_log("your kernel does not support linux pid namespace\n");
			exit(1);
		}

		char *ns_hostname = strchr(uwsgi.ns, ':');
		if (ns_hostname) {
			ns_hostname[0] = 0;
			ns_hostname++;
			if (sethostname(ns_hostname, strlen(ns_hostname))) {
				uwsgi_error("sethostname()");
			}
		}

		FILE *procmounts;
		char line[1024];
		int unmounted = 1;
		char *delim0, *delim1;

		if (chdir(uwsgi.ns)) {
			uwsgi_error("chdir()");
			exit(1);
		}

		if (strcmp(uwsgi.ns, "/")) {
			ns_tmp_mountpoint = uwsgi_concat2(uwsgi.ns, "/.uwsgi_ns_tmp_mountpoint");
			mkdir(ns_tmp_mountpoint, S_IRWXU);

			ns_tmp_mountpoint2 = uwsgi_concat2(ns_tmp_mountpoint, "/.uwsgi_ns_tmp_mountpoint");
			mkdir(ns_tmp_mountpoint2, S_IRWXU);

			if (mount(uwsgi.ns, ns_tmp_mountpoint, "none", MS_BIND, NULL)) {
				uwsgi_error("mount()");
			}
			if (chdir(ns_tmp_mountpoint)) {
				uwsgi_error("chdir()");
			}

			if (pivot_root(".", ns_tmp_mountpoint2)) {
				uwsgi_error("pivot_root()");
				exit(1);
			}



			if (chdir("/")) {
				uwsgi_error("chdir()");
				exit(1);
			}

		}

		uwsgi_log("remounting /proc\n");
		if (mount("proc","/proc", "proc", 0, NULL)) {
			uwsgi_error("mount()");
		}

		while(unmounted) {

                        unmounted = 0;
                        procmounts = fopen("/proc/self/mounts", "r");
                        while(fgets(line,1024,procmounts) != NULL) {
                                delim0 = strchr(line, ' ');
                                delim0++;
                                delim1 = strchr(delim0, ' ');
                                *delim1 = 0;
				if (!strcmp(delim0,"/") || !strcmp(delim0,"/proc")) continue;
                                if (!umount(delim0)) {
                                        unmounted++;
                                }
                        }
                        fclose(procmounts);
                }

		if (rmdir("/.uwsgi_ns_tmp_mountpoint/.uwsgi_ns_tmp_mountpoint")) {
			uwsgi_error("rmdir()");
		}
		if (rmdir("/.uwsgi_ns_tmp_mountpoint")) {
			uwsgi_error("rmdir()");
		}

		if (strcmp(uwsgi.ns, "/")) {
			free(ns_tmp_mountpoint2);
			free(ns_tmp_mountpoint);
		}


	}
#endif

	if (!uwsgi.master_as_root) {
		uwsgi_as_root();
	}

	if (uwsgi.chdir) {
		if (chdir(uwsgi.chdir)) {
			uwsgi_error("chdir()");
			exit(1);
		}
	}

	if (uwsgi.pidfile2 && !uwsgi.is_a_reload) {
                uwsgi_log("writing pidfile2 to %s\n", uwsgi.pidfile2);
                FILE *pidfile2 = fopen(uwsgi.pidfile2, "w");
                if (!pidfile2) {
                        uwsgi_error_open(uwsgi.pidfile2);
                        exit(1);
                }
                if (fprintf(pidfile2, "%d\n", (int) getpid()) < 0) {
                        uwsgi_log("could not write pidfile2.\n");
                }
                fclose(pidfile2);
        }

	if (!uwsgi.no_initial_output) {
		if (!uwsgi.master_process) {
			uwsgi_log(" *** WARNING: you are running uWSGI without its master process manager ***\n");
		}
	}
#ifndef __OpenBSD__

	if (uwsgi.rl.rlim_max > 0) {
		uwsgi_log("limiting address space of processes...\n");
		if (setrlimit(RLIMIT_AS, &uwsgi.rl)) {
			uwsgi_error("setrlimit()");
		}
	}
	if (uwsgi.prio != 0) {
#ifdef __HAIKU__
		if (set_thread_priority(find_thread(NULL), uwsgi.prio) == B_BAD_THREAD_ID) {
			uwsgi_error("set_thread_priority()");
#else
		if (setpriority(PRIO_PROCESS, 0, uwsgi.prio)) {
			uwsgi_error("setpriority()");
#endif

		} else {
			uwsgi_log("scheduler priority set to %d\n", uwsgi.prio);
		}
	}
	if (!getrlimit(RLIMIT_AS, &uwsgi.rl)) {
		//check for overflow
		if (uwsgi.rl.rlim_max != RLIM_INFINITY && !uwsgi.no_initial_output) {
			uwsgi_log("your process address space limit is %lld bytes (%lld MB)\n", (long long) uwsgi.rl.rlim_max, (long long) uwsgi.rl.rlim_max / 1024 / 1024);
		}
	}
#endif

	uwsgi.page_size = getpagesize();

	if (!uwsgi.no_initial_output) {
		uwsgi_log("your memory page size is %d bytes\n", uwsgi.page_size);
	}

	if (uwsgi.buffer_size > 65536) {
		uwsgi_log("invalid buffer size.\n");
		exit(1);
	}
	sanitize_args();

	// end of generic initialization


	// start the Emperor if needed
	if (uwsgi.emperor_dir) {

		if (socketpair(AF_UNIX, SOCK_STREAM, 0, emperor_pipe)) {
                	uwsgi_error("socketpair()");
			exit(1);
        	}

		uwsgi.emperor_pid = fork();
		if (uwsgi.emperor_pid < 0) {
			uwsgi_error("pid()");
			exit(1);
		}
		else if (uwsgi.emperor_pid > 0) {
			close(emperor_pipe[1]);
			emperor_loop();
			// never here
			exit(1);
		}

		// do not go on if no socket or gateway is defined
		if (!uwsgi.sockets_cnt && !uwsgi.gateways_cnt) {
			exit(0);
		}
		close(emperor_pipe[0]);
		uwsgi.has_emperor = 1;
        	uwsgi.emperor_fd = emperor_pipe[1];
        	uwsgi.master_process = 1;
        	uwsgi.no_orphans = 1;
	}


	uwsgi_register_loop("simple", simple_loop);
	uwsgi_register_loop("async", async_loop);


	// TODO rewrite to use uwsgi.max_fd
	if (uwsgi.async > 1) {
		if (!getrlimit(RLIMIT_NOFILE, &uwsgi.rl)) {
			if ((unsigned long) uwsgi.rl.rlim_cur < (unsigned long) uwsgi.async) {
				uwsgi_log("- your current max open files limit is %lu, this is lower than requested async cores !!! -\n", (unsigned long) uwsgi.rl.rlim_cur);
				if (uwsgi.rl.rlim_cur < uwsgi.rl.rlim_max && (unsigned long) uwsgi.rl.rlim_max > (unsigned long) uwsgi.async) {
					unsigned long tmp_nofile = (unsigned long) uwsgi.rl.rlim_cur;
					uwsgi.rl.rlim_cur = uwsgi.async;
					if (!setrlimit(RLIMIT_NOFILE, &uwsgi.rl)) {
						uwsgi_log("max open files limit reset to %lu\n", (unsigned long) uwsgi.rl.rlim_cur);
						uwsgi.async = uwsgi.rl.rlim_cur;
					} else {
						uwsgi.async = (int) tmp_nofile;
					}
				} else {
					uwsgi.async = uwsgi.rl.rlim_cur;
				}

				uwsgi_log("- async cores set to %d -\n", uwsgi.async);
			}
		}
	}

	if (!getrlimit(RLIMIT_NOFILE, &uwsgi.rl)) {
		uwsgi.max_fd = uwsgi.rl.rlim_cur;	
	}

	uwsgi.wsgi_requests = uwsgi_malloc(sizeof(struct wsgi_request *) * uwsgi.cores);

	for (i = 0; i < uwsgi.cores; i++) {
		uwsgi.wsgi_requests[i] = uwsgi_malloc(sizeof(struct wsgi_request));
		memset(uwsgi.wsgi_requests[i], 0, sizeof(struct wsgi_request));
	}

	uwsgi.async_buf = uwsgi_malloc(sizeof(char *) * uwsgi.cores);

	if (uwsgi.async > 1) {
		uwsgi_log("async fd table size: %d\n", uwsgi.max_fd);
		uwsgi.async_waiting_fd_table = malloc( sizeof(struct wsgi_request *) * uwsgi.max_fd);
        	if (!uwsgi.async_waiting_fd_table) {
                	uwsgi_error("malloc()");
                	exit(1);
        	}
	}

	if (uwsgi.post_buffering > 0) {
		uwsgi.async_post_buf = uwsgi_malloc(sizeof(char *) * uwsgi.cores);
		if (!uwsgi.post_buffering_bufsize) {
			uwsgi.post_buffering_bufsize = 8192;
		}
	}
	for (i = 0; i < uwsgi.cores; i++) {
		uwsgi.async_buf[i] = uwsgi_malloc(uwsgi.buffer_size);
		if (uwsgi.post_buffering > 0) {
			uwsgi.async_post_buf[i] = uwsgi_malloc(uwsgi.post_buffering_bufsize);
		}
	}


	//by default set wsgi_req to the first slot
	uwsgi.wsgi_req = uwsgi.wsgi_requests[0];

	if (uwsgi.cores > 1) {
		uwsgi_log("allocated %llu bytes (%llu KB) for %d cores per worker.\n", (uint64_t) (sizeof(struct wsgi_request) * uwsgi.cores),
			  (uint64_t) ((sizeof(struct wsgi_request) * uwsgi.cores) / 1024),
			  uwsgi.cores);
	}
	if (uwsgi.vhost) {
		uwsgi_log("VirtualHosting mode enabled.\n");
		uwsgi.apps_cnt = 0;
	}


	// application generic lock
	uwsgi.user_lock = uwsgi_mmap_shared_lock();
	uwsgi_lock_init(uwsgi.user_lock);

	if (uwsgi.master_process) {
		// signal table lock
		uwsgi.signal_table_lock = uwsgi_mmap_shared_lock();
		uwsgi_lock_init(uwsgi.signal_table_lock);

		// fmon table lock
		uwsgi.fmon_table_lock = uwsgi_mmap_shared_lock();
		uwsgi_lock_init(uwsgi.fmon_table_lock);

		// timer table lock
		uwsgi.timer_table_lock = uwsgi_mmap_shared_lock();
		uwsgi_lock_init(uwsgi.timer_table_lock);

		// rb_timer table lock
		uwsgi.rb_timer_table_lock = uwsgi_mmap_shared_lock();
		uwsgi_lock_init(uwsgi.rb_timer_table_lock);

		// daemons table lock
		uwsgi.daemon_table_lock = uwsgi_mmap_shared_lock();
		uwsgi_lock_init(uwsgi.daemon_table_lock);

		// cron table lock
		uwsgi.cron_table_lock = uwsgi_mmap_shared_lock();
		uwsgi_lock_init(uwsgi.cron_table_lock);
	}

#ifdef UWSGI_SPOOLER
	if (uwsgi.spool_dir) {
		// spooler lock
		uwsgi.spooler_lock = uwsgi_mmap_shared_lock();
                uwsgi_lock_init(uwsgi.spooler_lock);
	}
#endif

	uwsgi.rpc_table_lock = uwsgi_mmap_shared_lock();
	uwsgi_lock_init(uwsgi.rpc_table_lock);

	if (uwsgi.sharedareasize > 0) {
		uwsgi.sharedareamutex = uwsgi_mmap_shared_lock();

		uwsgi.sharedarea = mmap(NULL, uwsgi.page_size * uwsgi.sharedareasize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
		if (uwsgi.sharedarea) {
			uwsgi_log("shared area mapped at %p, you can access it with uwsgi.sharedarea* functions.\n", uwsgi.sharedarea);
			uwsgi_lock_init(uwsgi.sharedareamutex);
		} else {
			uwsgi_error("mmap()");
			exit(1);
		}

	}

	if (uwsgi.queue_size > 0) {
		if (!uwsgi.queue_blocksize) uwsgi.queue_blocksize = 8192;

		if (uwsgi.queue_blocksize % uwsgi.page_size != 0) {
                        uwsgi_log("invalid queue blocksize %llu: must be a multiple of memory page size (%d bytes)\n", (unsigned long long) uwsgi.queue_blocksize, uwsgi.page_size);
                        exit(1);
                }


		uwsgi.shared->queue_pos = 0;
                uwsgi.shared->queue_pull_pos = 0;

		if (uwsgi.queue_store) {
			uwsgi.queue_filesize = uwsgi.queue_blocksize * uwsgi.queue_size;
			int queue_fd;
			struct stat qst;

			if (stat(uwsgi.queue_store, &qst)) {
                                uwsgi_log("creating a new queue store file: %s\n", uwsgi.queue_store);
                                queue_fd = open(uwsgi.queue_store, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR );
                                if (queue_fd >= 0) {
                                        // fill the queue store
                                        if (ftruncate(queue_fd, uwsgi.queue_filesize)) {
                                                uwsgi_log("ftruncate()");
                                                exit(1);
                                        }
                                }
                        }
                        else {
                                if ((size_t)qst.st_size != uwsgi.queue_filesize || !S_ISREG(qst.st_mode)) {
                                        uwsgi_log("invalid queue store file. Please remove it or fix queue blocksize/items to match its size\n");
                                        exit(1);
                                }
                                queue_fd = open(uwsgi.queue_store, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR );
                                uwsgi_log("recovered queue from backing store file: %s\n", uwsgi.queue_store);
                        }

                        if (queue_fd < 0) {
                                uwsgi_error_open(uwsgi.queue_store);
                                exit(1);
                        }
                        uwsgi.queue = mmap(NULL, uwsgi.queue_filesize, PROT_READ | PROT_WRITE, MAP_SHARED, queue_fd, 0);
			uwsgi_queue_fix();		
		}
		else {
			uwsgi.queue = mmap(NULL, uwsgi.queue_blocksize * uwsgi.queue_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
		}
		if (!uwsgi.queue) {
                        uwsgi_error("mmap()");
                        exit(1);
                }

                uwsgi.queue_lock = uwsgi_mmap_shared_rwlock();
                uwsgi_rwlock_init(uwsgi.queue_lock);

		uwsgi_log("*** Queue subsystem initialized: %dMB preallocated ***\n", (uwsgi.queue_blocksize * uwsgi.queue_size)  / (1024*1024));

	}

	if (uwsgi.cache_max_items > 0) {

		if (!uwsgi.cache_blocksize) uwsgi.cache_blocksize = UMAX16;

		if (uwsgi.cache_blocksize % uwsgi.page_size != 0) {
			uwsgi_log("invalid cache blocksize %llu: must be a multiple of memory page size (%d bytes)\n", (unsigned long long) uwsgi.cache_blocksize, uwsgi.page_size);
			exit(1);
		}

		uwsgi.cache_hashtable = (uint64_t *) mmap(NULL, sizeof(uint64_t) * UMAX16, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
		if (!uwsgi.cache_hashtable) {
			uwsgi_error("mmap()");
                        exit(1);
		}

		memset(uwsgi.cache_hashtable, 0, sizeof(uint64_t) * UMAX16);

		uwsgi.cache_unused_stack = (uint64_t *) mmap(NULL, sizeof(uint64_t) * uwsgi.cache_max_items, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
                if (!uwsgi.cache_unused_stack) {
                        uwsgi_error("mmap()");
                        exit(1);
                }

                memset(uwsgi.cache_unused_stack, 0, sizeof(uint64_t) * uwsgi.cache_max_items);

		// the first cache item is always zero
		uwsgi.shared->cache_first_available_item = 1;
		uwsgi.shared->cache_unused_stack_ptr = 0;

		//uwsgi.cache_items = (struct uwsgi_cache_item *) mmap(NULL, sizeof(struct uwsgi_cache_item) * uwsgi.cache_max_items, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
		if (uwsgi.cache_store) {
			uwsgi.cache_filesize = (sizeof(struct uwsgi_cache_item) * uwsgi.cache_max_items) + (uwsgi.cache_blocksize * uwsgi.cache_max_items);
			int cache_fd;
			struct stat cst;

			if (stat(uwsgi.cache_store, &cst)) {
				uwsgi_log("creating a new cache store file: %s\n", uwsgi.cache_store);
				cache_fd = open(uwsgi.cache_store, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR );
				if (cache_fd >= 0) {
					// fill the caching store
					if (ftruncate(cache_fd, uwsgi.cache_filesize)) {
						uwsgi_log("ftruncate()");
						exit(1);
					}
				}
			}
			else {
				if ((size_t)cst.st_size != uwsgi.cache_filesize || !S_ISREG(cst.st_mode)) {
					uwsgi_log("invalid cache store file. Please remove it or fix cache blocksize/items to match its size\n");
					exit(1);
				}
				cache_fd = open(uwsgi.cache_store, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR );
				uwsgi_log("recovered cache from backing store file: %s\n", uwsgi.cache_store);
			}
			
			if (cache_fd < 0) {
				uwsgi_error_open(uwsgi.cache_store);
				exit(1);
			}
			uwsgi.cache_items = (struct uwsgi_cache_item *) mmap(NULL, uwsgi.cache_filesize, PROT_READ | PROT_WRITE, MAP_SHARED, cache_fd, 0);
			uwsgi_cache_fix();
			
		}
		else {
			uwsgi.cache_items = (struct uwsgi_cache_item *) mmap(NULL, (sizeof(struct uwsgi_cache_item) * uwsgi.cache_max_items) + (uwsgi.cache_blocksize * uwsgi.cache_max_items), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
			for(i=0;i< (int) uwsgi.cache_max_items;i++) {
				memset(&uwsgi.cache_items[i], 0, sizeof(struct uwsgi_cache_item));
			}
		}
		if (!uwsgi.cache_items) {
			uwsgi_error("mmap()");
                        exit(1);
		}

		/*
		uwsgi.cache = mmap(NULL, uwsgi.cache_blocksize * uwsgi.cache_max_items, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
		if (!uwsgi.cache) {
			uwsgi_error("mmap()");
                        exit(1);
		}
		*/

		uwsgi.cache = ((void *) uwsgi.cache_items) + (sizeof(struct uwsgi_cache_item) * uwsgi.cache_max_items) ;
		
		uwsgi.cache_lock = uwsgi_mmap_shared_rwlock();
        	uwsgi_rwlock_init(uwsgi.cache_lock);

		uwsgi.p[111] = &uwsgi_cache_plugin;

		uwsgi_log("*** Cache subsystem initialized: %dMB preallocated ***\n", ((sizeof(uint64_t) * UMAX16) + (sizeof(uint64_t) * uwsgi.cache_max_items) + (uwsgi.cache_blocksize * uwsgi.cache_max_items) + (sizeof(struct uwsgi_cache_item) * uwsgi.cache_max_items)) / (1024*1024));
	}

	// attach startup daemons
	if (uwsgi.master_process) {
		for(i=0;i<uwsgi.startup_daemons_cnt;i++) {
			if (uwsgi_attach_daemon(uwsgi.startup_daemons[i])) {
				uwsgi_log("!!! unable to attach daemon %s !!!\n", uwsgi.startup_daemons[i]);
			}
		}
	}

	/* plugin initialization */
	for(i =0; i < uwsgi.gp_cnt; i++) {
		if (uwsgi.gp[i]->init) {
			uwsgi.gp[i]->init();
		}
	}


	if (!uwsgi.no_server) {

		//check for inherited sockets
			if (uwsgi.is_a_reload) {
				for (i = 0; i < uwsgi.sockets_cnt; i++) {
					//a bit overengineering
						if (uwsgi.sockets[i].name != NULL) {

						for (j = 3; j < sysconf(_SC_OPEN_MAX); j++) {
							socket_type_len = sizeof(struct sockaddr_un);
							gsa.sa = &usa.sa;
							if (!getsockname(j, gsa.sa, &socket_type_len)) {
								if (socket_type_len <= 2) {
									// unbound socket
									continue;
								}
								if (gsa.sa->sa_family == AF_UNIX) {
									if (!strcmp(usa.sa_un.sun_path, uwsgi.sockets[i].name)) {
										uwsgi.sockets[i].fd = j;
										uwsgi.sockets[i].family = AF_UNIX;
										uwsgi.sockets[i].bound = 1;
										uwsgi.sockets_poll[i].fd = uwsgi.sockets[i].fd;
										uwsgi.sockets_poll[i].events = POLLIN;
										uwsgi_log("uwsgi socket %d inherited UNIX address %s fd %d\n", i, uwsgi.sockets[i].name, uwsgi.sockets[i].fd);
									}
								} else if (gsa.sa->sa_family == AF_INET) {
									char *computed_addr;
									char computed_port[6];
									isa.sa_in = (struct sockaddr_in *) &usa;
									char ipv4a[INET_ADDRSTRLEN + 1];
									memset(ipv4a, 0, INET_ADDRSTRLEN + 1);
									memset(computed_port, 0, 6);


									if (snprintf(computed_port, 6, "%d", ntohs(isa.sa_in->sin_port)) > 0) {
										if (inet_ntop(AF_INET, (const void *) &isa.sa_in->sin_addr.s_addr, ipv4a, INET_ADDRSTRLEN)) {

											if (!strcmp("0.0.0.0", ipv4a)) {
												computed_addr = uwsgi_concat2(":", computed_port);
											} else {
												computed_addr = uwsgi_concat3(ipv4a, ":", computed_port);
											}
											char *asterisk = strchr(uwsgi.sockets[i].name, '*');
											int match = 1;
											if (asterisk) {
												asterisk[0] = 0;
												match = strncmp(computed_addr, uwsgi.sockets[i].name, strlen(uwsgi.sockets[i].name));
												asterisk[0] = '*';	
											}
											else {
												match = strcmp(computed_addr, uwsgi.sockets[i].name);
											}
											if (!match) {
												uwsgi.sockets[i].fd = j;
												uwsgi.sockets[i].family = AF_INET;
												uwsgi.sockets[i].bound = 1;
												uwsgi.sockets_poll[i].fd = uwsgi.sockets[i].fd;
												uwsgi.sockets_poll[i].events = POLLIN;
												uwsgi_log("uwsgi socket %d inherited INET address %s fd %d\n", i, uwsgi.sockets[i].name, uwsgi.sockets[i].fd);
											}
											free(computed_addr);
										}
									}
								}
							}
						}
					}
				}

				//now close all the unbound fd
				for (j = 3; j < sysconf(_SC_OPEN_MAX); j++) {
					int useless = 1;
#ifdef UWSGI_MULTICAST
					if (j == uwsgi.cluster_fd) continue;
#endif
					if (uwsgi.has_emperor) { if (j == uwsgi.emperor_fd) continue; }
					socket_type_len = sizeof(struct sockaddr_un);
					gsa.sa = (struct sockaddr *) & usa;
					if (!getsockname(j, gsa.sa, &socket_type_len)) {
						for (i = 0; i < uwsgi.sockets_cnt; i++) {
							if (uwsgi.sockets[i].fd == j && uwsgi.sockets[i].bound) {
								useless = 0;
								break;
							}
						}
					}
					if (useless)
						close(j);
				}
			}
		//now bind all the unbound sockets
		for (i = 0; i < uwsgi.sockets_cnt; i++) {
			if (!uwsgi.sockets[i].bound) {
				char *tcp_port = strchr(uwsgi.sockets[i].name, ':');
				if (tcp_port == NULL) {
					uwsgi.sockets[i].fd = bind_to_unix(uwsgi.sockets[i].name, uwsgi.listen_queue, uwsgi.chmod_socket, uwsgi.abstract_socket);
					uwsgi.sockets[i].family = AF_UNIX;
					uwsgi_log("uwsgi socket %d bound to UNIX address %s fd %d\n", i, uwsgi.sockets[i].name, uwsgi.sockets[i].fd);
				} else {
					uwsgi.sockets[i].fd = bind_to_tcp(uwsgi.sockets[i].name, uwsgi.listen_queue, tcp_port);
					uwsgi.sockets[i].family = AF_INET;
					uwsgi_log("uwsgi socket %d bound to TCP address %s fd %d\n", i, uwsgi.sockets[i].name, uwsgi.sockets[i].fd);
				}

				if (uwsgi.sockets[i].fd < 0) {
					uwsgi_log("unable to create server socket on: %s\n", uwsgi.sockets[i].name);
					exit(1);
				}
			}
			uwsgi.sockets[i].bound = 1;
			uwsgi.sockets_poll[i].fd = uwsgi.sockets[i].fd;
			uwsgi.sockets_poll[i].events = POLLIN;
		}

		int zero_used = 0;
		for (i = 0; i < uwsgi.sockets_cnt; i++) {
			if (uwsgi.sockets[i].bound && uwsgi.sockets[i].fd == 0) {
				zero_used = 1;
				break;
			}
		}

		if (!zero_used) {
			socket_type_len = sizeof(struct sockaddr_un);
			gsa.sa = (struct sockaddr *) & usa;
			if (!getsockname(0, gsa.sa, &socket_type_len)) {
				if (uwsgi.sockets_cnt < 8) {
					uwsgi.sockets_cnt++;
					uwsgi.sockets[uwsgi.sockets_cnt - 1].fd = 0;
					uwsgi.sockets[uwsgi.sockets_cnt - 1].bound = 1;
					uwsgi.sockets[uwsgi.sockets_cnt - 1].family = gsa.sa->sa_family;
					if (uwsgi.sockets[uwsgi.sockets_cnt - 1].family == AF_UNIX) {	
						uwsgi.sockets[uwsgi.sockets_cnt - 1].name = usa.sa_un.sun_path;
						uwsgi_log("uwsgi socket %d inherited UNIX address %s fd 0\n", uwsgi.sockets_cnt - 1, uwsgi.sockets[uwsgi.sockets_cnt - 1].name);
					}
					else {
						uwsgi_log("uwsgi socket %d inherited INET address %s fd 0\n", uwsgi.sockets_cnt - 1, uwsgi.sockets[uwsgi.sockets_cnt - 1].name);
					}
					uwsgi.sockets_poll[uwsgi.sockets_cnt - 1].fd = 0;
					uwsgi.sockets_poll[uwsgi.sockets_cnt - 1].events = POLLIN;
				} else {
					uwsgi_log("too many socket defined, i cannot map fd 0\n");
				}
			} else {
				int fd = open("/dev/null", O_RDONLY);
				if (fd < 0) {
					uwsgi_error_open("/dev/null");
					exit(1);
				}
				if (fd != 0) {
					if (dup2(fd, 0)) {
						uwsgi_error("dup2()");
						exit(1);
					}
				}
			}

		}

	
		// put listening socket in non-blocking state
		for (i = 0; i < uwsgi.sockets_cnt; i++) {
			uwsgi.sockets[i].arg = fcntl(uwsgi.sockets[i].fd, F_GETFL, NULL);
                	if (uwsgi.sockets[i].arg < 0) {
                        	uwsgi_error("fcntl()");
				exit(1);
                	}
                	uwsgi.sockets[i].arg |= O_NONBLOCK;
                	if (fcntl(uwsgi.sockets[i].fd, F_SETFL, uwsgi.sockets[i].arg) < 0) {
                        	uwsgi_error("fcntl()");
                        	exit(1);
                	}
		}
	
	}

	
	// initialize request plugin only if workers or master are available
	if (uwsgi.sockets_cnt || uwsgi.master_process) {
		for (i = 0; i < 0xFF; i++) {
			if (uwsgi.p[i]->init) {
				uwsgi.p[i]->init();
			}
		}
	}


	/* gp/plugin initialization */
	for(i =0; i < uwsgi.gp_cnt; i++) {
		if (uwsgi.gp[i]->post_init) {
			uwsgi.gp[i]->post_init();
		}
	}

	for(i =0; i < 0xff; i++) {
		if (uwsgi.p[i]->post_init) {
			uwsgi.p[i]->post_init();
		}
	}

	uwsgi.current_wsgi_req = simple_current_wsgi_req;


#ifdef UWSGI_THREADING
	if (uwsgi.sockets_cnt) {
		if (uwsgi.has_threads) {
			if (uwsgi.threads > 1)
				uwsgi.current_wsgi_req = threaded_current_wsgi_req;
			for (i = 0; i < 0xFF; i++) {
				if (uwsgi.p[i]->enable_threads)
					uwsgi.p[i]->enable_threads();
			}
		}
	}
#endif

	if (!uwsgi.sockets_cnt && !uwsgi.gateways_cnt && !uwsgi.no_server) {
		uwsgi_log("The -s/--socket option is missing and stdin is not a socket.\n");
		exit(1);
	}
	else if (!uwsgi.sockets_cnt && uwsgi.gateways_cnt && !uwsgi.no_server && !uwsgi.master_process) {
		exit(0);
	}

	if (!uwsgi.sockets_cnt) uwsgi.numproc = 0;

#ifdef UWSGI_DEBUG
	for (i = 0; i < uwsgi.sockets_cnt; i++) {
		so_bufsize_len = sizeof(int);
		if (getsockopt(uwsgi.sockets[i].fd, SOL_SOCKET, SO_RCVBUF, &so_bufsize, &so_bufsize_len)) {
			uwsgi_error("getsockopt()");
		} else {
			uwsgi_debug("uwsgi socket %d SO_RCVBUF size: %d\n", i, so_bufsize);
		}

		so_bufsize_len = sizeof(int);
		if (getsockopt(uwsgi.sockets[i].fd, SOL_SOCKET, SO_SNDBUF, &so_bufsize, &so_bufsize_len)) {
			uwsgi_error("getsockopt()");
		} else {
			uwsgi_debug("uwsgi socket %d SO_SNDBUF size: %d\n", i, so_bufsize);
		}
	}
#endif


#ifndef UNBIT
	uwsgi_log("your server socket listen backlog is limited to %d connections\n", uwsgi.listen_queue);
#endif


	memset(uwsgi.apps, 0, sizeof(uwsgi.apps));

	uwsgi.workers = (struct uwsgi_worker *) mmap(NULL, sizeof(struct uwsgi_worker) * (uwsgi.numproc + 1 + uwsgi.grunt), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
	if (!uwsgi.workers) {
		uwsgi_error("mmap()");
		exit(1);
	}
	memset(uwsgi.workers, 0, sizeof(struct uwsgi_worker) * uwsgi.numproc + 1);

	for(i=0;i<MAX_SOCKETS;i++) {
		if (!uwsgi.map_socket[i]) continue;
		char *p = strtok(uwsgi.map_socket[i], ",");
                while (p != NULL) {
			int w = atoi(p);
			if (w < 1 || w > uwsgi.numproc) {
				uwsgi_log("invalid worker num: %d\n", w);
				exit(1);
			}
			uwsgi.workers[w].sockets_mask[i] = 1;
			uwsgi_log("mapped socket %d (%s) to worker %d\n", i, uwsgi.sockets[i].name, w);
                        p = strtok(NULL, ",");
                }
	
	}

	uwsgi.mypid = getpid();
	masterpid = uwsgi.mypid;

	if (uwsgi.cores > 1) {
		for (i = 0; i < uwsgi.numproc+1; i++) {
			uwsgi.core = (struct uwsgi_core **) mmap(NULL, sizeof(struct uwsgi_core *) * uwsgi.cores, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
			if (!uwsgi.core) {
				uwsgi_error("mmap()");
				exit(1);
			}
			memset(uwsgi.core, 0, sizeof(struct uwsgi_core *) * uwsgi.cores);

			for (j = 0; j < uwsgi.cores; j++) {
				uwsgi.core[j] = (struct uwsgi_core *) mmap(NULL, sizeof(struct uwsgi_core), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
				if (!uwsgi.core[j]) {
					uwsgi_error("mmap()");
					exit(1);
				}
				memset(uwsgi.core[j], 0, sizeof(struct uwsgi_core));
			}
		}
	}
	uwsgi.workers[0].pid = masterpid;

	/*

	   uwsgi.shared->hooks[0] = uwsgi_request_wsgi;
	   uwsgi.shared->after_hooks[0] = uwsgi_after_request_wsgi;

	   uwsgi.shared->hooks[UWSGI_MODIFIER_ADMIN_REQUEST] = uwsgi_request_admin;	//10
#ifdef UWSGI_SPOOLER
uwsgi.shared->hooks[UWSGI_MODIFIER_SPOOL_REQUEST] = uwsgi_request_spooler;	//17
#endif
uwsgi.shared->hooks[UWSGI_MODIFIER_EVAL] = uwsgi_request_eval;	//22
uwsgi.shared->hooks[UWSGI_MODIFIER_FASTFUNC] = uwsgi_request_fastfunc;	//26

uwsgi.shared->hooks[UWSGI_MODIFIER_MANAGE_PATH_INFO] = uwsgi_request_wsgi;	// 30
uwsgi.shared->after_hooks[UWSGI_MODIFIER_MANAGE_PATH_INFO] = uwsgi_after_request_wsgi;	// 30

uwsgi.shared->hooks[UWSGI_MODIFIER_MESSAGE_MARSHAL] = uwsgi_request_marshal;	//33
uwsgi.shared->hooks[UWSGI_MODIFIER_PING] = uwsgi_request_ping;	//100
*/

	uwsgi_log("*** Operational MODE: ");
	if (!uwsgi.numproc) {
		uwsgi_rawlog("no-workers");
	}
	else if (uwsgi.threads > 1) {
		if (uwsgi.numproc > 1) {
			uwsgi_rawlog("preforking+threaded");
		} else {
			uwsgi_rawlog("threaded");
		}
	}
#ifdef UWSGI_ASYNC
	else if (uwsgi.async > 1) {
		if (uwsgi.numproc > 1) {
			uwsgi_rawlog("preforking+async");
		} else {
			uwsgi_rawlog("async");
		}
	}
#endif
	else if (uwsgi.numproc > 1) {
		uwsgi_rawlog("preforking");
	} else {
		uwsgi_rawlog("single process");
	}

	uwsgi_rawlog(" ***\n");

	//init apps hook
	for (i = 0; i < 0xFF; i++) {
		if (uwsgi.p[i]->init_apps) {
			uwsgi.p[i]->init_apps();
		}
	}

	for (i = 0; i < uwsgi.gp_cnt; i++) {
		if (uwsgi.gp[i]->init_apps) {
			uwsgi.gp[i]->init_apps();
		}
	}

	/*parse xml for <app> tags */
#ifdef UWSGI_XML
	if (uwsgi.xml_round2 && uwsgi.xml_config != NULL) {
		uwsgi_xml_config(uwsgi.wsgi_req, 1, NULL);
	}
#endif

	for (i = 0; i < uwsgi.mounts_cnt; i++) {
		char *what = strchr(uwsgi.mounts[i], '=');
		if (what) {
			what[0] = 0;
			what++;
			uwsgi_log("mounting %s on %s\n", what, uwsgi.mounts[i]);
			for (j = 0; j < 0xFF; j++) {
                		if (uwsgi.p[j]->mount_app) {
                        		if (uwsgi.p[j]->mount_app(uwsgi.mounts[i], what) != -1) break;
                		}
        		}
			what--; what[0] = '=';
		} else {
			uwsgi_log("invalid mountpoint: %s\n", uwsgi.mounts[i]);
			exit(1);
		}
	}


	if (uwsgi.no_server) {
		uwsgi_log("no-server mode requested. Goodbye.\n");
		exit(0);
	}
	//is this a proxy only worker ?

	if (!uwsgi.master_process && uwsgi.numproc == 0) {
		exit(0);
	}
	if (!uwsgi.single_interpreter) {
		uwsgi_log("*** uWSGI is running in multiple interpreter mode ***\n");
	}

	if (uwsgi.master_process) {
		if (uwsgi.is_a_reload) {
			uwsgi_log("gracefully (RE)spawned uWSGI master process (pid: %d)\n", uwsgi.mypid);
		} else {
			uwsgi_log("spawned uWSGI master process (pid: %d)\n", uwsgi.mypid);
		}
	}



	// security in multiuser environment: allow only a subset of modifiers
	if (uwsgi.allowed_modifiers) {
		for (i = 0; i < 0xFF; i++) {
			if (!uwsgi_list_has_num(uwsgi.allowed_modifiers, i)) {
                        	uwsgi.p[i]->request = unconfigured_hook;
                        	uwsgi.p[i]->after_request = unconfigured_after_hook;
                	}
        	}
	}


#ifdef UWSGI_SPOOLER
	if (uwsgi.spool_dir != NULL && uwsgi.sockets_cnt > 0) {
		uwsgi.shared->spooler_pid = spooler_start();
	}
#endif

#ifdef UWSGI_ROUTING
	routing_setup();
#endif

	if (!uwsgi.master_process) {
		if (uwsgi.numproc == 1) {
			uwsgi_log("spawned uWSGI worker 1 (and the only) (pid: %d, cores: %d)\n", masterpid, uwsgi.cores);
		} else {
			uwsgi_log("spawned uWSGI worker 1 (pid: %d, cores: %d)\n", masterpid, uwsgi.cores);
		}
		uwsgi.workers[1].pid = masterpid;
		uwsgi.workers[1].id = 1;
		uwsgi.workers[1].last_spawn = time(NULL);
		uwsgi.workers[1].manage_next_request = 1;
		uwsgi.mywid = 1;
		gettimeofday(&last_respawn, NULL);
		uwsgi.respawn_delta = last_respawn.tv_sec;
	}
	else {
		// setup internal signalling system
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, uwsgi.shared->worker_signal_pipe)) {
                        uwsgi_error("socketpair()\n");
			exit(1);
                }

	}
	for (i = 2 - uwsgi.master_process; i < uwsgi.numproc + 1; i++) {
		pid = fork();
		if (pid == 0) {
			close(uwsgi.shared->worker_signal_pipe[0]);
			uwsgi.mypid = getpid();
			uwsgi.workers[i].pid = uwsgi.mypid;
			uwsgi.workers[i].id = i;
			uwsgi.workers[i].last_spawn = time(NULL);
			uwsgi.workers[i].manage_next_request = 1;
			uwsgi.mywid = i;
			break;
		} else if (pid < 1) {
			uwsgi_error("fork()");
			exit(1);
		} else {
			uwsgi_log("spawned uWSGI worker %d (pid: %d, cores: %d)\n", i, pid, uwsgi.cores);
			//close(uwsgi.workers[i].pipe[1]);
			gettimeofday(&last_respawn, NULL);
			uwsgi.respawn_delta = last_respawn.tv_sec;
		}
	}


	if (getpid() == masterpid && uwsgi.master_process == 1) {
		master_loop(argv, environ);
		//from now on the process is a real worker
	}

	for(i=0;i<uwsgi.sockets_cnt;i++) {
		if (uwsgi.workers[uwsgi.mywid].sockets_mask[i]) {
			// disable the socket for this worker
#ifdef UWSGI_DEBUG
			uwsgi_log("switching off socket %d (%d) on worker %d\n", i, uwsgi.sockets[i].fd, uwsgi.mywid);
#endif
			int fd = uwsgi.sockets[i].fd;
			close(fd);
			fd = open("/dev/null", O_RDONLY);
			if (fd < 0) {
				uwsgi_error_open("/dev/null");
				exit(1);
			}
			if (fd != uwsgi.sockets[i].fd) {
				if (dup2(fd, uwsgi.sockets[i].fd)) {
					uwsgi_error("dup2()");
					exit(1);
				}
				close(fd);
			}
			uwsgi.sockets_poll[i].fd = -1;
			uwsgi.sockets_poll[i].events = 0;
		}
	}

	if (uwsgi.cpu_affinity) {
#ifdef __linux__
		cpu_set_t cpuset;
		CPU_ZERO(&cpuset);
		int ncpu = sysconf(_SC_NPROCESSORS_ONLN);
		int base_cpu = (uwsgi.mywid-1)*uwsgi.cpu_affinity;
		if (base_cpu >= ncpu) {
			base_cpu = base_cpu % ncpu;
		}
		uwsgi_log("set cpu affinity for worker %d to", uwsgi.mywid);
		for(i=0;i<uwsgi.cpu_affinity;i++) {
			if (base_cpu >= ncpu) base_cpu = 0 ;
			CPU_SET(base_cpu, &cpuset);
			uwsgi_log(" %d", base_cpu);
			base_cpu++; 
		}	
		if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset)) {
			uwsgi_error("sched_setaffinity()");
		}
		uwsgi_log("\n");
#endif
	}

	if (uwsgi.worker_exec) {
		char *w_argv[2];
		w_argv[0] = uwsgi.worker_exec;
		w_argv[1] = NULL;

                uwsgi.sockets[0].arg &= (~O_NONBLOCK);
                if (fcntl(uwsgi.sockets[i].fd, F_SETFL, uwsgi.sockets[i].arg) < 0) {
                       	uwsgi_error("fcntl()");
                       	exit(1);
                }

		if (uwsgi.sockets[0].fd != 0) {
			if (dup2(uwsgi.sockets[0].fd, 0)) {
				uwsgi_error("dup2()");
			}
		}
		execvp(w_argv[0], w_argv);
		// never here
		uwsgi_error("execvp()");
		exit(1);
	}

	if (uwsgi.master_as_root) {
                uwsgi_as_root();
        }

	for (i = 0; i < 0xFF; i++) {
		if (uwsgi.p[i]->post_fork) {
			uwsgi.p[i]->post_fork();
		}
	}

	//postpone the queue initialization as kevent
	//do not pass kfd after fork()
#ifdef UWSGI_ASYNC
	if (uwsgi.async > 1) {
		uwsgi.async_queue = event_queue_init();
		if (uwsgi.async_queue < 0) {
			exit(1);
		}

		for(i=0;i<uwsgi.sockets_cnt;i++) {
			event_queue_add_fd_read(uwsgi.async_queue, uwsgi.sockets[i].fd);
		}
	}

	uwsgi.rb_async_timeouts = uwsgi_init_rb_timer();

        uwsgi.async_queue_unused = uwsgi_malloc(sizeof(struct wsgi_request*) * uwsgi.async);

        for(i=0;i<uwsgi.async;i++) {
                uwsgi.async_queue_unused[i] = uwsgi.wsgi_requests[i];
        }

        uwsgi.async_queue_unused_ptr = uwsgi.async-1;
#endif



	uwsgi.async_hvec = uwsgi_malloc(sizeof(struct iovec *) * uwsgi.cores);
	for (i = 0; i < uwsgi.cores; i++) {
		uwsgi.async_hvec[i] = uwsgi_malloc(sizeof(struct iovec) * uwsgi.vec_size);
	}

	if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0 && !uwsgi.master_process) {
		signal(SIGALRM, (void *) &harakiri);
	}
	uwsgi_unix_signal(SIGHUP, gracefully_kill);
	uwsgi_unix_signal(SIGINT, end_me);
	uwsgi_unix_signal(SIGTERM, reload_me);


	uwsgi_unix_signal(SIGUSR1, stats);

	signal(SIGUSR2, (void *) &what_i_am_doing);


	signal(SIGPIPE, (void *) &warn_pipe);

	//initialization done

	if (uwsgi.chdir2) {
		if (chdir(uwsgi.chdir2)) {
			uwsgi_error("chdir()");
			exit(1);
		}
	}


	//re - initialize wsgi_req(can be full of init_uwsgi_app data)
	for (i = 0; i < uwsgi.cores; i++) {
		memset(uwsgi.wsgi_requests[i], 0, sizeof(struct wsgi_request));
		uwsgi.wsgi_requests[i]->async_id = i;
	}


	// eventually remap plugins
	if (uwsgi.remap_modifier) {
		char *map = strtok(uwsgi.remap_modifier, ",");
		struct uwsgi_plugin *up_tmp;
                while (map != NULL) {
			char *colon = strchr(map, ':');
			if (colon) {
				colon[0] = 0;
				int rm_src = atoi(map);
				int rm_dst = atoi(colon+1);
				up_tmp = uwsgi.p[rm_dst] ;
				uwsgi.p[rm_dst] = uwsgi.p[rm_src]; 
				uwsgi.p[rm_src] = up_tmp ;
				// fix rpc
				for(i=0;i<uwsgi.shared->rpc_count;i++) {
					if (uwsgi.shared->rpc_table[i].modifier1 == rm_src) uwsgi.shared->rpc_table[i].modifier1 = rm_dst;
					else if (uwsgi.shared->rpc_table[i].modifier1 == rm_dst) uwsgi.shared->rpc_table[i].modifier1 = rm_src;
				}
			}	
                        map = strtok(NULL, ",");
                }
	}


	if (uwsgi.master_process) {
       		uwsgi.sockets_poll[uwsgi.sockets_cnt].fd = uwsgi.shared->worker_signal_pipe[1];
        	uwsgi.sockets_poll[uwsgi.sockets_cnt].events = POLLIN;
#ifdef UWSGI_ASYNC
		// add uwsgi signal fd to async queue
		if (uwsgi.async > 1) {
			event_queue_add_fd_read(uwsgi.async_queue, uwsgi.sockets_poll[uwsgi.sockets_cnt].fd);
		}
#endif
	}


	if (uwsgi.loop) {
		void (*u_loop) (void) = uwsgi_get_loop(uwsgi.loop);
		uwsgi_log("running %s loop %p\n", uwsgi.loop, u_loop);
		u_loop();
		uwsgi_log("done\n");
		goto end;
	} else {
		if (uwsgi.threads > 1) {
			pthread_attr_t pa;
			pthread_t *a_thread;
			int ret;

			ret = pthread_attr_init(&pa);
			if (ret) {
				uwsgi_log("pthread_attr_init() = %d\n", ret);
				exit(1);
			}
			ret = pthread_attr_setdetachstate(&pa, PTHREAD_CREATE_DETACHED);
			if (ret) {
				uwsgi_log("pthread_attr_setdetachstate() = %d\n", ret);
				exit(1);
			}
			if (pthread_key_create(&uwsgi.tur_key, NULL)) {
				uwsgi_error("pthread_key_create()");
				exit(1);
			}
			for (i = 1; i < uwsgi.threads; i++) {
				long j = i;
				a_thread = uwsgi_malloc(sizeof(pthread_t));
				pthread_create(a_thread, &pa, simple_loop, (void *) j);
			}
		}

		if (uwsgi.async < 2) {
			long y = 0;
			simple_loop((void *) y);
		} else {
			async_loop(NULL);
		}

	}

end:
	if (uwsgi.workers[uwsgi.mywid].manage_next_request == 0) {
		reload_me(0);
	} else {
		goodbye_cruel_world();
	}

	// never here
	return 0;
}

	static int manage_base_opt(int i, char *optarg) {

		char *p;
		struct uwsgi_static_map *usm;

		switch (i) {

		case 0:
			return 1;
#ifdef UWSGI_UDP
		case LONG_ARGS_CLUSTER_RELOAD:
			send_udp_message(98, optarg, "", 0);
			break;
		case LONG_ARGS_CLUSTER_LOG:
			uwsgi_stdin_sendto(optarg, 96, 0);
			break;
#endif
		case LONG_ARGS_VHOSTHOST:
			uwsgi.vhost = 1;
			uwsgi.vhost_host = 1;
			return 1;
		case LONG_ARGS_LOOP:
			uwsgi.loop = optarg;
			return 1;
		case LONG_ARGS_WORKER_EXEC:
			uwsgi.worker_exec = optarg;
			return 1;
		case LONG_ARGS_REMAP_MODIFIER:
			uwsgi.remap_modifier = optarg;
			return 1;
		case LONG_ARGS_ALLOWED_MODIFIERS:
			uwsgi.allowed_modifiers = optarg;
			return 1;
		case LONG_ARGS_PLUGINS:
			p = strtok(optarg, ",");
			while (p != NULL) {
#ifdef UWSGI_DEBUG
				uwsgi_debug("loading plugin %s\n", p);
#endif
				uwsgi_load_plugin(-1, p, NULL, 0);
				p = strtok(NULL, ",");
			}
			build_options();
			return 1;
		case LONG_ARGS_CHDIR:
			uwsgi.chdir = optarg;
			return 1;
		case LONG_ARGS_CHDIR2:
			uwsgi.chdir2 = optarg;
			return 1;
#ifdef UWSGI_LDAP
		case LONG_ARGS_LDAP:
			uwsgi.ldap = optarg;
			return 1;
		case LONG_ARGS_LDAP_SCHEMA:
			uwsgi_ldap_schema_dump();
			return 1;
		case LONG_ARGS_LDAP_SCHEMA_LDIF:
			uwsgi_ldap_schema_dump_ldif();
			return 1;
#endif
		case LONG_ARGS_MODE:
			uwsgi.mode = optarg;
			return 1;
		case LONG_ARGS_ENV:
			if (putenv(optarg)) {
				uwsgi_error("putenv()");
			}
			return 1;
#ifdef UWSGI_THREADING
		case LONG_ARGS_THREADS:
			uwsgi.threads = atoi(optarg);
			return 1;
#endif
#ifdef UWSGI_ASYNC
		case LONG_ARGS_ASYNC:
			uwsgi.async = atoi(optarg);
			return 1;
#endif
		case LONG_ARGS_LOGTO:
			logto(optarg);
			return 1;
		case LONG_ARGS_EMPEROR:
			uwsgi.emperor_dir = optarg;
			return 1;
		case LONG_ARGS_RELOAD_MERCY:
			uwsgi.reload_mercy = atoi(optarg);
			return 1;
		case LONG_ARGS_LOG_MASTER:
			uwsgi.log_master = 1;
			return 1;
		case LONG_ARGS_LOG_SYSLOG:
			log_syslog(optarg);
			uwsgi.log_syslog = 1;
			uwsgi.log_master = 1;
			uwsgi.master_process = 1;
			return 1;
		case LONG_ARGS_PRINT:
			uwsgi_log("%s\n", optarg);
			return 1;
		case LONG_ARGS_VERSION:
			fprintf(stdout, "uWSGI %s\n", UWSGI_VERSION);
			exit(0);
#ifdef UWSGI_SNMP
		case LONG_ARGS_SNMP:
			uwsgi.snmp = 1;
			if (optarg) {
				uwsgi.snmp_addr = optarg;
				uwsgi.master_process = 1;
			}
			return 1;
		case LONG_ARGS_SNMP_COMMUNITY:
			uwsgi.snmp = 1;
			uwsgi.snmp_community = optarg;
			return 1;
#endif
		case LONG_ARGS_PIDFILE:
			uwsgi.pidfile = optarg;
			return 1;
		case LONG_ARGS_PIDFILE2:
			uwsgi.pidfile2 = optarg;
			return 1;
#ifdef UWSGI_UDP
		case LONG_ARGS_UDP:
			uwsgi.udp_socket = optarg;
			uwsgi.master_process = 1;
			return 1;
#endif
#ifdef UWSGI_MULTICAST
		case LONG_ARGS_MULTICAST:
			uwsgi.multicast_group = optarg;
			uwsgi.master_process = 1;
			return 1;
		case LONG_ARGS_CLUSTER:
			uwsgi.cluster = optarg;
			uwsgi.master_process = 1;
			return 1;
		case LONG_ARGS_CLUSTER_NODES:
			uwsgi.cluster = optarg;
			uwsgi.cluster_nodes = 1;
			uwsgi.master_process = 1;
			return 1;
#endif
		case LONG_ARGS_CHROOT:
			uwsgi.chroot = optarg;
			return 1;
		case LONG_ARGS_GID:
			uwsgi.gid = atoi(optarg);
			if (!uwsgi.gid) {
				uwsgi.gidname = optarg;
			}
			return 1;
		case LONG_ARGS_UID:
			uwsgi.uid = atoi(optarg);
			if (!uwsgi.uid) {
				uwsgi.uidname = optarg;
			}
			return 1;
		case LONG_ARGS_BINARY_PATH:
			uwsgi.binary_path = optarg;
			return 1;
#ifdef UWSGI_ERLANG
		case LONG_ARGS_ERLANG:
			uwsgi.erlang_node = optarg;
			return 1;
		case LONG_ARGS_ERLANG_COOKIE:
			uwsgi.erlang_cookie = optarg;
			return 1;
#endif
		case LONG_ARGS_CHECK_STATIC:
			uwsgi.check_static = optarg;
			uwsgi.check_static_len = strlen(uwsgi.check_static);
			return 1;
		case LONG_ARGS_FILE_SERVE_MODE:
			if (!strcasecmp("x-sendfile", optarg)) {
				uwsgi.file_serve_mode = 2;
			}
			else if (!strcasecmp("xsendfile", optarg)) {
				uwsgi.file_serve_mode = 2;
			}
			else if (!strcasecmp("x-accel-redirect", optarg)) {
				uwsgi.file_serve_mode = 1;
			}
			else if (!strcasecmp("xaccelredirect", optarg)) {
				uwsgi.file_serve_mode = 1;
			}
			else if (!strcasecmp("nginx", optarg)) {
				uwsgi.file_serve_mode = 1;
			}
			return 1;
		case LONG_ARGS_STATIC_MAP:
			usm = uwsgi.static_maps;
			if (!usm) {
				usm = uwsgi_malloc(sizeof(struct uwsgi_static_map));
				uwsgi.static_maps = usm;
			}
			else {
				while(usm->next) {
					if (!usm->next) {
						usm->next = uwsgi_malloc(sizeof(struct uwsgi_static_map));
						usm = usm->next;
						break;
					}
				}
			}

			char *docroot = strchr(optarg, '=');
			if (!docroot) {
				uwsgi_log("invalid document root in static map\n");
				exit(1);
			}

			usm->mountpoint = optarg;
			usm->mountpoint_len = docroot-usm->mountpoint;

			usm->document_root = realpath(docroot+1, NULL);
			usm->document_root_len = strlen(usm->document_root);

			uwsgi_log("static-mapped %.*s to %.*s\n", usm->mountpoint_len, usm->mountpoint, usm->document_root_len, usm->document_root);

			usm->next = NULL;
			return 1;
		case LONG_ARGS_ATTACH_DAEMON:
			if (uwsgi.startup_daemons_cnt < MAX_DAEMONS) {
				uwsgi.startup_daemons[uwsgi.startup_daemons_cnt] = optarg;
				uwsgi.startup_daemons_cnt++;
			} else {
				uwsgi_log("you can specify at most %d --attach-daemons options\n", MAX_DAEMONS);
			}
			return 1;
		case LONG_ARGS_SUBSCRIBE_TO:
			if (uwsgi.subscriptions_cnt < MAX_SUBSCRIPTIONS) {
				uwsgi.subscriptions[uwsgi.subscriptions_cnt] = optarg;
				uwsgi.subscriptions_cnt++;
			} else {
				uwsgi_log("you can specify at most %d --attach-daemons options\n", MAX_SUBSCRIPTIONS);
			}
			return 1;
#ifdef __linux__
		case LONG_ARGS_CGROUP:
			uwsgi.cgroup = optarg;
			return 1;
		case LONG_ARGS_CGROUP_OPT:
			if (uwsgi.cgroup_opt_cnt < 63) {
				uwsgi.cgroup_opt[uwsgi.cgroup_opt_cnt] = optarg;
				uwsgi.cgroup_opt_cnt++;
			} else {
				uwsgi_log("you can specify at most 64 --cgroup_opt options\n");
			}
			return 1;
		case LONG_ARGS_LINUX_NS:
			uwsgi.ns = optarg;
			return 1;
		case LONG_ARGS_LINUX_NS_NET:
			uwsgi.ns_net = optarg;
			return 1;
#endif
		case LONG_ARGS_LIMIT_AS:
			uwsgi.rl.rlim_cur = (atoi(optarg)) * 1024 * 1024;
			uwsgi.rl.rlim_max = uwsgi.rl.rlim_cur;
			return 1;
		case LONG_ARGS_LIMIT_POST:
			uwsgi.limit_post = (int) strtol(optarg, NULL, 10);
			return 1;
		case LONG_ARGS_RELOAD_ON_AS:
			uwsgi.reload_on_as = atoi(optarg);
			return 1;
		case LONG_ARGS_RELOAD_ON_RSS:
			uwsgi.reload_on_rss = atoi(optarg);
			return 1;
		case LONG_ARGS_TOUCH_RELOAD:
			uwsgi.touch_reload = optarg;
			uwsgi.master_process = 1;
			return 1;
		case LONG_ARGS_PRIO:
			uwsgi.prio = (int) strtol(optarg, NULL, 10);
			return 1;
		case LONG_ARGS_CPU_AFFINITY:
			uwsgi.cpu_affinity = (int) strtol(optarg, NULL, 10);
			return 1;
		case LONG_ARGS_POST_BUFFERING:
			uwsgi.post_buffering = atoi(optarg);
			return 1;
		case LONG_ARGS_POST_BUFFERING_SIZE:
			uwsgi.post_buffering_bufsize = atoi(optarg);
			return 1;
		case LONG_ARGS_UPLOAD_PROGRESS:
			uwsgi.upload_progress = optarg;
			return 1;
#ifdef UWSGI_YAML
		case 'y':
			uwsgi.yaml = optarg;
			return 1;
#endif
#ifdef UWSGI_INI
		case LONG_ARGS_INI:
			uwsgi.ini = optarg;
			return 1;
#endif
		case LONG_ARGS_MAP_SOCKET:
			p = strchr(optarg, ':');
			if (!p) {
				uwsgi_log("invalid map-socket syntax, must be socketnum:workerN[,workerN...]\n");
				exit(1);
			}
			p[0] = 0;
			int sn = atoi(optarg);
			if (sn < 0 || sn >= MAX_SOCKETS) {
				uwsgi_log("invalid socket number in map-socket\n");
				exit(1);
			}
			uwsgi.map_socket[sn] = p+1;
			p[0] = ':';
			return 1;
		case LONG_ARGS_CHECK_INTERVAL:
			uwsgi.shared->options[UWSGI_OPTION_MASTER_INTERVAL] = atoi(optarg);
			return 1;
		case LONG_ARGS_CACHE:
			uwsgi.cache_max_items = atoi(optarg);
			return 1;
		case LONG_ARGS_CACHE_STORE:
			uwsgi.cache_store = optarg;
			uwsgi.master_process = 1;
			return 1;
		case LONG_ARGS_CACHE_STORE_SYNC:
			uwsgi.cache_store_sync = atoi(optarg);
			return 1;
		case LONG_ARGS_CACHE_BLOCKSIZE:
			uwsgi.cache_blocksize = atoi(optarg);
			return 1;
		case LONG_ARGS_QUEUE_STORE:
			uwsgi.queue_store = optarg;
			uwsgi.master_process = 1;
			return 1;
		case LONG_ARGS_QUEUE_STORE_SYNC:
			uwsgi.queue_store_sync = atoi(optarg);
			return 1;
		case LONG_ARGS_QUEUE:
			uwsgi.queue_size = atoi(optarg);
			return 1;
		case LONG_ARGS_QUEUE_BLOCKSIZE:
			uwsgi.queue_blocksize = atoi(optarg);
			return 1;
		case 'A':
			uwsgi.sharedareasize = atoi(optarg);
			return 1;
		case 'L':
			uwsgi.shared->options[UWSGI_OPTION_LOGGING] = 0;
			return 1;
		case LONG_ARGS_LOG_ZERO:
			uwsgi.shared->options[UWSGI_OPTION_LOG_ZERO] = 1;
			return 1;
		case LONG_ARGS_LOG_SLOW:
			uwsgi.shared->options[UWSGI_OPTION_LOG_SLOW] = atoi(optarg);
			return 1;
		case LONG_ARGS_LOG_4xx:
			uwsgi.shared->options[UWSGI_OPTION_LOG_4xx] = 1;
			return 1;
		case LONG_ARGS_LOG_5xx:
			uwsgi.shared->options[UWSGI_OPTION_LOG_5xx] = 1;
			return 1;
		case LONG_ARGS_LOG_BIG:
			uwsgi.shared->options[UWSGI_OPTION_LOG_BIG] = atoi(optarg);
			return 1;
		case LONG_ARGS_LOG_SENDFILE:
			uwsgi.shared->options[UWSGI_OPTION_LOG_SENDFILE] = 1;
			return 1;
		case LONG_ARGS_MOUNT:
			if (uwsgi.mounts_cnt < MAX_APPS) {
				uwsgi.mounts[uwsgi.mounts_cnt] = optarg;
				uwsgi.mounts_cnt++;
			} else {
				uwsgi_log("you can specify at most %d --mount options\n", MAX_APPS);
			}
			return 1;
#ifdef UWSGI_SPOOLER
		case 'Q':
			uwsgi.spool_dir = uwsgi_malloc(PATH_MAX);
			if (access(optarg, R_OK | W_OK | X_OK)) {
				uwsgi_error("[spooler directory] access()");
				exit(1);
			}
			if (!realpath(optarg, uwsgi.spool_dir)) {
				uwsgi_error("realpath()");
				exit(1);
			}
			uwsgi.master_process = 1;
			return 1;
#endif

		case 'd':
			if (!uwsgi.is_a_reload) {
				daemonize(optarg);
			}
			return 1;
		case 's':
			if (uwsgi.sockets_cnt < 8) {
				uwsgi.sockets[uwsgi.sockets_cnt].name = generate_socket_name(optarg);
				uwsgi.sockets_cnt++;
			} else {
				uwsgi_log("you can specify at most 8 --socket options\n");
			}
			return 1;
		case LONG_ARGS_SHARED_SOCKET:
			if (uwsgi.shared_sockets_cnt < MAX_SOCKETS) {
				uwsgi.shared_sockets[uwsgi.shared_sockets_cnt].name = generate_socket_name(optarg);
				uwsgi.shared_sockets_cnt++;
			} else {
				uwsgi_log("you can specify at most 8 --socket options\n");
			}
			return 1;
#ifdef UWSGI_XML
		case 'x':
			uwsgi.xml_config = optarg;
			return 1;
#endif
		case 'l':
			uwsgi.listen_queue = atoi(optarg);
			return 1;
		case 'v':
			uwsgi.max_vars = atoi(optarg);
			uwsgi.vec_size = 4 + 1 + (4 * uwsgi.max_vars);
			return 1;
		case 'p':
			if (!strcmp(optarg, "auto")) {
#ifndef __sun__
				struct rlimit rl;
				if (getrlimit(RLIMIT_NPROC, &rl)) {
					uwsgi_error("getrlimit()");
					uwsgi.numproc = 1;
				}
				else {
					if (rl.rlim_cur == RLIM_INFINITY || rl.rlim_cur > 64) {
						if (rl.rlim_max != RLIM_INFINITY && rl.rlim_max < 64) {
							uwsgi.numproc = rl.rlim_max;
						}
						else {
#ifdef _SC_NPROCESSORS_ONLN
							uwsgi.numproc = (sysconf(_SC_NPROCESSORS_ONLN))*2;	
#else
							uwsgi.numproc = 1;
#endif
						}
					}
					else {
						uwsgi.numproc = rl.rlim_cur;
					}
					if (uwsgi.numproc > 1) {
						uwsgi.numproc--;
						uwsgi.master_process = 1;
					}
				}
#else
				uwsgi.numproc = 4;
#endif
			}
			else {
				uwsgi.numproc = atoi(optarg);
			}
			return 1;
		case 'r':
			uwsgi.shared->options[UWSGI_OPTION_REAPER] = 1;
			return 1;
		case 'm':
			uwsgi.shared->options[UWSGI_OPTION_MEMORY_DEBUG] = 1;
			return 1;
		case 't':
			uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] = atoi(optarg);
			return 1;
		case 'b':
			uwsgi.buffer_size = atoi(optarg);
			return 1;
		case 'c':
			uwsgi.shared->options[UWSGI_OPTION_CGI_MODE] = 1;
			return 1;
		case 'a':
			uwsgi.abstract_socket = 1;
			return 1;
		case LONG_ARGS_LOG_DATE:
			uwsgi.logdate = 1;
			if (optarg) {
				uwsgi.log_strftime = optarg;
			}
			return 1;
		case 'C':
			uwsgi.chmod_socket = 1;
			if (optarg) {
				if (strlen(optarg) != 3) {
					uwsgi_log("invalid chmod value: %s\n", optarg);
					exit(1);
				}
				for (i = 0; i < 3; i++) {
					if (optarg[i] < '0' || optarg[i] > '7') {
						uwsgi_log("invalid chmod value: %s\n", optarg);
						exit(1);
					}
				}

				uwsgi.chmod_socket_value = (uwsgi.chmod_socket_value << 3) + (optarg[0] - '0');
				uwsgi.chmod_socket_value = (uwsgi.chmod_socket_value << 3) + (optarg[1] - '0');
				uwsgi.chmod_socket_value = (uwsgi.chmod_socket_value << 3) + (optarg[2] - '0');
			}
			return 1;
		case 'M':
			uwsgi.master_process = 1;
			return 1;
		case 'R':
			uwsgi.shared->options[UWSGI_OPTION_MAX_REQUESTS] = atoi(optarg);
			return 1;
		case 'z':
			if (atoi(optarg) > 0) {
				uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT] = atoi(optarg);
			}
			return 1;
		case 'T':
			uwsgi.has_threads = 1;
			uwsgi.shared->options[UWSGI_OPTION_THREADS] = 1;
			return 1;
		case 'i':
			uwsgi.single_interpreter = 1;
			return 1;
		case 'h':
			uwsgi_help();
/*
			fprintf(stdout, "Usage: %s [options...]\n\
\t-d|--daemonize <logfile|addr>\tdaemonize and log into <logfile> or udp <addr>\n", uwsgi.binary_path);
*/
			return 0;
		}

		return 0;
	}

	void manage_opt(int i, char *optarg) {

		int j;

		if (manage_base_opt(i, optarg)) {
			return;
		}

		for (j = 0; j < 0xFF; j++) {
			if (uwsgi.p[j]->manage_opt) {
				if (uwsgi.p[j]->manage_opt(i, optarg)) {
					return;
				}
			}
		}

		for (j = 0; j < uwsgi.gp_cnt; j++) {
			if (uwsgi.gp[j]->manage_opt) {
				if (uwsgi.gp[j]->manage_opt(i, optarg)) {
					return;
				}
			}
		}

		//never here
		exit(1);

	}

void uwsgi_cluster_simple_add_node(char *nodename, int workers, int type) {

	int i;
	struct uwsgi_cluster_node *ucn;
	char *tcp_port;

	if (strlen(nodename) > 100) {
		uwsgi_log("invalid cluster node name %s\n", nodename);
		return;
	}

	tcp_port = strchr(nodename, ':');
	if (tcp_port == NULL) {
		fprintf(stdout, "invalid cluster node name %s\n", nodename);
		return;
	}

	// first check for already present node
	for (i = 0; i < MAX_CLUSTER_NODES; i++) {
                ucn = &uwsgi.shared->nodes[i];
		if (ucn->name[0] != 0) {
			if (!strcmp(ucn->name, nodename)) {
				ucn->status = UWSGI_NODE_OK;			
				ucn->last_seen = time(NULL);
				return;
			}
		}
	}

	for (i = 0; i < MAX_CLUSTER_NODES; i++) {
		ucn = &uwsgi.shared->nodes[i];

		if (ucn->name[0] == 0) {
			memcpy(ucn->name, nodename, strlen(nodename) + 1);
			ucn->workers = workers;
			ucn->ucn_addr.sin_family = AF_INET;
			ucn->ucn_addr.sin_port = htons(atoi(tcp_port + 1));
			tcp_port[0] = 0;
			if (nodename[0] == 0) {
				ucn->ucn_addr.sin_addr.s_addr = INADDR_ANY;
			} else {
			uwsgi_log("%s\n", nodename);
				ucn->ucn_addr.sin_addr.s_addr = inet_addr(nodename);
			}

			ucn->type = type;
			// here memory can be freed, as it is allocated by uwsgi_concat2n
			if (type == CLUSTER_NODE_DYNAMIC) {
				free(nodename);
			}
			else {
				tcp_port[0] = ':';
			}
			ucn->last_seen = time(NULL);
			uwsgi_log("[uWSGI cluster] added node %s\n", ucn->name);
			return;
		}
	}

	uwsgi_log("unable to add node %s\n", nodename);
}

void uwsgi_cluster_add_node(struct uwsgi_cluster_node *nucn, int type) {

        int i;
        struct uwsgi_cluster_node *ucn;
        char *tcp_port;

	uwsgi_log("adding node\n");

        tcp_port = strchr(nucn->name, ':');
        if (tcp_port == NULL) {
                fprintf(stdout, "invalid cluster node name %s\n", nucn->name);
                return;
        }

        // first check for already present node
        for (i = 0; i < MAX_CLUSTER_NODES; i++) {
                ucn = &uwsgi.shared->nodes[i];
                if (ucn->name[0] != 0) {
                        if (!strcmp(ucn->name, nucn->name)) {
                                ucn->status = UWSGI_NODE_OK;
                                ucn->last_seen = time(NULL);
				// update requests
				ucn->requests = nucn->requests;
                                return;
                        }
                }
        }

        for (i = 0; i < MAX_CLUSTER_NODES; i++) {
                ucn = &uwsgi.shared->nodes[i];

                if (ucn->name[0] == 0) {
                        memcpy(ucn->name, nucn->name, strlen(nucn->name) + 1);
                        memcpy(ucn->nodename, nucn->nodename, strlen(nucn->nodename) + 1);
                        ucn->workers = nucn->workers;
                        ucn->ucn_addr.sin_family = AF_INET;
                        ucn->ucn_addr.sin_port = htons(atoi(tcp_port + 1));
                        tcp_port[0] = 0;
                        if (nucn->name[0] == 0) {
                                ucn->ucn_addr.sin_addr.s_addr = INADDR_ANY;
                        } else {
                        uwsgi_log("%s\n", nucn->name);
                                ucn->ucn_addr.sin_addr.s_addr = inet_addr(nucn->name);
                        }

                        ucn->type = type;
                        // here memory can be freed, as it is allocated by uwsgi_concat2n
                        if (type != CLUSTER_NODE_DYNAMIC) {
                                tcp_port[0] = ':';
                        }
                        ucn->last_seen = time(NULL);
			ucn->requests = nucn->requests;
                        uwsgi_log("[uWSGI cluster] added node %s\n", ucn->name);
                        return;
                }
        }

        uwsgi_log("unable to add node %s\n", nucn->name);
}



void build_options() {
		int i;
		struct option *lopt,
		*aopt;
		int opt_count = count_options(long_base_options);
		int short_opt_size = strlen(base_short_options);
		char *so_ptr;

		for (i = 0; i < 0xFF; i++) {
			if (uwsgi.p[i]->short_options) {
				short_opt_size += strlen(uwsgi.p[i]->short_options);
			}
		}

		for(i=0;i<uwsgi.gp_cnt;i++) {
			if (uwsgi.gp[i]->short_options) {
				short_opt_size += strlen(uwsgi.gp[i]->short_options);
			}
		}

		if (short_options) {
			free(short_options);
		}
		short_options = uwsgi_malloc(short_opt_size + 1);
		memcpy(short_options, base_short_options, strlen(base_short_options));
		so_ptr = short_options + strlen(base_short_options);

		for (i = 0; i < 0xFF; i++) {
			if (uwsgi.p[i]->short_options) {
				memcpy(so_ptr, uwsgi.p[i]->short_options, strlen(uwsgi.p[i]->short_options));
				so_ptr += strlen(uwsgi.p[i]->short_options);
			}
		}

		for (i = 0; i < uwsgi.gp_cnt; i++) {
			if (uwsgi.gp[i]->short_options) {
				memcpy(so_ptr, uwsgi.gp[i]->short_options, strlen(uwsgi.gp[i]->short_options));
				so_ptr += strlen(uwsgi.gp[i]->short_options);
			}
		}

		*so_ptr = 0;

		for (i = 0; i < 0xFF; i++) {
			if (uwsgi.p[i]->options) {
				opt_count += count_options(uwsgi.p[i]->options);
			}
		}

		for (i = 0; i < uwsgi.gp_cnt; i++) {
			if (uwsgi.gp[i]->options) {
				opt_count += count_options(uwsgi.gp[i]->options);
			}
		}

		if (uwsgi.long_options) {
			free(uwsgi.long_options);
		}
		uwsgi.long_options = uwsgi_malloc(sizeof(struct option) * (opt_count + 1));
		opt_count = 0;
		lopt = long_base_options;
		while ((aopt = lopt)) {
			if (!aopt->name)
				break;
			uwsgi.long_options[opt_count].name = aopt->name;
			uwsgi.long_options[opt_count].has_arg = aopt->has_arg;
			uwsgi.long_options[opt_count].flag = aopt->flag;
			uwsgi.long_options[opt_count].val = aopt->val;
			opt_count++;
			lopt++;
		}

		for (i = 0; i < 0xFF; i++) {
			lopt = uwsgi.p[i]->options;
			if (!lopt)
				continue;

			while ((aopt = lopt)) {
				if (!aopt->name)
					break;
				uwsgi.long_options[opt_count].name = aopt->name;
				uwsgi.long_options[opt_count].has_arg = aopt->has_arg;
				uwsgi.long_options[opt_count].flag = aopt->flag;
				uwsgi.long_options[opt_count].val = aopt->val;
				opt_count++;
				lopt++;
			}

		}

		for (i = 0; i < uwsgi.gp_cnt; i++) {
			lopt = uwsgi.gp[i]->options;
			if (!lopt)
				continue;

			while ((aopt = lopt)) {
				if (!aopt->name)
					break;
				uwsgi.long_options[opt_count].name = aopt->name;
				uwsgi.long_options[opt_count].has_arg = aopt->has_arg;
				uwsgi.long_options[opt_count].flag = aopt->flag;
				uwsgi.long_options[opt_count].val = aopt->val;
				opt_count++;
				lopt++;
			}

		}

		uwsgi.long_options[opt_count].name = 0;
		uwsgi.long_options[opt_count].has_arg = 0;
		uwsgi.long_options[opt_count].flag = 0;
		uwsgi.long_options[opt_count].val = 0;
}


void manage_string_opt(char *key, uint16_t keylen, char *val, uint16_t vallen, void *data) {

	// never free this value
	char *key2 = uwsgi_concat2n(key, keylen, "", 0);
	char *val2 = uwsgi_concat2n(val, vallen, "", 0);

	uwsgi_log("%s = %s\n", key2, val2);
	add_exported_option(key2, val2, 0);
}

#ifdef UWSGI_UDP
int uwsgi_cluster_add_me() {

	const char *key1 = "hostname";
	const char *key2 = "address";
	const char *key3 = "workers";
	const char *key4 = "requests";

	char *ptrbuf ;
	uint16_t ustrlen;
	char numproc[6];

	if (!uwsgi.sockets[0].name) {
		uwsgi_log("you need to specify at least a socket to start a uWSGI cluster\n");
		exit(1);
	}

	snprintf(numproc, 6, "%d", uwsgi.numproc);

	size_t len = 2 + strlen(key1) + 2 + strlen(uwsgi.hostname) + 2 + strlen(key2) + 2 + strlen(uwsgi.sockets[0].name) + 2 + strlen(key3) + 2 + strlen(numproc) + 2 + strlen(key4) + 2 + 1;
	char *buf = uwsgi_malloc( len );

	ptrbuf = buf;

	ustrlen = strlen(key1);
        *ptrbuf++ = (uint8_t) (ustrlen  & 0xff);
        *ptrbuf++ = (uint8_t) ((ustrlen >>8) & 0xff);
	memcpy(ptrbuf, key1, strlen(key1)); ptrbuf+=strlen(key1);

	ustrlen = strlen(uwsgi.hostname);
        *ptrbuf++ = (uint8_t) (ustrlen  & 0xff);
        *ptrbuf++ = (uint8_t) ((ustrlen >>8) & 0xff);
	memcpy(ptrbuf, uwsgi.hostname, strlen(uwsgi.hostname)); ptrbuf+=strlen(uwsgi.hostname);

	ustrlen = strlen(key2);
        *ptrbuf++ = (uint8_t) (ustrlen  & 0xff);
        *ptrbuf++ = (uint8_t) ((ustrlen >>8) & 0xff);
	memcpy(ptrbuf, key2, strlen(key2)); ptrbuf+=strlen(key2);

	ustrlen = strlen(uwsgi.sockets[0].name);
        *ptrbuf++ = (uint8_t) (ustrlen  & 0xff);
        *ptrbuf++ = (uint8_t) ((ustrlen >>8) & 0xff);
	memcpy(ptrbuf, uwsgi.sockets[0].name, strlen(uwsgi.sockets[0].name)); ptrbuf+=strlen(uwsgi.sockets[0].name);


	ustrlen = strlen(key3);
        *ptrbuf++ = (uint8_t) (ustrlen  & 0xff);
        *ptrbuf++ = (uint8_t) ((ustrlen >>8) & 0xff);
	memcpy(ptrbuf, key3, strlen(key3)); ptrbuf+=strlen(key3);

	ustrlen = strlen(numproc);
        *ptrbuf++ = (uint8_t) (ustrlen  & 0xff);
        *ptrbuf++ = (uint8_t) ((ustrlen >>8) & 0xff);
	memcpy(ptrbuf, numproc, strlen(numproc)); ptrbuf+=strlen(numproc);

	ustrlen = strlen(key4);
        *ptrbuf++ = (uint8_t) (ustrlen  & 0xff);
        *ptrbuf++ = (uint8_t) ((ustrlen >>8) & 0xff);
	memcpy(ptrbuf, key4, strlen(key4)); ptrbuf+=strlen(key4);

	ustrlen = 1;
        *ptrbuf++ = (uint8_t) (ustrlen  & 0xff);
        *ptrbuf++ = (uint8_t) ((ustrlen >>8) & 0xff);
	memcpy(ptrbuf, "0", 1); ptrbuf+=1;


	uwsgi_string_sendto(uwsgi.cluster_fd, 95, 0, (struct sockaddr *) &uwsgi.mc_cluster_addr, sizeof(uwsgi.mc_cluster_addr), buf, len);

	free(buf);

	uwsgi_log("add_me() successfull\n");

	return 0;
}

int uwsgi_cluster_join(char *name) {

	int fd ;
	char *cp;
	int broadcast = 0;


	if (name[0] == ':') {
		fd = bind_to_udp(name, 0, 1);
		broadcast = 1;
	}
	else {
		fd = bind_to_udp(name, 1, 0);
	}

	if (fd >= 0) {
		cp = strchr(name,':');
                cp[0] = 0;
                uwsgi.mc_cluster_addr.sin_family=AF_INET;
		if (broadcast) {
                	uwsgi.mc_cluster_addr.sin_addr.s_addr=INADDR_BROADCAST;
		}
		else {
                	uwsgi.mc_cluster_addr.sin_addr.s_addr=inet_addr(name);
		}
                uwsgi.mc_cluster_addr.sin_port=htons(atoi(cp+1));
                cp[0] = ':';


		// announce my presence to all the nodes
		uwsgi_string_sendto(fd, 73, 0, (struct sockaddr *) &uwsgi.mc_cluster_addr, sizeof(uwsgi.mc_cluster_addr), uwsgi.hostname, strlen(uwsgi.hostname));
	}
	else {
		exit(1);
	}

	
	return fd;

}

void uwsgi_stdin_sendto(char *socket_name, uint8_t modifier1, uint8_t modifier2) {

	char buf[4096];
	ssize_t rlen ;
	size_t delta = 4096;
	char *ptr = buf;

	rlen = read(0, ptr, delta);
	while(rlen > 0) {
		uwsgi_log("%.*s\n", rlen, ptr);
		ptr += rlen;
		delta-=rlen;
		if (delta <= 0) break;
		rlen = read(0, ptr, delta);
	}
	
	if (ptr > buf) {
		send_udp_message(modifier1, socket_name, buf, ptr-buf);
		uwsgi_log("sent string \"%.*s\" to cluster node %s", ptr-buf, buf, socket_name);
	}
	
}
#endif


char *uwsgi_cluster_best_node() {
	
	int i;
	int best_node = -1;
	struct uwsgi_cluster_node *ucn;

	for (i = 0; i < MAX_CLUSTER_NODES; i++) {
                ucn = &uwsgi.shared->nodes[i];
                if (ucn->name[0] != 0 && ucn->status == UWSGI_NODE_OK) {
			if (best_node == -1) {
				best_node = i;
			}
			else {
				if (ucn->last_choosen < uwsgi.shared->nodes[best_node].last_choosen) {
					best_node = i;
				}
			}
                }
        }

	if (best_node == -1) {
		return NULL;
	}

	uwsgi.shared->nodes[best_node].last_choosen = time(NULL);
	return uwsgi.shared->nodes[best_node].name;
}


struct uwsgi_help_item main_help[] = {

{"socket <name>", "path (or name) of UNIX/TCP socket to bind to"},
{"listen <num>", "set socket listen queue to <n> (default 100, maximum is system dependent)"},
{"socket-timeout <sec>", "set socket timeout to <sec> seconds (default 4 seconds)"},
{"buffer-size <n>", "set buffer size to <n> bytes"},
{"disable-logging", "disable request logging (only errors or server messages will be logged)"},
{"xmlconfig <path>", "path of xml config file"},
{"harakiri <sec>", "set harakiri timeout to <sec> seconds"},
{"harakiri-verbose", "report additional info during harakiri"},
{"processes <n>", "spawn <n> uwsgi worker processes"},
{"workers <n>", "spawn <n> uwsgi worker processes"},
{"max-vars <n>", "set maximum number of vars/headers to <n>"},
{"sharedarea <n>", "create a shared memory area of <n> pages"},
{"cgi-mode", "set cgi mode"},
{"chmod-socket[=NNN]", "chmod socket to 666 or NNN"},
{"chmod[=NNN]", "chmod socket to 666 or NNN"},
{"memory-report",  "enable memory usage report"},
{"single-interpreter", "single interpreter mode"},
{"abstract-socket", "set socket in the abstract namespace (Linux only)"},
{"enable-threads", "enable threads support"},
{"master", "enable master process manager"},
{"help", "this help"},
{"reaper", "process reaper (call waitpid(-1,...) after each request)"},
{"max-requests", "maximum number of requests for each worker"},
{"test", "test if uWSGI can import a module"},
{"spooler <dir>", "run the spooler on directory <dir>"},
{"pidfile <file>", "write the masterpid to <file>"},
{"chroot <dir>", "chroot to directory <dir> (only root)"},
{"gid <id/groupname>", "setgid to <id/groupname> (only root)"},
{"uid <id/username>", "setuid to <id/username> (only root)"},
{"chdir <dir>", "chdir to <dir> before app loading"},
{"chdir2 <dir>", "chdir to <dir> after module loading"},
{"no-server", "initialize the uWSGI server then exit. Useful for testing and using uwsgi embedded module"},
{"no-defer-accept", "disable the no-standard way to defer the accept() call (TCP_DEFER_ACCEPT, SO_ACCEPTFILTER...)"},
{"check-interval <sec>", "set the check interval (in seconds) of the master process"},
{"limit-as <MB>", "limit the address space of processes to MB megabytes"},
{"limit-post <bytes>", "limit HTTP content_length size to <bytes>"},
{"post-buffering <bytes>", "buffer HTTP POST request higher than <bytes> to disk"},
{"post-buffering-bufsize <b>", "set the buffer size to <b> bytes for post-buffering"},
{"prio <N>", "set process priority/nice to N"},
{"no-orphans", "automatically kill workers on master's dead"},
{"udp <ip:port>", "bind master process to udp socket on ip:port"},
{"multicast <group>", "set multicast group"},
{"snmp[=<addr>]", "enable SNMP support in the UDP server or bind it to <addr>"},
{"snmp-community <value>", "set SNMP community code to <value>"},
{"erlang <name|address>", "enable the Erlang server with node name <name@address>"},
{"erlang-cookie <cookie>", "set the erlang cookie to <cookie>"},
{"nagios", "do a nagios check"},
{"binary-path <bin-path>", "set the path for the next reload of uWSGI (needed for chroot environments)"},
{"proxy <socket>", "run the uwsgi proxy on socket <socket>"},
{"proxy-node <socket>", "add the node <socket> to the proxy"},
{"proxy-max-connections <n>", "set the max number of concurrent connections mnaged by the proxy"},
{"async <n>", "enable async mode with n core"},
{"threads <n>", "spawn <n> threads core"},
{"logto <logfile|addr>", "log to file/udp"},
{"logdate", "add timestamp to loglines"},
{"log-zero", "log requests with 0 response size"},
{"log-slow <t>", "log requests slower than <t> milliseconds"},
{"log-4xx", "log requests with status code 4xx"},
{"log-5xx", "log requests with status code 5xx"},
{"log-big <n>", "log requests bigger than <n> bytes"},
{"log-sendfile", "log sendfile() requests"},
{"ignore-script-name", "disable uWSGI management of SCRIPT_NAME"},
{"no-default-app", "do not fallback unknown SCRIPT_NAME requests"},
{"ini <inifile>", "path of ini config file"},
{"ldap <url>", "url of LDAP uWSGIConfig resource"},
{"ldap-schema", "dump uWSGIConfig LDAP schema"},
{"ldap-schema-ldif", "dump uWSGIConfig LDAP schema in LDIF format"},
{"grunt", "enable grunt workers"},
{"ugreen", "enable uGreen support"},
{"ugreen-stacksize <n>", "set uGreen stacksize to <n>"},
{"no-site", "do not import site.py on startup"},
{"vhost", "enable virtual hosting"},
{"vhost-host", "use the Host header as the key for virtual hosting"},
{"mount MOUNTPOINT=app", "add a new app under MOUNTPOINT"},
{"routing", "enable uWSGI advanced routing"},
{"http <addr>", "start embedded HTTP server on <addr>"},
{"http-only", "start only the embedded HTTP server"},
{"http-var KEY[=VALUE]", "add var KEY to uwsgi requests made by the embedded HTTP server"},
{"catch-exceptions", "print exceptions in the browser"},
{"mode", "set configuration mode"},
{"env KEY=VALUE", "set environment variable"},
{"vacuum", "clear the environment on exit (remove UNIX sockets and pidfiles)"},
{"ping <addr>", "ping a uWSGI server (returns 1 on failure 0 on success)"},
{"ping-timeout <n>", "set ping timeout to <n>"},
{"cgroup <group>", "run the server in <group> cgroup (Linux only)"},
{"cgroup-opt KEY=VAL", "set cgroup option (Linux only)"},
{"version", "print server version"},
{"attach-daemon <command>", "run <command> under the control of master process"},
{"daemonize <logfile|addr>", "daemonize and log into <logfile> or udp <addr>"},

{ 0, 0 },

};


void uwsgi_help(void) {

	struct uwsgi_help_item *uhi, *all_help;
	int max_size = 0;
	struct option *lopt;
	int found;
	char *space;
	char *tmp_option = NULL;
	int i;

	all_help = main_help;

	build_options();

	while( (uhi = all_help) ) {

		if (uhi->key == 0)
			break;

		if ((int)strlen(uhi->key) > max_size) {
			max_size = (int)strlen(uhi->key);
		}

		all_help++;
	}


	for (i = 0; i < 0xFF; i++) {
        	if (uwsgi.p[i]->help) {

			all_help = uwsgi.p[i]->help;
			while( (uhi = all_help) ) {
				if (uhi->key == 0) break;
				if ((int)strlen(uhi->key) > max_size)
					max_size = (int)strlen(uhi->key);
				all_help++;	
			}

                }
	}

        for (i = 0; i < uwsgi.gp_cnt; i++) {
        	if (uwsgi.gp[i]->help) {

			all_help = uwsgi.gp[i]->help ;
			while( (uhi = all_help) ) {
				if (uhi->key == 0) break;
				if ((int)strlen(uhi->key) > max_size)
					max_size = (int)strlen(uhi->key);
				all_help++;	
			}
			
                }
	}	

	fprintf(stdout, "Usage: %s [options...]\n", uwsgi.binary_path);

	lopt = uwsgi.long_options;

	max_size+=4;

        while(lopt->name) {

		found = 0;

		all_help = main_help;
		while( (uhi = all_help) ) {
			if (uhi->key == 0) break;

			tmp_option = uwsgi_concat2(uhi->key, "");
			space = strchr(tmp_option, ' ');
			if (!space) space = strstr(tmp_option, "[=");
			if (space) space[0] = 0;

			if (!strcmp(tmp_option, lopt->name)) {
				found = 1;
				break;
			}

			free(tmp_option);
			all_help++;
		}

		if (!found) {
			for (i = 0; i < 0xFF; i++) {
				if (uwsgi.p[i]->help) {
					all_help = uwsgi.p[i]->help;
					while( (uhi = all_help) ) {
						if (uhi->key == 0) break;
						tmp_option = uwsgi_concat2(uhi->key, "");
						space = strchr(tmp_option, ' ');
						if (!space) space = strstr(tmp_option, "[=");
						if (space) space[0] = 0;

						if (!strcmp(tmp_option, lopt->name)) {
							found = 1;
							break;
						}
	
						free(tmp_option);
						all_help++;
					}
				}
				if (found) break;
			}	
		}

		if (!found) {
			for (i = 0; i < uwsgi.gp_cnt; i++) {
				if (uwsgi.gp[i]->help) {
					all_help = uwsgi.gp[i]->help;
					while( (uhi = all_help) ) {
						if (uhi->key == 0) break;
						tmp_option = uwsgi_concat2(uhi->key, "");
						space = strchr(tmp_option, ' ');
						if (!space) space = strstr(tmp_option, "[=");
						if (space) space[0] = 0;

						if (!strcmp(tmp_option, lopt->name)) {
							found = 1;
							break;
						}
	
						free(tmp_option);
						all_help++;
					}
				}
				if (found) break;
			}	
		}


		if (found) {
			if (!lopt->flag && ( (lopt->val >= 'a' && lopt->val <= 'z') || (lopt->val >= 'A' && lopt->val <= 'Z'))) {
				fprintf(stdout, "    -%c|--%-*s %s\n", lopt->val,  max_size-3, uhi->key, uhi->value);
			}
			else {
				fprintf(stdout, "    --%-*s %s\n", max_size, uhi->key, uhi->value);
			}
			if (tmp_option) free(tmp_option);
		}
		else {
			fprintf(stdout, "    --%-*s *** UNDOCUMENTED OPTION ***\n", max_size, lopt->name);
		}
			
                lopt++;
        }

	exit(0);
}


