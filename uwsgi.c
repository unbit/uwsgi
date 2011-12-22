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

#if defined(__APPLE__) && defined(UWSGI_AS_SHARED_LIBRARY)
#include <crt_externs.h>
char **environ;
#else
extern char **environ;
#endif

static char *short_options = NULL;

static char *base_short_options = "s:S:p:t:x:d:l:v:b:mcaCTiMhrR:z:A:Q:Ly:";

UWSGI_DECLARE_EMBEDDED_PLUGINS;

static struct option long_base_options[] = {
	{"socket", required_argument, 0, 's'},
	{"uwsgi-socket", required_argument, 0, 's'},
	{"http-socket", required_argument, 0, LONG_ARGS_HTTP_SOCKET},
	{"fastcgi-socket", required_argument, 0, LONG_ARGS_FASTCGI_SOCKET},
	{"protocol", required_argument, 0, LONG_ARGS_PROTOCOL},
	{"socket-protocol", required_argument, 0, LONG_ARGS_SOCKET_PROTOCOL},
	{"shared-socket", required_argument, 0, LONG_ARGS_SHARED_SOCKET},
	{"processes", required_argument, 0, 'p'},
	{"workers", required_argument, 0, 'p'},
	{"harakiri", required_argument, 0, 't'},
	{"harakiri-verbose", no_argument, &uwsgi.harakiri_verbose, 1},
	{"spooler-harakiri", required_argument, 0, LONG_ARGS_SPOOLER_HARAKIRI},
	{"mule-harakiri", required_argument, 0, LONG_ARGS_MULE_HARAKIRI},
#ifdef UWSGI_XML
	{"xmlconfig", required_argument, 0, 'x'},
	{"xml", required_argument, 0, 'x'},
#endif
	{"set", required_argument, 0, 'S'},
	{"inherit", required_argument, 0, LONG_ARGS_INHERIT},
	{"daemonize", required_argument, 0, 'd'},
	{"stop", required_argument, 0, LONG_ARGS_STOP},
	{"reload", required_argument, 0, LONG_ARGS_RELOAD},
	{"pause", required_argument, 0, LONG_ARGS_PAUSE},
	{"suspend", required_argument, 0, LONG_ARGS_PAUSE},
	{"resume", required_argument, 0, LONG_ARGS_PAUSE},
	{"listen", required_argument, 0, 'l'},
	{"max-vars", required_argument, 0, 'v'},
	{"buffer-size", required_argument, 0, 'b'},
	{"memory-report", no_argument, 0, 'm'},
	{"profiler", required_argument, 0, LONG_ARGS_PROFILER},
	{"cgi-mode", no_argument, 0, 'c'},
	{"abstract-socket", no_argument, 0, 'a'},
	{"chmod-socket", optional_argument, 0, 'C'},
	{"chown-socket", required_argument, 0, LONG_ARGS_CHOWN_SOCKET},
	{"umask", required_argument, 0, LONG_ARGS_UMASK},
#ifdef __linux__
	{"freebind", no_argument, &uwsgi.freebind, 1},
#endif
	{"map-socket", required_argument, 0, LONG_ARGS_MAP_SOCKET},
	{"chmod", optional_argument, 0, 'C'},
#ifdef UWSGI_THREADING
	{"enable-threads", no_argument, 0, 'T'},
#endif
	{"auto-procname", no_argument, &uwsgi.auto_procname, 1},
	{"procname-prefix", required_argument, 0, LONG_ARGS_PROCNAME_PREFIX},
	{"procname-prefix-spaced", required_argument, 0, LONG_ARGS_PROCNAME_PREFIX_SP},
	{"procname-append", required_argument, 0, LONG_ARGS_PROCNAME_APPEND},
	{"procname", required_argument, 0, LONG_ARGS_PROCNAME},
	{"procname-master", required_argument, 0, LONG_ARGS_PROCNAME_MASTER},
	{"single-interpreter", no_argument, 0, 'i'},
	{"master", no_argument, 0, 'M'},
	{"emperor", required_argument, 0, LONG_ARGS_EMPEROR},
	{"emperor-tyrant", no_argument, &uwsgi.emperor_tyrant, 1},
	{"emperor-stats", required_argument, 0, LONG_ARGS_EMPEROR_STATS},
	{"emperor-stats-server", required_argument, 0, LONG_ARGS_EMPEROR_STATS},
	{"early-emperor", no_argument, &uwsgi.early_emperor, 1},
	{"emperor-broodlord", required_argument, 0, LONG_ARGS_EMPEROR_BROODLORD},
	{"emperor-amqp-vhost", required_argument, 0, LONG_ARGS_EMPEROR_AMQP_VHOST},
	{"emperor-amqp-username", required_argument, 0, LONG_ARGS_EMPEROR_AMQP_USERNAME},
	{"emperor-amqp-password", required_argument, 0, LONG_ARGS_EMPEROR_AMQP_PASSWORD},
	{"emperor-throttle", required_argument, 0, LONG_ARGS_EMPEROR_THROTTLE},
	{"vassals-inherit", required_argument, 0, LONG_ARGS_VASSALS_INHERIT},
	{"vassals-start-hook", required_argument, 0, LONG_ARGS_VASSALS_START_HOOK},
	{"vassals-stop-hook", required_argument, 0, LONG_ARGS_VASSALS_STOP_HOOK},
	{"vassal-sos-backlog", required_argument, 0, LONG_ARGS_VASSAL_SOS_BACKLOG},
	{"auto-snapshot", optional_argument, 0, LONG_ARGS_AUTO_SNAPSHOT},
	{"reload-mercy", required_argument, 0, LONG_ARGS_RELOAD_MERCY},
	{"exit-on-reload", no_argument, &uwsgi.exit_on_reload, 1},
	{"die-on-term", no_argument, &uwsgi.die_on_term, 1},
	{"help", no_argument, 0, 'h'},
	{"usage", no_argument, 0, 'h'},
	{"reaper", no_argument, 0, 'r'},
	{"max-requests", required_argument, 0, 'R'},
	{"socket-timeout", required_argument, 0, 'z'},
	{"no-fd-passing", no_argument, &uwsgi.no_fd_passing, 1},
	{"locks", required_argument, 0, LONG_ARGS_LOCKS},
	{"sharedarea", required_argument, 0, 'A'},
	{"cache", required_argument, 0, LONG_ARGS_CACHE},
	{"cache-blocksize", required_argument, 0, LONG_ARGS_CACHE_BLOCKSIZE},
	{"cache-store", required_argument, 0, LONG_ARGS_CACHE_STORE},
	{"cache-store-sync", required_argument, 0, LONG_ARGS_CACHE_STORE_SYNC},
	{"cache-server", required_argument, 0, LONG_ARGS_CACHE_SERVER},
	{"cache-server-threads", required_argument, 0, LONG_ARGS_CACHE_SERVER_THREADS},
	{"queue", required_argument, 0, LONG_ARGS_QUEUE},
	{"queue-blocksize", required_argument, 0, LONG_ARGS_QUEUE_BLOCKSIZE},
	{"queue-store", required_argument, 0, LONG_ARGS_QUEUE_STORE},
	{"queue-store-sync", required_argument, 0, LONG_ARGS_QUEUE_STORE_SYNC},
#ifdef UWSGI_SPOOLER
	{"spooler", required_argument, 0, 'Q'},
	{"spooler-ordered", no_argument, &uwsgi.spooler_ordered, 1},
	{"spooler-chdir", required_argument, 0, LONG_ARGS_SPOOLER_CHDIR},
#endif
	{"mule", optional_argument, 0, LONG_ARGS_MULE},
	{"mules", required_argument, 0, LONG_ARGS_MULES},
	{"signal", required_argument, 0, LONG_ARGS_SIGNAL},
	{"signal-bufsize", required_argument, 0, LONG_ARGS_SIGNAL_BUFSIZE},
	{"signals-bufsize", required_argument, 0, LONG_ARGS_SIGNAL_BUFSIZE},
	{"farm", required_argument, 0, LONG_ARGS_FARM},
	{"disable-logging", no_argument, 0, 'L'},

	{"pidfile", required_argument, 0, LONG_ARGS_PIDFILE},
	{"pidfile2", required_argument, 0, LONG_ARGS_PIDFILE2},
	{"chroot", required_argument, 0, LONG_ARGS_CHROOT},
	{"gid", required_argument, 0, LONG_ARGS_GID},
	{"uid", required_argument, 0, LONG_ARGS_UID},
#ifdef UWSGI_CAP
	{"cap", required_argument,0, LONG_ARGS_CAP},
#endif
#ifdef __linux__
	{"unshare", required_argument,0, LONG_ARGS_UNSHARE},
#endif
	{"exec-as-root", required_argument,0, LONG_ARGS_EXEC_AS_ROOT},
	{"exec-as-user", required_argument,0, LONG_ARGS_EXEC_AS_USER},
#ifdef UWSGI_INI
	{"ini", required_argument, 0, LONG_ARGS_INI},
#endif
#ifdef UWSGI_YAML
	{"yaml", required_argument, 0, 'y'},
	{"yml", required_argument, 0, 'y'},
#endif
#ifdef UWSGI_JSON
	{"json", required_argument, 0, 'j'},
#endif
#ifdef UWSGI_SQLITE3
	{"sqlite3", required_argument, 0, LONG_ARGS_SQLITE3},
	{"sqlite", required_argument, 0, LONG_ARGS_SQLITE3},
#endif
#ifdef UWSGI_ZEROMQ
	{"zeromq", required_argument, 0, LONG_ARGS_ZEROMQ},
	{"zmq", required_argument, 0, LONG_ARGS_ZEROMQ},
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
	{"evil-reload-on-as", required_argument, 0, LONG_ARGS_EVIL_RELOAD_ON_AS},
	{"evil-reload-on-rss", required_argument, 0, LONG_ARGS_EVIL_RELOAD_ON_RSS},
#ifdef __linux__
#ifdef MADV_MERGEABLE
	{"ksm", optional_argument, 0, LONG_ARGS_KSM},
#endif
#endif
	{"touch-reload", required_argument, 0, LONG_ARGS_TOUCH_RELOAD},
	{"propagate-touch", no_argument, &uwsgi.propagate_touch, 1},
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
	{"stats", required_argument, 0, LONG_ARGS_STATS},
	{"stats-server", required_argument, 0, LONG_ARGS_STATS},
#ifdef UWSGI_MULTICAST
	{"multicast", required_argument, 0, LONG_ARGS_MULTICAST},
	{"cluster", required_argument, 0, LONG_ARGS_CLUSTER},
	{"cluster-nodes", required_argument, 0, LONG_ARGS_CLUSTER_NODES},
	{"cluster-reload", required_argument, 0, LONG_ARGS_CLUSTER_RELOAD},
	{"cluster-log", required_argument, 0, LONG_ARGS_CLUSTER_LOG},
#endif
	{"subscribe-to", required_argument, 0, LONG_ARGS_SUBSCRIBE_TO},
	{"st", required_argument, 0, LONG_ARGS_SUBSCRIBE_TO},
	{"subscribe", required_argument, 0, LONG_ARGS_SUBSCRIBE_TO},
	{"subscribe-freq", required_argument, 0, LONG_ARGS_SUBSCRIBE_FREQ},
	{"subscription-tolerance", required_argument, 0, LONG_ARGS_SUBSCR_TOLERANCE},
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
	{"logto2", required_argument, 0, LONG_ARGS_LOGTO2},
	{"logfile-chown", no_argument, &uwsgi.logfile_chown, 1},
	{"logfile-chmod", required_argument, 0, LONG_ARGS_LOGFILE_CHMOD},
	{"log-syslog", optional_argument, 0, LONG_ARGS_LOG_SYSLOG},
	{"log-socket", required_argument, 0, LONG_ARGS_LOG_SOCKET},
	{"logger", required_argument, 0, LONG_ARGS_LOGGER},
	{"threaded-logger", no_argument, &uwsgi.threaded_logger, 1},
#ifdef UWSGI_ZEROMQ
	{"log-zeromq", required_argument, 0, LONG_ARGS_LOG_ZEROMQ},
#endif
	{"log-master", no_argument, 0, LONG_ARGS_LOG_MASTER},
	{"log-reopen", no_argument, &uwsgi.log_reopen, 1},
	{"log-truncate", no_argument, &uwsgi.log_truncate, 1},
	{"log-maxsize", required_argument, 0, LONG_ARGS_LOG_MAXSIZE},
	{"log-backupname", required_argument, 0, LONG_ARGS_LOG_BACKUPNAME},
	{"logdate", optional_argument, 0, LONG_ARGS_LOG_DATE},
	{"log-date", optional_argument, 0, LONG_ARGS_LOG_DATE},
	{"log-prefix", optional_argument, 0, LONG_ARGS_LOG_DATE},
	{"log-zero", no_argument, 0, LONG_ARGS_LOG_ZERO},
	{"log-slow", required_argument, 0, LONG_ARGS_LOG_SLOW},
	{"log-4xx", no_argument, 0, LONG_ARGS_LOG_4xx},
	{"log-5xx", no_argument, 0, LONG_ARGS_LOG_5xx},
	{"log-big", required_argument, 0, LONG_ARGS_LOG_BIG},
	{"log-sendfile", required_argument, 0, LONG_ARGS_LOG_SENDFILE},
	{"log-micros", no_argument, &uwsgi.log_micros, 1},
	{"log-x-forwarded-for", no_argument, &uwsgi.log_x_forwarded_for, 1},
	{"master-as-root", no_argument, &uwsgi.master_as_root, 1},
	{"chdir", required_argument, 0, LONG_ARGS_CHDIR},
	{"chdir2", required_argument, 0, LONG_ARGS_CHDIR2},
	{"lazy", no_argument, &uwsgi.lazy, 1},
	{"cheap", no_argument, &uwsgi.cheap, 1},
	{"cheaper", required_argument, 0, LONG_ARGS_CHEAPER},
	{"cheaper-step", required_argument, 0, LONG_ARGS_CHEAPER_STEP},
	{"idle", required_argument, 0, LONG_ARGS_IDLE},
	{"die-on-idle", no_argument, &uwsgi.die_on_idle, 1},
	{"mount", required_argument, 0, LONG_ARGS_MOUNT},
#ifdef UWSGI_PCRE
	{"regexp-mount", required_argument, 0, LONG_ARGS_REGEXP_MOUNT},
#endif
	{"grunt", no_argument, &uwsgi.grunt, 1},
	{"threads", required_argument, 0, LONG_ARGS_THREADS},
	{"threads-stacksize", required_argument, 0, LONG_ARGS_THREADS_STACKSIZE},
	{"thread-stacksize", required_argument, 0, LONG_ARGS_THREADS_STACKSIZE},
	{"threads-stack-size", required_argument, 0, LONG_ARGS_THREADS_STACKSIZE},
	{"thread-stack-size", required_argument, 0, LONG_ARGS_THREADS_STACKSIZE},
	{"vhost", no_argument, &uwsgi.vhost, 1},
	{"vhost-host", no_argument, 0, LONG_ARGS_VHOSTHOST},
#ifdef UWSGI_ROUTING
	{"routing", no_argument, &uwsgi.routing, 1},
#endif
	{"add-header", required_argument, 0, LONG_ARGS_ADD_HEADER},
	{"check-static", required_argument, 0, LONG_ARGS_CHECK_STATIC},
	{"static-check", required_argument, 0, LONG_ARGS_CHECK_STATIC},
	{"static-skip-ext", required_argument, 0, LONG_ARGS_STATIC_SKIP_EXT},
	{"static-map", required_argument, 0, LONG_ARGS_STATIC_MAP},
	{"static-index", required_argument, 0, LONG_ARGS_STATIC_INDEX},
	{"mimefile", required_argument, 0, LONG_ARGS_MIMEFILE},
	{"mime-file", required_argument, 0, LONG_ARGS_MIMEFILE},
	{"file-serve-mode", required_argument, 0, LONG_ARGS_FILE_SERVE_MODE},
	{"fileserve-mode", required_argument, 0, LONG_ARGS_FILE_SERVE_MODE},
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
	{"reuse-port", no_argument, &uwsgi.reuse_port, 1},
	{"zerg", required_argument, 0, LONG_ARGS_ZERG},
	{"zerg-server", required_argument, 0, LONG_ARGS_ZERG_SERVER},
	{"cron", required_argument, 0, LONG_ARGS_CRON},
	{"loop", required_argument, 0, LONG_ARGS_LOOP},
	{"worker-exec", required_argument, 0, LONG_ARGS_WORKER_EXEC},
	{"attach-daemon", required_argument, 0, LONG_ARGS_ATTACH_DAEMON},
	{"plugins", required_argument, 0, LONG_ARGS_PLUGINS},
	{"autoload", no_argument, &uwsgi.autoload, 1},
	{"allowed-modifiers", required_argument, 0, LONG_ARGS_ALLOWED_MODIFIERS},
	{"remap-modifier", required_argument, 0, LONG_ARGS_REMAP_MODIFIER},
	{"dump-options", no_argument, &uwsgi.dump_options, 1},
	{"show-config", no_argument, &uwsgi.show_config, 1},
	{"print", required_argument, 0, LONG_ARGS_PRINT},
	{"version", no_argument, 0, LONG_ARGS_VERSION},
	{0, 0, 0, 0}
};

void show_config(void) {
        int i;
                       fprintf(stdout, "\n;uWSGI instance configuration\n[uwsgi]\n");
                for (i = 0; i < uwsgi.exported_opts_cnt; i++) {
                        if (uwsgi.exported_opts[i]->value) {
                                fprintf(stdout, "%s = %s\n", uwsgi.exported_opts[i]->key, uwsgi.exported_opts[i]->value);
                        }
                        else {
                                fprintf(stdout, "%s = true\n", uwsgi.exported_opts[i]->key);
                        }
                }
                fprintf(stdout, ";end of configuration\n\n");

}

void uwsgi_apply_templates(void) {

	struct uwsgi_config_template *uct = uwsgi.config_templates;

        while (uct) {
		if (uct->applied)  {
			uct = uct->next;
			continue;
		}
                uwsgi_log("using %s as config template\n", uct->filename);
#ifdef UWSGI_XML
                if (!strcmp(uct->filename + strlen(uct->filename) - 4, ".xml")) {
                        uwsgi_xml_config(uct->filename, uwsgi.wsgi_req, 0, uwsgi.magic_table);
                }
#endif
#ifdef UWSGI_INI
                if (!strcmp(uct->filename + strlen(uct->filename) - 4, ".ini")) {
                        uwsgi_ini_config(uct->filename, uwsgi.magic_table);
                }
#endif
#ifdef UWSGI_YAML
                if (!strcmp(uct->filename + strlen(uct->filename) - 4, ".yml")) {
                        uwsgi_yaml_config(uct->filename, uwsgi.magic_table);
                }
                if (!strcmp(uct->filename + strlen(uct->filename) - 5, ".yaml")) {
                        uwsgi_yaml_config(uct->filename, uwsgi.magic_table);
                }
#endif
#ifdef UWSGI_JSON
                if (!strcmp(uct->filename + strlen(uct->filename) - 3, ".js")) {
                        uwsgi_json_config(uct->filename, uwsgi.magic_table);
                }
                if (!strcmp(uct->filename + strlen(uct->filename) - 5, ".json")) {
                        uwsgi_json_config(uct->filename, uwsgi.magic_table);
                }
#endif
#ifdef UWSGI_SQLITE3
                if (!strcmp(uct->filename + strlen(uct->filename) - 3, ".db")) {
                        uwsgi_sqlite3_config(uct->filename, uwsgi.magic_table);
                }
                if (!strcmp(uct->filename + strlen(uct->filename) - 7, ".sqlite")) {
                        uwsgi_sqlite3_config(uct->filename, uwsgi.magic_table);
                }
                if (!strcmp(uct->filename + strlen(uct->filename) - 8, ".sqlite3")) {
                        uwsgi_sqlite3_config(uct->filename, uwsgi.magic_table);
                }
#endif
		uct->applied = 1;
                uct = uct->next;
        }

}

void uwsgi_configure(void) {

	struct option *lopt;
	struct option *aopt;
	char *val;
	int i;
	int is_retry;
	int found;

	// plugins and inherit must be processed first (to have a consistent template system)

	for (i = 0; i < uwsgi.exported_opts_cnt; i++) {
		if (uwsgi.exported_opts[i]->configured)
                        continue;

		if (!strcmp("plugin", uwsgi.exported_opts[i]->key) || !strcmp("plugins", uwsgi.exported_opts[i]->key)) {
			manage_opt(LONG_ARGS_PLUGINS, uwsgi.exported_opts[i]->value);
			uwsgi.exported_opts[i]->configured = 1;
		}

		else if (!strcmp("inherit", uwsgi.exported_opts[i]->key)) {
			manage_opt(LONG_ARGS_INHERIT, uwsgi.exported_opts[i]->value);
			uwsgi.exported_opts[i]->configured = 1;
		}

		else if (!strcmp("vassals-inherit", uwsgi.exported_opts[i]->key)) {
			manage_opt(LONG_ARGS_VASSALS_INHERIT, uwsgi.exported_opts[i]->value);
			uwsgi.exported_opts[i]->configured = 1;
		}
	}

	// apply templates (again)
	uwsgi_apply_templates();

	for (i = 0; i < uwsgi.exported_opts_cnt; i++) {

#ifdef UWSGI_DEBUG
		uwsgi_log("i = %d %p\n", i, uwsgi.exported_opts[i]);
#endif

		if (uwsgi.exported_opts[i]->configured)
			continue;

		is_retry = 0;
	      retry:
		found = 0;
		lopt = uwsgi.long_options;;
		while ((aopt = lopt)) {
			if (!aopt->name)
				break;

			if (!strcmp(aopt->name, uwsgi.exported_opts[i]->key)) {
				found = 1;
				val = uwsgi.exported_opts[i]->value;

				if (aopt->flag)
					*aopt->flag = aopt->val;
				else if (val) {
					if (aopt->has_arg == optional_argument) {
						if (!strcasecmp("true", val) || !strcmp("1", val)) {
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

		if (!found && uwsgi.autoload && !is_retry) {
			DIR *pdir;
			struct dirent *dp;
			pdir = opendir(UWSGI_PLUGIN_DIR);
			if (!pdir) {
				uwsgi_fatal_error("opendir()");
			}
			while ((dp = readdir(pdir)) != NULL) {
				if (!strncmp("_plugin.so", dp->d_name + (strlen(dp->d_name) - 10), 19)) {
					if (uwsgi_load_plugin(-1, dp->d_name, uwsgi.exported_opts[i]->key, 2)) {
						uwsgi_log("option \"%s\" found in plugin %s\n", uwsgi.exported_opts[i]->key, dp->d_name);
						found = 1;
						break;
					}
				}
			}
			if (found) {
				build_options();
				closedir(pdir);
				// avoid deadly loops...
				is_retry = 1;
				goto retry;
			}
			closedir(pdir);
		}
	}

}

void config_magic_table_fill(char *filename, char **magic_table) {

	char *tmp = NULL;

	magic_table['o'] = filename;
	if (filename[0] == '/') {
		magic_table['p'] = filename;
	}
	else {
		magic_table['p'] = uwsgi_concat3(uwsgi.cwd, "/", filename);
	}
	magic_table['s'] = uwsgi_get_last_char(magic_table['p'], '/') + 1;
	magic_table['d'] = uwsgi_concat2n(magic_table['p'], magic_table['s'] - magic_table['p'], "", 0);
	if (magic_table['d'][strlen(magic_table['d'])-1] == '/') {
		tmp = magic_table['d'] + (strlen(magic_table['d']) -1) ;
#ifdef UWSGI_DEBUG
		uwsgi_log("tmp = %c\n", *tmp);
#endif
		*tmp = 0;
	}
	if (uwsgi_get_last_char(magic_table['d'], '/'))
		magic_table['c'] = uwsgi_get_last_char(magic_table['d'], '/') + 1;

	if (tmp) *tmp = '/';

	if (uwsgi_get_last_char(filename, '.'))
		magic_table['e'] = uwsgi_get_last_char(filename, '.') + 1;
	if (uwsgi_get_last_char(magic_table['s'], '.'))
		magic_table['n'] = uwsgi_concat2n(magic_table['s'], uwsgi_get_last_char(magic_table['s'], '.') - magic_table['s'], "", 0);
}

int find_worker_id(pid_t pid) {
	int i;
	for (i = 1; i <= uwsgi.numproc; i++) {
		if (uwsgi.workers[i].pid == pid)
			return i;
	}

	return -1;
}


void warn_pipe() {
	struct wsgi_request *wsgi_req = current_wsgi_req();

	if (uwsgi.threads < 2 && wsgi_req->uri_len > 0) {
		uwsgi_log("SIGPIPE: writing to a closed pipe/socket/fd (probably the client disconnected) on request %.*s (ip %.*s) !!!\n", wsgi_req->uri_len, wsgi_req->uri, wsgi_req->remote_addr_len, wsgi_req->remote_addr);
	}
	else {
		uwsgi_log("SIGPIPE: writing to a closed pipe/socket/fd (probably the client disconnected) !!!\n");
	}
}

#ifdef UWSGI_THREADING
// in threading mode we need to use the cancel pthread subsystem
void wait_for_threads() {
	int i, ret;

	pthread_mutex_lock(&uwsgi.six_feet_under_lock);
	for (i = 0; i < uwsgi.threads; i++) {
		if (!pthread_equal(uwsgi.core[i]->thread_id, pthread_self())) {
			pthread_cancel(uwsgi.core[i]->thread_id);
		}
	}

	// wait for thread termination
	for (i = 0; i < uwsgi.threads; i++) {
		if (!pthread_equal(uwsgi.core[i]->thread_id, pthread_self())) {
			ret = pthread_join(uwsgi.core[i]->thread_id, NULL);
			if (ret) {
				uwsgi_log("pthread_join() = %d\n", ret);
			}
		}
	}

	pthread_mutex_unlock(&uwsgi.six_feet_under_lock);
}
#endif


void gracefully_kill(int signum) {
	struct wsgi_request *wsgi_req = current_wsgi_req();

	uwsgi_log("Gracefully killing worker %d (pid: %d)...\n", uwsgi.mywid, uwsgi.mypid);
	uwsgi.workers[uwsgi.mywid].manage_next_request = 0;
#ifdef UWSGI_THREADING
	if (uwsgi.threads > 1) {
		wait_for_threads();
		if (!uwsgi.core[wsgi_req->async_id]->in_request) {
			exit(UWSGI_RELOAD_CODE);
		}
		return;
		// never here
	}
#endif

	// still not found a way to gracefully reload in async mode
	if (uwsgi.async > 1) {
		exit(UWSGI_RELOAD_CODE);
	}

	if (!uwsgi.core[0]->in_request) {
		exit(UWSGI_RELOAD_CODE);
	}
}

void end_me(int signum) {
	exit(UWSGI_END_CODE);
}


void goodbye_cruel_world() {

#ifdef UWSGI_THREADING
	if (uwsgi.threads > 1 && !uwsgi.to_hell) {
		wait_for_threads();
	}
#endif

	uwsgi.workers[uwsgi.mywid].manage_next_request = 0;
	uwsgi_log("...The work of process %d is done. Seeya!\n", getpid());
	exit(0);
}

void kill_them_all(int signum) {
	int i;
	uwsgi.to_hell = 1;

	if (uwsgi.reload_mercy > 0) {
                uwsgi.master_mercy = time(NULL) + uwsgi.reload_mercy;
        }
	else {
		uwsgi.master_mercy = time(NULL) + 5;
	}

	uwsgi_log("SIGINT/SIGQUIT received...killing workers...\n");

	// unsubscribe if needed
	struct uwsgi_string_list *subscriptions = uwsgi.subscriptions;
        while(subscriptions) {
                uwsgi_subscribe(subscriptions->value, 1);
                subscriptions = subscriptions->next;
        }


	for (i = 1; i <= uwsgi.numproc; i++) {
		if (uwsgi.workers[i].pid > 0)
			kill(uwsgi.workers[i].pid, SIGINT);
	}

#ifdef UWSGI_SPOOLER
	if (uwsgi.spool_dir && uwsgi.shared->spooler_pid > 0) {
		kill(uwsgi.shared->spooler_pid, SIGKILL);
		uwsgi_log("killing the spooler with pid %d\n", uwsgi.shared->spooler_pid);
	}

#endif

	if (uwsgi.emperor_pid >= 0) {
		kill(uwsgi.emperor_pid, SIGKILL);
		waitpid(uwsgi.emperor_pid, &i, 0);
		uwsgi_log("killing the emperor with pid %d\n", uwsgi.emperor_pid);
	}


	struct uwsgi_daemon *ud = uwsgi.daemons;
	while(ud) {
		if (ud->pid > 0)
			kill(-ud->pid, SIGKILL);
		ud = ud->next;
	}

	for (i = 0; i < uwsgi.gateways_cnt; i++) {
		if (uwsgi.gateways[i].pid > 0)
			kill(uwsgi.gateways[i].pid, SIGKILL);
	}

	for (i = 0; i < uwsgi.mules_cnt; i++) {
		if (uwsgi.mules[i].pid > 0)
			kill(uwsgi.mules[i].pid, SIGKILL);
	}

}

void grace_them_all(int signum) {
	int i;
	int waitpid_status;

	if (uwsgi.to_heaven == 1 || uwsgi.to_outworld == 1 || uwsgi.lazy_respawned > 0) return;

	if (!uwsgi.lazy)
		uwsgi.to_heaven = 1;
	else uwsgi.to_outworld = 1;

	if (uwsgi.reload_mercy > 0) {
		uwsgi.master_mercy = time(NULL) + uwsgi.reload_mercy;
	}
	else {
		// wait max 60 seconds for graceful reload
		uwsgi.master_mercy = time(NULL) + 60;
	}

#ifdef UWSGI_SPOOLER
	if (uwsgi.spool_dir && uwsgi.shared->spooler_pid > 0) {
		kill(uwsgi.shared->spooler_pid, SIGKILL);
		uwsgi_log("killing the spooler with pid %d\n", uwsgi.shared->spooler_pid);
	}
#endif

	if (uwsgi.emperor_pid >= 0) {
		kill(uwsgi.emperor_pid, SIGKILL);
		waitpid(uwsgi.emperor_pid, &i, 0);
		uwsgi_log("killing the emperor with pid %d\n", uwsgi.emperor_pid);
	}

	struct uwsgi_daemon *ud = uwsgi.daemons;
        while(ud) {
                if (ud->pid > 0)
                        kill(-ud->pid, SIGKILL);
                ud = ud->next;
        }

	for (i = 0; i < uwsgi.gateways_cnt; i++) {
		if (uwsgi.gateways[i].pid > 0)
			kill(uwsgi.gateways[i].pid, SIGKILL);
	}

	for (i = 0; i < uwsgi.mules_cnt; i++) {
		if (uwsgi.mules[i].pid > 0)
			kill(uwsgi.mules[i].pid, SIGKILL);
	}


	uwsgi_log("...gracefully killing workers...\n");

	// unsubscribe if needed
	struct uwsgi_string_list *subscriptions = uwsgi.subscriptions;
        while(subscriptions) {
                uwsgi_subscribe(subscriptions->value, 1);
                subscriptions = subscriptions->next;
        }

	for (i = 1; i <= uwsgi.numproc; i++) {
		if (uwsgi.auto_snapshot) {
			if (uwsgi.workers[i].snapshot > 0) {
				kill(uwsgi.workers[i].snapshot, SIGKILL);
				if (waitpid(uwsgi.workers[i].snapshot, &waitpid_status, 0) < 0) {
					uwsgi_error("waitpid()");
				}
			}
			if (uwsgi.workers[i].pid > 0) {
				if (uwsgi.auto_snapshot > 0 && i > uwsgi.auto_snapshot) {
					uwsgi.workers[i].snapshot = 0;
					kill(uwsgi.workers[i].pid, SIGHUP);
				}
				else {
					uwsgi.workers[i].snapshot = uwsgi.workers[i].pid;
					kill(uwsgi.workers[i].pid, SIGURG);
				}
			}
		}
		else if (uwsgi.workers[i].pid > 0) {
			if (uwsgi.lazy) uwsgi.workers[i].destroy = 1;
			kill(uwsgi.workers[i].pid, SIGHUP);
		}
	}

	if (uwsgi.auto_snapshot) {
		uwsgi.respawn_workers = 1;
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

void reap_them_all(int signum) {
	int i;

	// avoid reace condition in lazy mode
	if (uwsgi.to_outworld == 1 || uwsgi.lazy_respawned > 0) return;

	if (!uwsgi.lazy)
		uwsgi.to_heaven = 1;
	else uwsgi.to_outworld = 1;

	struct uwsgi_daemon *ud = uwsgi.daemons;
        while(ud) {
                if (ud->pid > 0)
                        kill(-ud->pid, SIGKILL);
                ud = ud->next;
        }

	for (i = 0; i < uwsgi.gateways_cnt; i++) {
		if (uwsgi.gateways[i].pid > 0)
			kill(uwsgi.gateways[i].pid, SIGKILL);
	}

	for (i = 0; i < uwsgi.mules_cnt; i++) {
		if (!uwsgi.mules) break;
		if (uwsgi.mules[i].pid > 0)
			kill(uwsgi.mules[i].pid, SIGKILL);
	}

	if (uwsgi.emperor_pid >= 0) {
		kill(uwsgi.emperor_pid, SIGKILL);
		waitpid(uwsgi.emperor_pid, &i, 0);
		uwsgi_log("killing the emperor with pid %d\n", uwsgi.emperor_pid);
	}

	if (!uwsgi.workers)
		return;

	uwsgi_log("...brutally killing workers...\n");

	// unsubscribe if needed
	struct uwsgi_string_list *subscriptions = uwsgi.subscriptions;
        while(subscriptions) {
                uwsgi_subscribe(subscriptions->value, 1);
                subscriptions = subscriptions->next;
        }

	for (i = 1; i <= uwsgi.numproc; i++) {
		if (uwsgi.workers[i].pid > 0)
			kill(uwsgi.workers[i].pid, SIGTERM);
	}
}

void harakiri() {

	uwsgi_log("\nF*CK !!! i must kill myself (pid: %d app_id: %d)...\n", uwsgi.mypid, uwsgi.wsgi_req->app_id);

	if (!uwsgi.master_process) {
		uwsgi_log("*** if you want your workers to be automatically respawned consider enabling the uWSGI master process ***\n");
	}
	exit(0);
}

void snapshot_me(int signum) {
	// wakeup !!!
	if (uwsgi.snapshot) {
		uwsgi.snapshot = 0;
		return;
	}

	uwsgi.workers[uwsgi.mywid].manage_next_request = 0;
#ifdef UWSGI_THREADING
	if (uwsgi.threads > 1) {
		wait_for_threads();
	}
#endif
	uwsgi.snapshot = 1;
	uwsgi_log("[snapshot] process %d taken\n", (int) getpid());
}

void stats(int signum) {
	//fix this for better logging(this cause races)
	struct uwsgi_app *ua = NULL;
	int i, j;

	if (uwsgi.mywid == 0) {
		show_config();
		uwsgi_log("\tworkers total requests: %llu\n", uwsgi.workers[0].requests);
		uwsgi_log("-----------------\n");
		for(j=1;j<=uwsgi.numproc;j++) {
			for (i = 0; i < uwsgi.workers[j].apps_cnt; i++) {
				ua = &uwsgi.workers[j].apps[i];
				if (ua) {
					uwsgi_log("\tworker %d app %d [%.*s] requests: %d exceptions: %d\n", j, i, ua->mountpoint_len, ua->mountpoint, ua->requests, ua->exceptions);
				}
			}
			uwsgi_log("-----------------\n");
		}
	}
	else {
		uwsgi_log("worker %d total requests: %llu\n", uwsgi.mywid, uwsgi.workers[0].requests);
		for (i = 0; i < uwsgi.workers[uwsgi.mywid].apps_cnt; i++) {
			ua = &uwsgi.workers[uwsgi.mywid].apps[i];
			if (ua) {
				uwsgi_log("\tapp %d [%.*s] requests: %d exceptions: %d\n", i, ua->mountpoint_len, ua->mountpoint, ua->requests, ua->exceptions);
			}
		}
		uwsgi_log("-----------------\n");
	}
	uwsgi_log("\n");
}

void what_i_am_doing() {

	struct wsgi_request *wsgi_req;
	int i;

	if (uwsgi.cores > 1) {
		for (i = 0; i < uwsgi.cores; i++) {
			wsgi_req = uwsgi.wsgi_requests[i];
			if (wsgi_req->uri_len > 0) {
				if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0 && uwsgi.workers[uwsgi.mywid].harakiri < time(NULL)) {
					uwsgi_log("HARAKIRI: --- uWSGI worker %d core %d (pid: %d) WAS managing request %.*s since %.*s ---\n", (int) uwsgi.mywid, i, (int) uwsgi.mypid, wsgi_req->uri_len, wsgi_req->uri, 24, ctime((const time_t *) &wsgi_req->start_of_request.tv_sec));
				}
				else {
					uwsgi_log("SIGUSR2: --- uWSGI worker %d core %d (pid: %d) is managing request %.*s since %.*s ---\n", (int) uwsgi.mywid, i, (int) uwsgi.mypid, wsgi_req->uri_len, wsgi_req->uri, 24, ctime((const time_t *) &wsgi_req->start_of_request.tv_sec));
				}
			}
		}
	}
	else {
		wsgi_req = uwsgi.wsgi_requests[0];
		if (wsgi_req->uri_len > 0) {
			if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0 && uwsgi.workers[uwsgi.mywid].harakiri < time(NULL)) {
				uwsgi_log("HARAKIRI: --- uWSGI worker %d (pid: %d) WAS managing request %.*s since %.*s ---\n", (int) uwsgi.mywid, (int) uwsgi.mypid, wsgi_req->uri_len, wsgi_req->uri, 24, ctime((const time_t *) &wsgi_req->start_of_request.tv_sec));
			}
			else {
				uwsgi_log("SIGUSR2: --- uWSGI worker %d (pid: %d) is managing request %.*s since %.*s ---\n", (int) uwsgi.mywid, (int) uwsgi.mypid, wsgi_req->uri_len, wsgi_req->uri, 24, ctime((const time_t *) &wsgi_req->start_of_request.tv_sec));
			}
		}
		else if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0 && uwsgi.workers[uwsgi.mywid].harakiri < time(NULL) && uwsgi.workers[uwsgi.mywid].sig) {
			uwsgi_log("HARAKIRI: --- uWSGI worker %d (pid: %d) WAS handling signal %d ---\n", (int) uwsgi.mywid, (int) uwsgi.mypid, uwsgi.workers[uwsgi.mywid].signum);
		}
	}
}


pid_t masterpid;
struct timeval last_respawn;


int unconfigured_hook(struct wsgi_request *wsgi_req) {
	uwsgi_log("-- unavailable modifier requested: %d --\n", wsgi_req->uh.modifier1);
	return -1;
}

static void unconfigured_after_hook(struct wsgi_request *wsgi_req) {
	return;
}

struct uwsgi_plugin unconfigured_plugin = {

	.name = "unconfigured",
	.request = unconfigured_hook,
	.after_request = unconfigured_after_hook,
};

static void vacuum(void) {

	struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;

	if (uwsgi.vacuum) {
		if (getpid() == masterpid) {
			if (chdir(uwsgi.cwd)) {
				uwsgi_error("chdir()");
			}
			if (uwsgi.pidfile && !uwsgi.uid) {
				if (unlink(uwsgi.pidfile)) {
					uwsgi_error("unlink()");
				}
				else {
					uwsgi_log("VACUUM: pidfile removed.\n");
				}
			}
			if (uwsgi.pidfile2) {
				if (unlink(uwsgi.pidfile2)) {
					uwsgi_error("unlink()");
				}
				else {
					uwsgi_log("VACUUM: pidfile2 removed.\n");
				}
			}
			if (uwsgi.chdir) {
				if (chdir(uwsgi.chdir)) {
					uwsgi_error("chdir()");
				}
			}
			while (uwsgi_sock) {
				if (uwsgi_sock->family == AF_UNIX) {
					if (unlink(uwsgi_sock->name)) {
						uwsgi_error("unlink()");
					}
					else {
						uwsgi_log("VACUUM: unix socket %s removed.\n", uwsgi_sock->name);
					}
				}
				uwsgi_sock = uwsgi_sock->next;
			}
		}
	}
}

void signal_pidfile(int sig, char *filename) {

	int size = 0;

	char *buffer = uwsgi_open_and_read(filename, &size, 1, NULL);

	if (size > 0) {
		if (kill((pid_t) atoi(buffer), sig)) {
			uwsgi_error("kill()");
		}
	}
	else {
		uwsgi_log("error: invalid pidfile\n");
	}
}

static void uwsgi_command_signal(char *opt) {

	int tmp_signal;
	char *colon = strchr(opt, ',');
	if (!colon) {
		uwsgi_log("invalid syntax for signal, must be addr,signal\n");
		exit(1);
	}

	colon[0] = 0;
	tmp_signal = atoi(colon+1);
	
	if (tmp_signal < 0 || tmp_signal > 255) {
		uwsgi_log("invalid signal number\n");
		exit(3);
	}

	uint8_t uwsgi_signal = tmp_signal;
	int ret = uwsgi_remote_signal_send(opt, uwsgi_signal);

	if (ret < 0) {
		uwsgi_log("unable to deliver signal %d to node %s\n", uwsgi_signal, opt);
		exit(1);
	}

	if (ret == 0) {
		uwsgi_log("node %s rejected signal %d\n", opt, uwsgi_signal);
		exit(2);
	}

	uwsgi_log("signal %d delivered to node %s\n", uwsgi_signal, opt);
	exit(0);
}

void fixup_argv_and_environ(int argc, char **argv, char **environ) {


	uwsgi.orig_argv = argv;
	uwsgi.argv = argv;
	uwsgi.argc = argc;
	uwsgi.environ = environ;

#if defined(__linux__) || defined(__sun__)

	int i;
	int env_count = 0;

	uwsgi.argv = uwsgi_malloc( sizeof(char *) * (argc+1));

	for(i=0;i<argc;i++) {
		if (i==0 || argv[0] + uwsgi.max_procname + 1 == argv[i]) {
			uwsgi.max_procname += strlen(argv[i]) + 1;
		}
		uwsgi.argv[i] = strdup(argv[i]);
	}

	// required by execve
	uwsgi.argv[i+1] = NULL;
	
	uwsgi.max_procname++;

	for (i = 0; environ[i] != NULL; i++) {
		// useless
		//if ((environ[0] + uwsgi.max_procname + 1) == environ[i]) {
			uwsgi.max_procname += strlen(environ[i]) + 1;
		//}
		env_count++;
	}

	uwsgi.environ = uwsgi_malloc(sizeof(char *) * env_count);
	for(i=0;i<env_count;i++) {
		uwsgi.environ[i] = strdup(environ[i]);
#ifdef UWSGI_DEBUG
		uwsgi_log("ENVIRON: %s\n", uwsgi.environ[i]);
#endif
		environ[i] = uwsgi.environ[i];
	}

#ifdef UWSGI_DEBUG
	uwsgi_log("max space for custom process name = %d\n", uwsgi.max_procname);
#endif
	//environ = uwsgi.environ;

#endif
}




#ifdef UWSGI_AS_SHARED_LIBRARY
int uwsgi_init(int argc, char *argv[], char *envp[]) {

#ifdef __APPLE__
	char*** envPtr = _NSGetEnviron();
	environ = *envPtr;
#endif

#else
int main(int argc, char *argv[], char *envp[]) {
#endif

	int i;
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
	char *optname;

	signal(SIGHUP, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);


	//initialize masterpid with a default value
	masterpid = getpid();

	memset(&uwsgi, 0, sizeof(struct uwsgi_server));
	uwsgi.cwd = uwsgi_get_cwd();

	init_magic_table(uwsgi.magic_table);

	atexit(vacuum);


#ifdef UWSGI_DEBUG
#ifdef __sun__
	if (uname(&uuts) < 0) {
#else
	if (uname(&uuts)) {
#endif
		uwsgi_error("uname()");
	}
	else {
		uwsgi_log("SYSNAME: %s\nNODENAME: %s\nRELEASE: %s\nVERSION: %s\nMACHINE: %s\n", uuts.sysname, uuts.nodename, uuts.release, uuts.version, uuts.machine);
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

	uwsgi.signal_socket = -1;
	uwsgi.my_signal_socket = -1;
	uwsgi.cache_server_fd = -1;
	uwsgi.stats_fd = -1;

	uwsgi.original_log_fd = -1;

	uwsgi.emperor_fd_config = -1;
	uwsgi.emperor_throttle = 1000;
	uwsgi.emperor_pid = -1;

	uwsgi.subscribe_freq = 10;
	uwsgi.subscription_tolerance = 17;

	uwsgi.cluster_fd = -1;
	uwsgi.cores = 1;

	uwsgi.default_app = -1;

	uwsgi.buffer_size = 4096;
	uwsgi.numproc = 1;

	uwsgi.async = 1;
	uwsgi.listen_queue = 100;

	uwsgi.max_vars = MAX_VARS;
	uwsgi.vec_size = 4 + 1 + (4 * MAX_VARS);

	uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT] = 4;
	uwsgi.shared->options[UWSGI_OPTION_LOGGING] = 1;

#ifdef UWSGI_SPOOLER
	uwsgi.shared->spooler_signal_pipe[0] = -1;
	uwsgi.shared->spooler_signal_pipe[1] = -1;
#endif
	uwsgi.shared->mule_signal_pipe[0] = -1;
	uwsgi.shared->mule_signal_pipe[1] = -1;

	uwsgi.shared->mule_queue_pipe[0] = -1;
	uwsgi.shared->mule_queue_pipe[1] = -1;

	uwsgi.shared->worker_log_pipe[0] = -1;
        uwsgi.shared->worker_log_pipe[1] = -1; 

	uwsgi.mime_file = "/etc/mime.types";


	gettimeofday(&uwsgi.start_tv, NULL);

	setlinebuf(stdout);

	uwsgi.rl.rlim_cur = 0;
	uwsgi.rl.rlim_max = 0;

	// are we under systemd ?
	char *notify_socket = getenv("NOTIFY_SOCKET");
	if (notify_socket) {
		uwsgi_systemd_init(notify_socket);
	}

	uwsgi_notify("initializing uWSGI");

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

	char *screen_env = getenv("TERM");
	if (screen_env) {
		if (!strcmp(screen_env, "screen")) {
			uwsgi.screen_session = getenv("STY");
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
	}
	else {
		if (setenv("UWSGI_RELOADS", "0", 1)) {
			uwsgi_error("setenv()");
		}
	}

	uwsgi.page_size = getpagesize();
	uwsgi.binary_path = uwsgi_get_binary_path(argv[0]);

	// ok we can now safely play with argv and environ
	fixup_argv_and_environ(argc, argv, environ);

	if (gethostname(uwsgi.hostname, 255)) {
		uwsgi_error("gethostname()");
	}
	uwsgi.hostname_len = strlen(uwsgi.hostname);

#ifdef UWSGI_ZEROMQ
	uwsgi_register_logger("zeromq", uwsgi_zeromq_logger);
	uwsgi_register_logger("zmq", uwsgi_zeromq_logger);
#endif

	//initialize embedded plugins
	UWSGI_LOAD_EMBEDDED_PLUGINS
		// now a bit of magic, if the executable basename contains a 'uwsgi_' string,
		// try to automatically load a plugin
#ifdef UWSGI_DEBUG
	uwsgi_log("executable name: %s\n", uwsgi.binary_path);
#endif

	char *original_proc_name = getenv("UWSGI_ORIGINAL_PROC_NAME");
	if (!original_proc_name) {
		// here we use argv[0];
		original_proc_name = argv[0];
		setenv("UWSGI_ORIGINAL_PROC_NAME", original_proc_name, 1);
	}
	char *p = strrchr(original_proc_name, '/');
	if (p == NULL) p = original_proc_name; 
	p = strstr(p, "uwsgi_");
	if (p != NULL) {
		plugins_requested = strtok(uwsgi_str(p+6), "_");
		while(plugins_requested) {
			uwsgi_log("[uwsgi] implicit plugin requested %s\n", plugins_requested);
			uwsgi_load_plugin(-1, plugins_requested, NULL, 0);
			plugins_requested = strtok(NULL, "_");
		}
	}

	plugins_requested = getenv("UWSGI_PLUGINS");
	if (plugins_requested) {
		plugins_requested = uwsgi_concat2(plugins_requested, "");
		char *p = strtok(plugins_requested, ",");
		while (p != NULL) {
			uwsgi_load_plugin(-1, p, NULL, 0);
			p = strtok(NULL, ",");
		}
	}

	build_options();

	uwsgi.magic_table['v'] = uwsgi.cwd;
	uwsgi.magic_table['h'] = uwsgi.hostname;

#ifdef UWSGI_EMBED_CONFIG
	uwsgi_ini_config("", uwsgi.magic_table);	
#endif

	uwsgi.option_index = -1;
	while ((i = getopt_long(uwsgi.argc, uwsgi.argv, short_options, uwsgi.long_options, &uwsgi.option_index)) != -1) {

		if (uwsgi.option_index > -1) {
			optname = (char *) uwsgi.long_options[uwsgi.option_index].name;
		}
		else {
			optname = uwsgi_get_optname_by_index(i);
		}
		// is this a flagged option ?
		if (i == 0) {
			add_exported_option(optname, strdup("1"), 0);
		}
		else {
			add_exported_option(optname, optarg, 1);
			manage_opt(i, optarg);
		}
		uwsgi.option_index = -1;
	}

#ifdef UWSGI_DEBUG
	uwsgi_log("optind:%d argc:%d\n", optind,argc);
#endif

	if (optind < argc) {
		for(i=optind;i<uwsgi.argc;i++) {
			char *lazy = uwsgi.argv[i];
			if (lazy[0] != '[') {
				if (0) {
				}

#ifdef UWSGI_XML
				else if (!strcmp(lazy + strlen(lazy) - 4, ".xml")) {
					uwsgi.xml_config = lazy;
				}
#endif
#ifdef UWSGI_INI
				else if (!strcmp(lazy + strlen(lazy) - 4, ".ini")) {
					uwsgi_string_new_list(&uwsgi.ini, lazy);
				}
#endif
#ifdef UWSGI_YAML
				else if (!strcmp(lazy + strlen(lazy) - 4, ".yml")) {
					uwsgi.yaml = lazy;
				}
				else if (!strcmp(lazy + strlen(lazy) - 5, ".yaml")) {
					uwsgi.yaml = lazy;
				}
#endif
#ifdef UWSGI_JSON
				else if (!strcmp(lazy + strlen(lazy) - 3, ".js")) {
					uwsgi.json = lazy;
				}
				else if (!strcmp(lazy + strlen(lazy) - 5, ".json")) {
					uwsgi.json = lazy;
				}
#endif
#ifdef UWSGI_SQLITE3
				else if (!strcmp(lazy + strlen(lazy) - 3, ".db")) {
					uwsgi.sqlite3 = lazy;
				}
				else if (!strcmp(lazy + strlen(lazy) - 7, ".sqlite")) {
					uwsgi.sqlite3 = lazy;
				}
				else if (!strcmp(lazy + strlen(lazy) - 8, ".sqlite3")) {
					uwsgi.sqlite3 = lazy;
				}
#endif
				// manage magic mountpoint
				else if ((lazy[0] == '/' || strchr(lazy, '|')) && strchr(lazy, '=')) {
				}
				else {
					int magic = 0;
					int j;
					for (j = 0; j< uwsgi.gp_cnt; j++) {
						if (uwsgi.gp[j]->magic) {
							if (uwsgi.gp[j]->magic(NULL, lazy)) {
								magic = 1;
								break;
							}
						}
					}
					if (!magic) {
						for (j = 0; j < 0xFF; j++) {
							if (uwsgi.p[j]->magic) {
								if (uwsgi.p[j]->magic(NULL, lazy)) {
									magic = 1;
									break;
								}
							}
						}
					}
				}
			}
		}
	}

	
#ifdef UWSGI_XML
	if (uwsgi.xml_config != NULL) {
		config_magic_table_fill(uwsgi.xml_config, uwsgi.magic_table);
		uwsgi_xml_config(uwsgi.xml_config, uwsgi.wsgi_req, 0, uwsgi.magic_table);
		uwsgi.xml_config = uwsgi.magic_table['p'];
	}
#endif
#ifdef UWSGI_INI
	struct uwsgi_string_list *config_file;
	if (uwsgi.ini != NULL) {
		config_file = uwsgi.ini;
		while(config_file) {
			config_magic_table_fill(config_file->value, uwsgi.magic_table);
			uwsgi_ini_config(config_file->value, uwsgi.magic_table);
			config_file = config_file->next;
		}
	}
#endif
#ifdef UWSGI_YAML
	if (uwsgi.yaml != NULL) {
		config_magic_table_fill(uwsgi.yaml, uwsgi.magic_table);
		uwsgi_yaml_config(uwsgi.yaml, uwsgi.magic_table);
	}
#endif
#ifdef UWSGI_JSON
	if (uwsgi.json != NULL) {
		config_magic_table_fill(uwsgi.json, uwsgi.magic_table);
		uwsgi_json_config(uwsgi.json, uwsgi.magic_table);
	}
#endif
#ifdef UWSGI_SQLITE3
	if (uwsgi.sqlite3 != NULL) {
		config_magic_table_fill(uwsgi.sqlite3, uwsgi.magic_table);
		uwsgi_sqlite3_config(uwsgi.sqlite3, uwsgi.magic_table);
	}
#endif
#ifdef UWSGI_LDAP
	if (uwsgi.ldap != NULL) {
		uwsgi_ldap_config();
	}
#endif

	//parse environ
	parse_sys_envs(environ);

	// apply templates passed from command line
	uwsgi_apply_templates();

	// second pass: ENVs
	uwsgi_apply_config_pass('$', (char *(*)(char *))getenv);

	// third pass: FILEs
	uwsgi_apply_config_pass('@', uwsgi_simple_file_read);

	// last pass: REFERENCEs
	uwsgi_apply_config_pass('%', uwsgi_get_exported_opt);

	// ok, the options dictionary is available, lets manage it
	uwsgi_configure();

	// setup master logging
	if (uwsgi.log_master) {

		if (uwsgi.requested_logger) {
			char *colon = strchr(uwsgi.requested_logger, ':');
			if (colon) {
				*colon = 0;
			}

			uwsgi.choosen_logger = uwsgi_get_logger(uwsgi.requested_logger);
			if (!uwsgi.choosen_logger) {
				uwsgi_log("unable to find logger %s\n", uwsgi.requested_logger);
				exit(1);
			}

			if (colon) {
				uwsgi.choosen_logger_arg = colon+1;
				*colon = ':';
			}

		}

        	uwsgi.original_log_fd = dup(1);
                create_logpipe();

        }

	/* uWSGI IS CONFIGURED !!! */

	if (uwsgi.dump_options) {
		struct option *lopt = uwsgi.long_options;
		while (lopt->name) {
			fprintf(stdout, "%s\n", lopt->name);
			lopt++;
		}
		exit(0);
	}

	if (uwsgi.show_config) {
		show_config();
	}


	cluster_setup();

	//call after_opt hooks

	if (uwsgi.binary_path == uwsgi.argv[0]) {
		uwsgi.binary_path = uwsgi_str(uwsgi.argv[0]);
	}


		if (uwsgi.shared->options[UWSGI_OPTION_CGI_MODE] == 0) {
			uwsgi_log_initial("*** Starting uWSGI %s (%dbit) on [%.*s] ***\n", UWSGI_VERSION, (int) (sizeof(void *)) * 8, 24, ctime((const time_t *) &uwsgi.start_tv.tv_sec));
		}
		else {
			uwsgi_log_initial("*** Starting uWSGI %s (CGI mode) (%dbit) on [%.*s] ***\n", UWSGI_VERSION, (int) (sizeof(void *)) * 8, 24, ctime((const time_t *) &uwsgi.start_tv.tv_sec));
		}

#ifdef UWSGI_DEBUG
		uwsgi_log("***\n*** You are running a DEBUG version of uWSGI, please disable debug in your build profile and recompile it ***\n***\n");
#endif

		uwsgi_log_initial("compiled with version: %s on %s\n", __VERSION__, UWSGI_BUILD_DATE);

#ifdef __BIG_ENDIAN__
		uwsgi_log_initial("*** big endian arch detected ***\n");
#endif


	uwsgi_log_initial("current working directory: %s\n", uwsgi.cwd);

	if (uwsgi.screen_session) {
		uwsgi_log("*** running under screen session %s ***\n", uwsgi.screen_session);
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

	uwsgi_log_initial("detected binary path: %s\n", uwsgi.binary_path);

	struct uwsgi_socket *shared_sock = uwsgi.shared_sockets;
	while (shared_sock) {
		char *tcp_port = strchr(shared_sock->name, ':');
		if (tcp_port == NULL) {
			shared_sock->fd = bind_to_unix(shared_sock->name, uwsgi.listen_queue, uwsgi.chmod_socket, uwsgi.abstract_socket);
			shared_sock->family = AF_UNIX;
			uwsgi_log("uwsgi shared socket %d bound to UNIX address %s fd %d\n", uwsgi_get_shared_socket_num(shared_sock), shared_sock->name, shared_sock->fd);
		}
		else {
			shared_sock->fd = bind_to_tcp(shared_sock->name, uwsgi.listen_queue, tcp_port);
			shared_sock->family = AF_INET;
			uwsgi_log("uwsgi shared socket %d bound to TCP address %s fd %d\n", uwsgi_get_shared_socket_num(shared_sock), shared_sock->name, shared_sock->fd);
		}

		if (shared_sock->fd < 0) {
			uwsgi_log("unable to create shared socket on: %s\n", shared_sock->name);
			exit(1);
		}
		shared_sock->bound = 1;

		shared_sock = shared_sock->next;
	}

	struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;
	while(uwsgi_sock) {

		if (uwsgi_sock->shared) {
			shared_sock = uwsgi_get_shared_socket_by_num(uwsgi_sock->from_shared);
			if (!shared_sock) {
				uwsgi_log("unable to find shared socket %d\n", uwsgi_sock->from_shared);
				exit(1);
			}
			uwsgi_sock->fd = shared_sock->fd;
                	uwsgi_sock->family = shared_sock->family;
                	uwsgi_sock->name = shared_sock->name;
			uwsgi_log("uwsgi socket %d mapped to shared socket %d (%s)\n", uwsgi_get_socket_num(uwsgi_sock), uwsgi_get_shared_socket_num(shared_sock), shared_sock->name);
		}

		uwsgi_sock = uwsgi_sock->next;
	}

	// start the Emperor if needed
	if (uwsgi.early_emperor && uwsgi.emperor_dir) {

		if (!uwsgi.sockets && !uwsgi.gateways_cnt && !uwsgi.master_process) {
			uwsgi_notify_ready();
			emperor_loop();
			// never here
			exit(1);
		}

		uwsgi.emperor_pid = uwsgi_fork("uWSGI Emperor");
		if (uwsgi.emperor_pid < 0) {
			uwsgi_error("pid()");
			exit(1);
		}
		else if (uwsgi.emperor_pid == 0) {
#ifdef __linux__
			if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0)) {
				uwsgi_error("prctl()");
			}
#endif
			emperor_loop();
			// never here
			exit(1);
		}
	}


	// call jail systems
	for (i = 0; i < uwsgi.gp_cnt; i++) {
		if (uwsgi.gp[i]->jail) {
			uwsgi.gp[i]->jail(uwsgi_start, uwsgi.argv);
		}
	}


	// TODO pluginize basic Linux namespace support
#ifdef __linux__
	if (uwsgi.ns) {
		linux_namespace_start((void *) uwsgi.argv);
		// never here
	}
	else {
#endif
		uwsgi_start((void *) uwsgi.argv);
#ifdef __linux__
	}
#endif


	// never here
	return 0;
}

int uwsgi_start(void *v_argv) {

#ifdef UWSGI_DEBUG
	int so_bufsize;
	socklen_t so_bufsize_len;
#endif


	int i, j;

	union uwsgi_sockaddr usa;
	union uwsgi_sockaddr_ptr gsa;
	socklen_t socket_type_len;

	struct uwsgi_socket *uwsgi_sock;

#ifdef __linux__
	uwsgi_set_cgroup();

	if (uwsgi.ns) {
		linux_namespace_jail();
	}
#endif

	if (!uwsgi.master_as_root && !uwsgi.chown_socket) {
		uwsgi_as_root();
	}

	if (uwsgi.logto2) {
		logto(uwsgi.logto2);
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

		if (!uwsgi.master_process) {
			uwsgi_log_initial("*** WARNING: you are running uWSGI without its master process manager ***\n");
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

		}
		else {
			uwsgi_log("scheduler priority set to %d\n", uwsgi.prio);
		}
	}
	if (!getrlimit(RLIMIT_AS, &uwsgi.rl)) {
		//check for overflow
		if (uwsgi.rl.rlim_max != (rlim_t) RLIM_INFINITY) {
			uwsgi_log_initial("your process address space limit is %lld bytes (%lld MB)\n", (long long) uwsgi.rl.rlim_max, (long long) uwsgi.rl.rlim_max / 1024 / 1024);
		}
	}
#endif


		uwsgi_log_initial("your memory page size is %d bytes\n", uwsgi.page_size);

	if (uwsgi.buffer_size > 65536) {
		uwsgi_log("invalid buffer size.\n");
		exit(1);
	}
	sanitize_args();

	if (uwsgi.build_mime_dict) {
		if (!access(uwsgi.mime_file, R_OK)) {
			uwsgi_build_mime_dict(uwsgi.mime_file);
		}
		else {
			uwsgi_log("!!! no mime.types file found !!!\n");
		}
	}

	// end of generic initialization


	// start the Emperor if needed
	if (!uwsgi.early_emperor && uwsgi.emperor_dir) {

		if (!uwsgi.sockets && !uwsgi.gateways_cnt && !uwsgi.master_process) {
			uwsgi_notify_ready();
			emperor_loop();
			// never here
			exit(1);
		}

		uwsgi.emperor_pid = uwsgi_fork("uWSGI Emperor");
		if (uwsgi.emperor_pid < 0) {
			uwsgi_error("pid()");
			exit(1);
		}
		else if (uwsgi.emperor_pid == 0) {
#ifdef __linux__
			if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0)) {
				uwsgi_error("prctl()");
			}
#endif
			emperor_loop();
			// never here
			exit(1);
		}
	}


	uwsgi_register_loop("simple", simple_loop);
#ifdef UWSGI_ASYNC
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
					}
					else {
						uwsgi.async = (int) tmp_nofile;
					}
				}
				else {
					uwsgi.async = uwsgi.rl.rlim_cur;
				}

				uwsgi_log("- async cores set to %d -\n", uwsgi.async);
			}
		}
	}
#endif

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
		uwsgi.async_waiting_fd_table = malloc(sizeof(struct wsgi_request *) * uwsgi.max_fd);
		if (!uwsgi.async_waiting_fd_table) {
			uwsgi_error("malloc()");
			exit(1);
		}
		memset(uwsgi.async_waiting_fd_table, 0, sizeof(struct wsgi_request *) * uwsgi.max_fd);
		uwsgi.async_proto_fd_table = malloc(sizeof(struct wsgi_request *) * uwsgi.max_fd);
		if (!uwsgi.async_proto_fd_table) {
			uwsgi_error("malloc()");
			exit(1);
		}
		memset(uwsgi.async_proto_fd_table, 0, sizeof(struct wsgi_request *) * uwsgi.max_fd);
	}

	if (uwsgi.post_buffering > 0) {
		uwsgi.async_post_buf = uwsgi_malloc(sizeof(char *) * uwsgi.cores);
		if (!uwsgi.post_buffering_bufsize)
			uwsgi.post_buffering_bufsize = 8192;
		if (uwsgi.post_buffering_bufsize < uwsgi.post_buffering) {
			uwsgi.post_buffering_bufsize = uwsgi.post_buffering;
			uwsgi_log("setting request body buffering size to %d bytes\n", uwsgi.post_buffering_bufsize);
		}
	}
	for (i = 0; i < uwsgi.cores; i++) {
		uwsgi.async_buf[i] = uwsgi_malloc(uwsgi.buffer_size);
		if (uwsgi.post_buffering > 0) {
			uwsgi.async_post_buf[i] = uwsgi_malloc(uwsgi.post_buffering_bufsize);
		}
	}

#ifdef UWSGI_DEBUG
	uwsgi_log("cores allocated...\n");
#endif


	//by default set wsgi_req to the first slot
	uwsgi.wsgi_req = uwsgi.wsgi_requests[0];

	if (uwsgi.cores > 1) {
		uwsgi_log("allocated %llu bytes (%llu KB) for %d cores per worker.\n", (uint64_t) (sizeof(struct wsgi_request) * uwsgi.cores), (uint64_t) ((sizeof(struct wsgi_request) * uwsgi.cores) / 1024), uwsgi.cores);
	}
	if (uwsgi.vhost) {
		uwsgi_log("VirtualHosting mode enabled.\n");
	}


	// event queue lock (mitigate same event on multiple queues)
	if (uwsgi.threads > 1) {
		pthread_mutex_init(&uwsgi.thunder_mutex, NULL);
	}

	// application generic lock
	uwsgi.user_lock = uwsgi_malloc(sizeof(void *) * (uwsgi.locks+1));
	for(i=0;i<uwsgi.locks+1;i++) {
		uwsgi.user_lock[i] = uwsgi_mmap_shared_lock();
		uwsgi_lock_init(uwsgi.user_lock[i]);
	}

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

		// probe table lock
		uwsgi.probe_table_lock = uwsgi_mmap_shared_lock();
		uwsgi_lock_init(uwsgi.probe_table_lock);

		// rb_timer table lock
		uwsgi.rb_timer_table_lock = uwsgi_mmap_shared_lock();
		uwsgi_lock_init(uwsgi.rb_timer_table_lock);

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

		uwsgi.sharedarea = mmap(NULL, uwsgi.page_size * uwsgi.sharedareasize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
		if (uwsgi.sharedarea) {
			uwsgi_log("shared area mapped at %p, you can access it with uwsgi.sharedarea* functions.\n", uwsgi.sharedarea);
		}
		else {
			uwsgi_error("mmap()");
			exit(1);
		}

		uwsgi.sa_lock = uwsgi_mmap_shared_rwlock();
                uwsgi_rwlock_init(uwsgi.sa_lock);
	}

	if (uwsgi.queue_size > 0) {
		uwsgi_init_queue();
	}

	if (uwsgi.cache_max_items > 0) {
		uwsgi_init_cache();
	}

	// create the cache server
	if (uwsgi.master_process && uwsgi.cache_server) {
		uwsgi.cache_server_fd = uwsgi_cache_server(uwsgi.cache_server, uwsgi.cache_server_threads);
	}

	/* plugin initialization */
	for (i = 0; i < uwsgi.gp_cnt; i++) {
		if (uwsgi.gp[i]->init) {
			uwsgi.gp[i]->init();
		}
	}


	if (!uwsgi.no_server) {

		// systemd socket activation
		if (!uwsgi.is_a_reload) {
			char *listen_pid = getenv("LISTEN_PID");
			if (listen_pid) {
				if (atoi(listen_pid) == (int) getpid()) {
					char *listen_fds = getenv("LISTEN_FDS");
					if (listen_fds) {
						int systemd_fds = atoi(listen_fds);
						if (systemd_fds > 0) {
							for(i=3;i<3+systemd_fds;i++) {
								uwsgi_sock = uwsgi_new_socket(NULL);
								uwsgi_add_socket_from_fd(uwsgi_sock, i);
							}
						}
						unsetenv("LISTEN_PID");
						unsetenv("LISTEN_FDS");
						goto skipzero;
					}
				}
			}
		}


		//check for inherited sockets
		if (uwsgi.is_a_reload || uwsgi.zerg) {

			if (uwsgi.zerg) {
#ifdef UWSGI_DEBUG
				uwsgi_log("attaching zerg sockets...\n");
#endif
				int zerg_fd;
				i = 0;
				for(;;) {
					zerg_fd = uwsgi.zerg[i];
					if (zerg_fd == -1) {
						break;
					}
					uwsgi_sock = uwsgi_new_socket(NULL);
					uwsgi_add_socket_from_fd(uwsgi_sock, zerg_fd);
					i++;
				}

				uwsgi_log("zerg sockets attached\n");
			}

			uwsgi_sock = uwsgi.sockets;
			while (uwsgi_sock) {
				//a bit overengineering
				if (uwsgi_sock->name[0] != 0 && !uwsgi_sock->bound) {
					for (j = 3; j < sysconf(_SC_OPEN_MAX); j++) {
						uwsgi_add_socket_from_fd(uwsgi_sock, j);
					}
				}
				uwsgi_sock = uwsgi_sock->next;
			}

			//now close all the unbound fd
			for (j = 3; j < sysconf(_SC_OPEN_MAX); j++) {
				int useless = 1;
#ifdef UWSGI_MULTICAST
				if (j == uwsgi.cluster_fd)
					continue;
#endif
				if (uwsgi.has_emperor) {
					if (j == uwsgi.emperor_fd)
						continue;
				}

				if (uwsgi.shared->worker_log_pipe[0] > -1) {
					if (j == uwsgi.shared->worker_log_pipe[0])
						continue;
				}

				if (uwsgi.shared->worker_log_pipe[1] > -1) {
					if (j == uwsgi.shared->worker_log_pipe[1])
						continue;
				}

				if (uwsgi.original_log_fd > -1) {
					if (j == uwsgi.original_log_fd)
						continue;
				}	

				if (uwsgi.cache_server && uwsgi.cache_server_fd != -1) {
					if (j == uwsgi.cache_server_fd)
						continue;
				}

				socket_type_len = sizeof(struct sockaddr_un);
				gsa.sa = (struct sockaddr *) &usa;
				if (!getsockname(j, gsa.sa, &socket_type_len)) {
					uwsgi_sock = uwsgi.sockets;
					while (uwsgi_sock) {
						if (uwsgi_sock->fd == j && uwsgi_sock->bound) {
							useless = 0;
							break;
						}
						uwsgi_sock = uwsgi_sock->next;
					}
				}
				if (useless)
					close(j);
			}
		}
		//now bind all the unbound sockets
		uwsgi_sock = uwsgi.sockets;
		while (uwsgi_sock) {
			if (!uwsgi_sock->bound) {
				char *tcp_port = strchr(uwsgi_sock->name, ':');
				if (tcp_port == NULL) {
					uwsgi_sock->fd = bind_to_unix(uwsgi_sock->name, uwsgi.listen_queue, uwsgi.chmod_socket, uwsgi.abstract_socket);
					uwsgi_sock->family = AF_UNIX;
					if (uwsgi.chown_socket) {
						uwsgi_chown(uwsgi_sock->name, uwsgi.chown_socket);
					}
					uwsgi_log("uwsgi socket %d bound to UNIX address %s fd %d\n", uwsgi_get_socket_num(uwsgi_sock), uwsgi_sock->name, uwsgi_sock->fd);
				}
				else {
					uwsgi_sock->fd = bind_to_tcp(uwsgi_sock->name, uwsgi.listen_queue, tcp_port);
					uwsgi_sock->family = AF_INET;
					uwsgi_log("uwsgi socket %d bound to TCP address %s fd %d\n", uwsgi_get_socket_num(uwsgi_sock), uwsgi_sock->name, uwsgi_sock->fd);
				}

				if (uwsgi_sock->fd < 0) {
					uwsgi_log("unable to create server socket on: %s\n", uwsgi_sock->name);
					exit(1);
				}
			}
			uwsgi_sock->bound = 1;
			uwsgi_sock = uwsgi_sock->next;
		}

		if (uwsgi.chown_socket) {
			if (!uwsgi.master_as_root) {
				uwsgi_as_root();
			}
		}

		int zero_used = 0;
		uwsgi_sock = uwsgi.sockets;
		while (uwsgi_sock) {
			if (uwsgi_sock->bound && uwsgi_sock->fd == 0) {
				zero_used = 1;
				break;
			}
			uwsgi_sock = uwsgi_sock->next;
		}

		if (!zero_used) {
			socket_type_len = sizeof(struct sockaddr_un);
			gsa.sa = (struct sockaddr *) &usa;
			if (!getsockname(0, gsa.sa, &socket_type_len)) {
				if (gsa.sa->sa_family == AF_UNIX) {
					uwsgi_sock = uwsgi_new_socket(usa.sa_un.sun_path);
					uwsgi_log("uwsgi socket %d inherited UNIX address %s fd 0\n", uwsgi_get_socket_num(uwsgi_sock), uwsgi_sock->name);
				}
				else {
					uwsgi_sock = uwsgi_new_socket(uwsgi_concat2("::",""));
					uwsgi_log("uwsgi socket %d inherited INET address %s fd 0\n", uwsgi_get_socket_num(uwsgi_sock), uwsgi_sock->name);
				}
			}
			else if (!uwsgi.honour_stdin) {
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
					close(fd);
				}
			}

		}

skipzero:
	
		// check for auto_port socket
		uwsgi_sock = uwsgi.sockets;
                while (uwsgi_sock) {
			if (uwsgi_sock->auto_port) {
				uwsgi_log("uwsgi socket %d bound to TCP address %s (port auto-assigned) fd %d\n", uwsgi_get_socket_num(uwsgi_sock), uwsgi_sock->name, uwsgi_sock->fd);
			}
			uwsgi_sock = uwsgi_sock->next;
		}


		// put listening socket in non-blocking state and set the protocol
		uwsgi_sock = uwsgi.sockets;
		while (uwsgi_sock) {
			uwsgi_sock->arg = fcntl(uwsgi_sock->fd, F_GETFL, NULL);
			if (uwsgi_sock->arg < 0) {
				uwsgi_error("fcntl()");
				exit(1);
			}
			uwsgi_sock->arg |= O_NONBLOCK;
			if (fcntl(uwsgi_sock->fd, F_SETFL, uwsgi_sock->arg) < 0) {
				uwsgi_error("fcntl()");
				exit(1);
			}

			char *requested_protocol = uwsgi_sock->proto_name;
			if (!requested_protocol) {
				requested_protocol = uwsgi.protocol;
			}

			if (requested_protocol && !strcmp("http", requested_protocol)) {
				uwsgi_sock->proto = uwsgi_proto_http_parser;
				uwsgi_sock->proto_accept = uwsgi_proto_base_accept;
				uwsgi_sock->proto_write = uwsgi_proto_http_write;
				uwsgi_sock->proto_writev = uwsgi_proto_http_writev;
				uwsgi_sock->proto_write_header = uwsgi_proto_http_write_header;
				uwsgi_sock->proto_writev_header = uwsgi_proto_http_writev_header;
				uwsgi_sock->proto_sendfile = NULL;
				uwsgi_sock->proto_close = uwsgi_proto_base_close;
			}
			else if (requested_protocol && (!strcmp("fastcgi", requested_protocol) || !strcmp("fcgi", requested_protocol))) {
				if (!strcmp(uwsgi.protocol, "fastcgi") || !strcmp(uwsgi.protocol, "fcgi")) {
					uwsgi.shared->options[UWSGI_OPTION_CGI_MODE] = 1;
				}
				uwsgi_sock->proto = uwsgi_proto_fastcgi_parser;
				uwsgi_sock->proto_accept = uwsgi_proto_base_accept;
				uwsgi_sock->proto_write = uwsgi_proto_fastcgi_write;
				uwsgi_sock->proto_writev = uwsgi_proto_fastcgi_writev;
				uwsgi_sock->proto_write_header = uwsgi_proto_fastcgi_write_header;
				uwsgi_sock->proto_writev_header = uwsgi_proto_fastcgi_writev_header;
				uwsgi_sock->proto_sendfile = uwsgi_proto_fastcgi_sendfile;
				uwsgi_sock->proto_close = uwsgi_proto_fastcgi_close;
			}
			else {
				uwsgi_sock->proto = uwsgi_proto_uwsgi_parser;
				uwsgi_sock->proto_accept = uwsgi_proto_base_accept;
				uwsgi_sock->proto_write = uwsgi_proto_uwsgi_write;
				uwsgi_sock->proto_writev = uwsgi_proto_uwsgi_writev;
				uwsgi_sock->proto_write_header = uwsgi_proto_uwsgi_write_header;
				uwsgi_sock->proto_writev_header = uwsgi_proto_uwsgi_writev_header;
				uwsgi_sock->proto_sendfile = NULL;
				uwsgi_sock->proto_close = uwsgi_proto_base_close;
			}

			uwsgi_sock = uwsgi_sock->next;
		}

#ifdef UWSGI_ZEROMQ
		if (uwsgi.zeromq) {
			uwsgi.zmq_responder = strchr(uwsgi.zeromq, ',');
			if (!uwsgi.zmq_responder) {
				uwsgi_log("invalid zeromq address\n");
				exit(1);
			}
			uwsgi.zmq_receiver = uwsgi_concat2n(uwsgi.zeromq, uwsgi.zmq_responder - uwsgi.zeromq, "", 0);
			uwsgi.zmq_responder++;
			uwsgi_log("zmq receiver: %s\n", uwsgi.zmq_receiver);
			uwsgi_log("zmq responder: %s\n", uwsgi.zmq_responder);

			uwsgi.zmq_socket = uwsgi_new_socket(uwsgi.zmq_receiver);
		}
#endif

	}


	// initialize request plugin only if workers or master are available
	if (uwsgi.sockets || uwsgi.master_process || uwsgi.no_server) {
		for (i = 0; i < 0xFF; i++) {
			if (uwsgi.p[i]->init) {
				uwsgi.p[i]->init();
			}
		}
	}


	/* gp/plugin initialization */
	for (i = 0; i < uwsgi.gp_cnt; i++) {
		if (uwsgi.gp[i]->post_init) {
			uwsgi.gp[i]->post_init();
		}
	}

	for (i = 0; i < 0xff; i++) {
		if (uwsgi.p[i]->post_init) {
			uwsgi.p[i]->post_init();
		}
	}

	uwsgi.current_wsgi_req = simple_current_wsgi_req;


#ifdef UWSGI_THREADING
	if (uwsgi.sockets || uwsgi.gateways_cnt) {
		if (uwsgi.has_threads) {
			if (uwsgi.threads > 1)
				uwsgi.current_wsgi_req = threaded_current_wsgi_req;
			(void) pthread_attr_init(&uwsgi.threads_attr);
			if (uwsgi.threads_stacksize) {
				if (pthread_attr_setstacksize(&uwsgi.threads_attr, uwsgi.threads_stacksize*1024) == 0) {
					uwsgi_log("threads stack size set to %dk\n", uwsgi.threads_stacksize);
				}
				else {
					uwsgi_log("!!! unable to set requested threads stacksize !!!\n");
				}
			}

			pthread_mutex_init(&uwsgi.lock_static, NULL);

			for (i = 0; i < 0xFF; i++) {
				if (uwsgi.p[i]->enable_threads)
					uwsgi.p[i]->enable_threads();
			}
		}
	}
#endif

	if (!uwsgi.sockets && !uwsgi.gateways_cnt && !uwsgi.no_server && !uwsgi.udp_socket && !uwsgi.emperor_dir) {
		uwsgi_log("The -s/--socket option is missing and stdin is not a socket.\n");
		exit(1);
	}
	else if (!uwsgi.sockets && uwsgi.gateways_cnt && !uwsgi.no_server && !uwsgi.master_process) {
		// here we will have a zombie... sorry
		uwsgi_log("...you should enable the master process... really...\n");
		exit(0);
	}

	if (!uwsgi.sockets)
		uwsgi.numproc = 0;

#ifdef UWSGI_DEBUG
	uwsgi_sock = uwsgi.sockets;
	while (uwsgi_sock) {
		so_bufsize_len = sizeof(int);
		if (getsockopt(uwsgi_sock->fd, SOL_SOCKET, SO_RCVBUF, &so_bufsize, &so_bufsize_len)) {
			uwsgi_error("getsockopt()");
		}
		else {
			uwsgi_debug("uwsgi socket %d SO_RCVBUF size: %d\n", i, so_bufsize);
		}

		so_bufsize_len = sizeof(int);
		if (getsockopt(uwsgi_sock->fd, SOL_SOCKET, SO_SNDBUF, &so_bufsize, &so_bufsize_len)) {
			uwsgi_error("getsockopt()");
		}
		else {
			uwsgi_debug("uwsgi socket %d SO_SNDBUF size: %d\n", i, so_bufsize);
		}
		uwsgi_sock = uwsgi_sock->next;
	}
#endif


#ifndef UNBIT
	uwsgi_log("your server socket listen backlog is limited to %d connections\n", uwsgi.listen_queue);
#endif

	if (uwsgi.crons) {
                struct uwsgi_cron *ucron = uwsgi.crons;
                while(ucron) {
                        uwsgi_log("command \"%s\" registered as uWSGI-cron task\n", ucron->command);
                        ucron = ucron->next;
                }
        }



	// apps are now per-worker
	//memset(uwsgi.apps, 0, sizeof(uwsgi.apps));

	uwsgi.workers = (struct uwsgi_worker *) mmap(NULL, sizeof(struct uwsgi_worker) * (uwsgi.numproc + 1 + uwsgi.grunt), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
	if (!uwsgi.workers) {
		uwsgi_error("mmap()");
		exit(1);
	}
	memset(uwsgi.workers, 0, sizeof(struct uwsgi_worker) * uwsgi.numproc + 1);

	for(i=1;i<=uwsgi.numproc;i++) {
		uwsgi.workers[i].signal_pipe[0] = - 1;
		uwsgi.workers[i].signal_pipe[1] = - 1;
		snprintf(uwsgi.workers[i].name, 0xff, "uWSGI worker %d", i);
	}

	if (uwsgi.master_process) {
		for(i=1;i<=uwsgi.numproc;i++) {
			create_signal_pipe(uwsgi.workers[i].signal_pipe);
		}
	}

	uwsgi.mypid = getpid();
	masterpid = uwsgi.mypid;

	uwsgi.workers[0].pid = masterpid;

	if (uwsgi.mules_cnt > 0) {
		uwsgi.mules = (struct uwsgi_mule *) mmap(NULL, sizeof(struct uwsgi_mule) * uwsgi.mules_cnt, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
		if (!uwsgi.mules) {
			uwsgi_error("mmap()");
                	exit(1);
		}
		memset(uwsgi.mules, 0, sizeof(struct uwsgi_mule) * uwsgi.mules_cnt);

		create_signal_pipe(uwsgi.shared->mule_signal_pipe);
		create_signal_pipe(uwsgi.shared->mule_queue_pipe);

		for(i=0;i<uwsgi.mules_cnt;i++) {
			// create the socket pipe
			create_signal_pipe(uwsgi.mules[i].signal_pipe);
			create_signal_pipe(uwsgi.mules[i].queue_pipe);

			uwsgi.mules[i].id = i+1;

			snprintf(uwsgi.mules[i].name, 0xff, "uWSGI mule %d", i+1);
		}
	}

	if (uwsgi.farms_cnt > 0) {
		uwsgi.farms = (struct uwsgi_farm *) mmap(NULL, sizeof(struct uwsgi_farm) * uwsgi.farms_cnt, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
		if (!uwsgi.farms) {
			uwsgi_error("mmap()");
                	exit(1);
		}
		memset(uwsgi.farms, 0, sizeof(struct uwsgi_farm) * uwsgi.farms_cnt);

		struct uwsgi_string_list *farm_name = uwsgi.farms_list;
		for(i=0;i<uwsgi.farms_cnt;i++) {

			char *farm_value = uwsgi_str(farm_name->value);

			char *mules_list = strchr(farm_value, ':');
			if (!mules_list) {
				uwsgi_log("invalid farm value (%s) must be in the form name:mule[,muleN].\n", farm_value);
				exit(1);
			}

			mules_list[0] = 0;
			mules_list++;

			strncpy(uwsgi.farms[i].name, farm_value, 0xff);

			// create the socket pipe
			create_signal_pipe(uwsgi.farms[i].signal_pipe);
			create_signal_pipe(uwsgi.farms[i].queue_pipe);

			char *p = strtok(mules_list, ",");
			while(p != NULL) {
				struct uwsgi_mule *um = get_mule_by_id( atoi( p ) );
				if (!um) {
					uwsgi_log("invalid mule id: %s\n", p);
					exit(1);
				}

				uwsgi_mule_farm_new(&uwsgi.farms[i].mules, um);

				p = strtok(NULL, ",");
			}
			uwsgi_log("created farm %d name: %s mules:%s\n", i+1, uwsgi.farms[i].name, strchr(farm_name->value, ':')+1);

			farm_name = farm_name->next;

		}
		
	}

	/*

	   uwsgi.shared->hooks[0] = uwsgi_request_wsgi;
	   uwsgi.shared->after_hooks[0] = uwsgi_after_request_wsgi;

	   uwsgi.shared->hooks[UWSGI_MODIFIER_ADMIN_REQUEST] = uwsgi_request_admin;     //10
	   #ifdef UWSGI_SPOOLER
	   uwsgi.shared->hooks[UWSGI_MODIFIER_SPOOL_REQUEST] = uwsgi_request_spooler;   //17
	   #endif
	   uwsgi.shared->hooks[UWSGI_MODIFIER_EVAL] = uwsgi_request_eval;       //22
	   uwsgi.shared->hooks[UWSGI_MODIFIER_FASTFUNC] = uwsgi_request_fastfunc;       //26

	   uwsgi.shared->hooks[UWSGI_MODIFIER_MANAGE_PATH_INFO] = uwsgi_request_wsgi;   // 30
	   uwsgi.shared->after_hooks[UWSGI_MODIFIER_MANAGE_PATH_INFO] = uwsgi_after_request_wsgi;       // 30

	   uwsgi.shared->hooks[UWSGI_MODIFIER_MESSAGE_MARSHAL] = uwsgi_request_marshal; //33
	   uwsgi.shared->hooks[UWSGI_MODIFIER_PING] = uwsgi_request_ping;       //100
	 */

	if (!uwsgi.numproc) {
		uwsgi_log("*** Operational MODE: no-workers ***\n");
	}
	else if (uwsgi.threads > 1) {
		if (uwsgi.numproc > 1) {
			uwsgi_log("*** Operational MODE: preforking+threaded ***\n");
		}
		else {
			uwsgi_log("*** Operational MODE: threaded ***\n");
		}
	}
#ifdef UWSGI_ASYNC
	else if (uwsgi.async > 1) {
		if (uwsgi.numproc > 1) {
			uwsgi_log("*** Operational MODE: preforking+async ***\n");
		}
		else {
			uwsgi_log("*** Operational MODE: async ***\n");
		}
	}
#endif
	else if (uwsgi.numproc > 1) {
		uwsgi_log("*** Operational MODE: preforking ***\n");
	}
	else {
		uwsgi_log("*** Operational MODE: single process ***\n");
	}

	// even the master has cores..
	uwsgi.core = uwsgi_malloc(sizeof(struct uwsgi_core *) * uwsgi.cores);
	for (j = 0; j < uwsgi.cores; j++) {
		uwsgi.core[j] = uwsgi_malloc(sizeof(struct uwsgi_core));
		memset(uwsgi.core[j], 0, sizeof(struct uwsgi_core));
	}

	// preinit apps (create the language environment)
	for (i = 0; i < 0xFF; i++) {
		if (uwsgi.p[i]->preinit_apps) {
			uwsgi.p[i]->preinit_apps();
		}
	}

	for (i = 0; i < uwsgi.gp_cnt; i++) {
		if (uwsgi.gp[i]->preinit_apps) {
			uwsgi.gp[i]->preinit_apps();
		}
	}

	//init apps hook (if not lazy)
	if (!uwsgi.lazy) {
		uwsgi_init_all_apps();
	}

	if (uwsgi.no_server) {
		uwsgi_log("no-server mode requested. Goodbye.\n");
		exit(0);
	}



	if (!uwsgi.master_process && uwsgi.numproc == 0) {
		exit(0);
	}
	if (!uwsgi.single_interpreter) {
		uwsgi_log("*** uWSGI is running in multiple interpreter mode ***\n");
	}

#ifdef __linux__
#ifdef MADV_MERGEABLE
	if (uwsgi.linux_ksm > 0) {
		uwsgi_log("[uwsgi-KSM] enabled with frequency: %d\n", uwsgi.linux_ksm); 
	}
#endif
#endif



	if (uwsgi.master_process) {
		if (uwsgi.is_a_reload) {
			uwsgi_log("gracefully (RE)spawned uWSGI master process (pid: %d)\n", uwsgi.mypid);
		}
		else {
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

	// master fixup
        for (i = 0; i < 0xFF; i++) {
                if (uwsgi.p[i]->master_fixup) {
                        uwsgi.p[i]->master_fixup(0);
                }
        }



#ifdef UWSGI_SPOOLER
	if (uwsgi.spool_dir != NULL && uwsgi.sockets) {
		create_signal_pipe(uwsgi.shared->spooler_signal_pipe);
		uwsgi.shared->spooler_pid = spooler_start();
	}
#endif

#ifdef UWSGI_ROUTING
	routing_setup();
#endif




	if (!uwsgi.master_process) {
		if (uwsgi.numproc == 1) {
			uwsgi_log("spawned uWSGI worker 1 (and the only) (pid: %d, cores: %d)\n", masterpid, uwsgi.cores);
		}
		else {
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
		create_signal_pipe(uwsgi.shared->worker_signal_pipe);
		uwsgi.signal_socket = uwsgi.shared->worker_signal_pipe[1];
	}

	// uWSGI is ready
	uwsgi_notify_ready();
	uwsgi.current_time = time(NULL);

	if (!uwsgi.cheap) {
		if (uwsgi.cheaper && uwsgi.cheaper_count) {
			for(i=1;i<=uwsgi.numproc;i++) {
				if (i <= uwsgi.cheaper_count) {
					if (uwsgi_respawn_worker(i)) break;
					gettimeofday(&last_respawn, NULL);
					uwsgi.respawn_delta = last_respawn.tv_sec;
				}
				else {
					uwsgi.workers[i].cheaped = 1;
				}
			}	
		}
		else {
			for (i = 2 - uwsgi.master_process; i < uwsgi.numproc + 1; i++) {
				if (uwsgi_respawn_worker(i))
					break;
				gettimeofday(&last_respawn, NULL);
				uwsgi.respawn_delta = last_respawn.tv_sec;
			}
		}
	}



	if (getpid() == masterpid && uwsgi.master_process == 1) {
#ifdef UWSGI_AS_SHARED_LIBRARY
		int ml_ret = master_loop(uwsgi.argv, uwsgi.environ);
		if (ml_ret == -1) {
			return 0;
		}
#else
		(void) master_loop(uwsgi.argv, uwsgi.environ);
#endif
		//from now on the process is a real worker
	}


	uwsgi_sock = uwsgi.sockets;
	while (uwsgi_sock) {
		struct uwsgi_string_list *usl = uwsgi.map_socket;
		int enabled = 1;
		while (usl) {

			char *colon = strchr(usl->value, ':');
			if (uwsgi_str_num(usl->value, colon - usl->value) == uwsgi_get_socket_num(uwsgi_sock)) {
				enabled = 0;
				char *p = strtok(colon + 1, ",");
				while (p != NULL) {
					int w = atoi(p);
					if (w < 1 || w > uwsgi.numproc) {
						uwsgi_log("invalid worker num: %d\n", w);
						exit(1);
					}
					if (w == uwsgi.mywid) {
						enabled = 1;
						uwsgi_log("mapped socket %d (%s) to worker %d\n", uwsgi_get_socket_num(uwsgi_sock), uwsgi_sock->name, uwsgi.mywid);
						break;
					}
					p = strtok(NULL, ",");
				}
			}

			usl = usl->next;
		}

		if (!enabled) {
			int fd = uwsgi_sock->fd;
			close(fd);
			fd = open("/dev/null", O_RDONLY);
			if (fd < 0) {
				uwsgi_error_open("/dev/null");
				exit(1);
			}
			if (fd != uwsgi_sock->fd) {
				if (dup2(fd, uwsgi_sock->fd)) {
					uwsgi_error("dup2()");
					exit(1);
				}
				close(fd);
			}
			uwsgi_sock->disabled = 1;
		}


		uwsgi_sock = uwsgi_sock->next;

	}

	uwsgi_sock = uwsgi.sockets;
	while (uwsgi_sock) {
		if (uwsgi_sock->disabled) {
			uwsgi_sock = uwsgi_del_socket(uwsgi_sock);
		}
		else {
			uwsgi_sock = uwsgi_sock->next;
		}
	}

	if (uwsgi.cpu_affinity) {
#ifdef __linux__
		cpu_set_t cpuset;
		CPU_ZERO(&cpuset);
		int ncpu = sysconf(_SC_NPROCESSORS_ONLN);
		int base_cpu = (uwsgi.mywid - 1) * uwsgi.cpu_affinity;
		if (base_cpu >= ncpu) {
			base_cpu = base_cpu % ncpu;
		}
		uwsgi_log("set cpu affinity for worker %d to", uwsgi.mywid);
		for (i = 0; i < uwsgi.cpu_affinity; i++) {
			if (base_cpu >= ncpu)
				base_cpu = 0;
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

		uwsgi.sockets->arg &= (~O_NONBLOCK);
		if (fcntl(uwsgi.sockets->fd, F_SETFL, uwsgi.sockets->arg) < 0) {
			uwsgi_error("fcntl()");
			exit(1);
		}

		if (uwsgi.sockets->fd != 0) {
			if (dup2(uwsgi.sockets->fd, 0)) {
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

	if (uwsgi.lazy) {
		uwsgi_init_all_apps();
	}

	for (i = 0; i < 0xFF; i++) {
		if (uwsgi.p[i]->post_fork) {
			uwsgi.p[i]->post_fork();
		}
	}

#ifdef UWSGI_ZEROMQ
	if (uwsgi.zmq_receiver && uwsgi.zmq_responder) {
		uwsgi.zmq_context = zmq_init(1);
		if (uwsgi.zmq_context == NULL) {
			uwsgi_error("zmq_init()");
			exit(1);
		}

		if (uwsgi.threads > 1) {
			pthread_mutex_init(&uwsgi.zmq_lock, NULL);
		}

		uwsgi.zmq_pub = zmq_socket(uwsgi.zmq_context, ZMQ_PUB);
		if (uwsgi.zmq_pub == NULL) {
			uwsgi_error("zmq_socket()");
			exit(1);
		}

		uuid_t uuid_zmq;
		char uuid_zmq_str[37];
		uuid_generate(uuid_zmq);
		uuid_unparse(uuid_zmq, uuid_zmq_str);

		uwsgi_log("%.*s\n", 36, uuid_zmq_str);
		if (zmq_setsockopt(uwsgi.zmq_pub, ZMQ_IDENTITY, uuid_zmq_str, 36) < 0) {
			uwsgi_error("zmq_setsockopt()");
			exit(1);
		}

		if (zmq_connect(uwsgi.zmq_pub, uwsgi.zmq_responder) < 0) {
			uwsgi_error("zmq_connect()");
			exit(1);
		}

		uwsgi.zmq_socket->proto = uwsgi_proto_zeromq_parser;
		uwsgi.zmq_socket->proto_accept = uwsgi_proto_zeromq_accept;
		uwsgi.zmq_socket->proto_close = uwsgi_proto_zeromq_close;
		uwsgi.zmq_socket->proto_write = uwsgi_proto_zeromq_write;
		uwsgi.zmq_socket->proto_writev = uwsgi_proto_zeromq_writev;
		uwsgi.zmq_socket->proto_write_header = uwsgi_proto_zeromq_write_header;
		uwsgi.zmq_socket->proto_writev_header = uwsgi_proto_zeromq_writev_header;
		uwsgi.zmq_socket->proto_sendfile = uwsgi_proto_zeromq_sendfile;

		uwsgi.zmq_socket->edge_trigger = 1;

		if (pthread_key_create(&uwsgi.zmq_pull, NULL)) {
			uwsgi_error("pthread_key_create()");
			exit(1);
		}

		void *tmp_zmq_pull = zmq_socket(uwsgi.zmq_context, ZMQ_PULL);
		if (tmp_zmq_pull == NULL) {
			uwsgi_error("zmq_socket()");
			exit(1);
		}
		if (zmq_connect(tmp_zmq_pull, uwsgi.zmq_receiver) < 0) {
			uwsgi_error("zmq_connect()");
			exit(1);
		}

		pthread_setspecific(uwsgi.zmq_pull, tmp_zmq_pull);

#ifdef ZMQ_FD
		size_t zmq_socket_len = sizeof(int);
		if (zmq_getsockopt(pthread_getspecific(uwsgi.zmq_pull), ZMQ_FD, &uwsgi.zmq_socket->fd, &zmq_socket_len) < 0) {
			uwsgi_error("zmq_getsockopt()");
			exit(1);
		}
#else
		uwsgi.zmq_socket->fd = -1;
#endif

		uwsgi.zmq_socket->bound = 1;
		uwsgi.zeromq_recv_flag = ZMQ_NOBLOCK;
	}
#endif

	//postpone the queue initialization as kevent
	//do not pass kfd after fork()
#ifdef UWSGI_ASYNC
	if (uwsgi.async > 1) {
		uwsgi.async_queue = event_queue_init();
		if (uwsgi.async_queue < 0) {
			exit(1);
		}

		uwsgi_add_sockets_to_queue(uwsgi.async_queue);

		uwsgi.rb_async_timeouts = uwsgi_init_rb_timer();

		uwsgi.async_queue_unused = uwsgi_malloc(sizeof(struct wsgi_request *) * uwsgi.async);

		for (i = 0; i < uwsgi.async; i++) {
			uwsgi.async_queue_unused[i] = uwsgi.wsgi_requests[i];
		}

		uwsgi.async_queue_unused_ptr = uwsgi.async - 1;

	}
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
	uwsgi_unix_signal(SIGTERM, end_me);

	if (uwsgi.auto_snapshot) {
		uwsgi_unix_signal(SIGURG, snapshot_me);
	}


	uwsgi_unix_signal(SIGUSR1, stats);

	signal(SIGUSR2, (void *) &what_i_am_doing);


	signal(SIGPIPE, (void *) &warn_pipe);

	//initialization done

	// run fixup handler
	for (i = 0; i < 0xFF; i++) {
		if (uwsgi.p[i]->fixup) {
			uwsgi.p[i]->fixup();
		}
	}

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
		while (map != NULL) {
			char *colon = strchr(map, ':');
			if (colon) {
				colon[0] = 0;
				int rm_src = atoi(map);
				int rm_dst = atoi(colon + 1);
				uwsgi.p[rm_dst]->request = uwsgi.p[rm_src]->request;
				uwsgi.p[rm_dst]->after_request = uwsgi.p[rm_src]->after_request;
			}
			map = strtok(NULL, ",");
		}
	}


#ifdef UWSGI_THREADING
	if (uwsgi.cores > 1) {
		uwsgi.core[0]->thread_id = pthread_self();
		pthread_mutex_init(&uwsgi.six_feet_under_lock, NULL);
	}
#endif

	uwsgi_ignition();

	// never here
	exit(0);

}


void uwsgi_ignition() {

	int i;

	// snapshot workers do not enter the loop until a specific signal (SIGURG) is raised...
	if (uwsgi.snapshot) {
	      wait_for_call_of_duty:
		uwsgi_sig_pause();
		if (uwsgi.snapshot)
			goto wait_for_call_of_duty;
		uwsgi_log("[snapshot] process %d is the new worker %d\n", (int) getpid(), uwsgi.mywid);
	}

	for (i = 0; i < 0xFF; i++) {
                if (uwsgi.p[i]->hijack_worker) {
                        uwsgi.p[i]->hijack_worker();
                }
        }

        for (i = 0; i < uwsgi.gp_cnt; i++) {
                if (uwsgi.gp[i]->hijack_worker) {
                        uwsgi.gp[i]->hijack_worker();
                }
        }


	if (uwsgi.loop) {
		void (*u_loop) (void) = uwsgi_get_loop(uwsgi.loop);
		if (!u_loop) {
			uwsgi_log("unavailable loop engine !!!\n");
			exit(1);
		}
		if (uwsgi.mywid == 1) {
			uwsgi_log("*** running %s loop engine [addr:%p] ***\n", uwsgi.loop, u_loop);
		}
		u_loop();
		uwsgi_log("your loop engine died. R.I.P.\n");
	}
	else {
#ifdef UWSGI_ZEROMQ
		if (uwsgi.zeromq && uwsgi.async < 2 && !uwsgi.sockets->next) {

			if (uwsgi.threads > 1) {
				if (pthread_key_create(&uwsgi.tur_key, NULL)) {
					uwsgi_error("pthread_key_create()");
					exit(1);
				}
				for (i = 1; i < uwsgi.threads; i++) {
					long j = i;
					pthread_create(&uwsgi.core[i]->thread_id, &uwsgi.threads_attr, zeromq_loop, (void *) j);
				}
			}

			long y = 0;
			zeromq_loop((void *) y);
		}
		else if (uwsgi.threads > 1) {
#else
		if (uwsgi.threads > 1) {
#endif

			if (pthread_key_create(&uwsgi.tur_key, NULL)) {
				uwsgi_error("pthread_key_create()");
				exit(1);
			}
			for (i = 1; i < uwsgi.threads; i++) {
				long j = i;
				pthread_create(&uwsgi.core[i]->thread_id, &uwsgi.threads_attr, simple_loop, (void *) j);
			}
		}

		if (uwsgi.async < 2) {
			long y = 0;
			simple_loop((void *) y);
		}
#ifdef UWSGI_ASYNC
		else {
			async_loop(NULL);
		}
#endif

	}

	if (uwsgi.snapshot) {
		uwsgi_ignition();
	}
	// never here
	pthread_exit(NULL);
}

static int manage_base_opt(int i, char *optarg) {

	char *p;
	char *docroot, *mountpoint;
	struct uwsgi_config_template *uct, *old_uct;
	struct uwsgi_cron *uc, *old_uc;
	struct uwsgi_socket *uwsgi_sock = NULL;
	int zerg_fd;
	mode_t umask_mode;

	switch (i) {

	case 0:
		return 1;
	case LONG_ARGS_PROCNAME_PREFIX:
		uwsgi.auto_procname = 1;
		uwsgi.procname_prefix = optarg;
		return 1;
	case LONG_ARGS_PROCNAME_PREFIX_SP:
		uwsgi.auto_procname = 1;
		uwsgi.procname_prefix = uwsgi_concat2(optarg, " ");
		return 1;
	case LONG_ARGS_PROCNAME_APPEND:
		uwsgi.auto_procname = 1;
		uwsgi.procname_append = optarg;
		return 1;
	case LONG_ARGS_PROCNAME:
		uwsgi.auto_procname = 1;
		uwsgi.procname = optarg;
		return 1;
	case LONG_ARGS_PROCNAME_MASTER:
		uwsgi.auto_procname = 1;
		uwsgi.procname_master = optarg;
		return 1;
#ifdef UWSGI_UDP
	case LONG_ARGS_CLUSTER_RELOAD:
		send_udp_message(98, 0, optarg, NULL, 0);
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
#ifdef UWSGI_ZEROMQ
	case LONG_ARGS_ZEROMQ:
		uwsgi.zeromq = optarg;
		return 1;
#endif
#ifdef UWSGI_SQLITE3
	case LONG_ARGS_SQLITE3:
		uwsgi.sqlite3 = optarg;
		return 1;
#endif
	case LONG_ARGS_REMAP_MODIFIER:
		uwsgi.remap_modifier = optarg;
		return 1;
	case LONG_ARGS_ALLOWED_MODIFIERS:
		uwsgi.allowed_modifiers = optarg;
		return 1;
	case LONG_ARGS_PLUGINS:
		p = strtok(uwsgi_concat2(optarg, ""), ",");
		while (p != NULL) {
#ifdef UWSGI_DEBUG
			uwsgi_debug("loading plugin %s\n", p);
#endif
			uwsgi_load_plugin(-1, p, NULL, 0);
			p = strtok(NULL, ",");
		}
		build_options();
		return 1;
	case LONG_ARGS_IDLE:
		uwsgi.idle = atoi(optarg);
		return 1;
	case LONG_ARGS_CHEAPER:
		uwsgi.master_process = 1;
		uwsgi.cheaper = 1;
		uwsgi.cheaper_count = atoi(optarg);
		return 1;
	case LONG_ARGS_CHEAPER_STEP:
		uwsgi.cheaper_step = atoi(optarg);
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
		uwsgi.has_threads = 1;
		uwsgi.threads = atoi(optarg);
		return 1;
	case LONG_ARGS_THREADS_STACKSIZE:
		uwsgi.has_threads = 1;
		uwsgi.threads_stacksize = atoi(optarg);
		return 1;
#endif
	case LONG_ARGS_PROTOCOL:
		uwsgi.protocol = optarg;
		return 1;
#ifdef UWSGI_ASYNC
	case LONG_ARGS_ASYNC:
		uwsgi.async = atoi(optarg);
		return 1;
#endif
	case LONG_ARGS_LOGTO:
		logto(optarg);
		return 1;
	case LONG_ARGS_LOGTO2:
		uwsgi.logto2 = optarg;
		return 1;
	case LONG_ARGS_EMPEROR_BROODLORD:
		uwsgi.emperor_broodlord = atoi(optarg);
		return 1;
	case LONG_ARGS_EMPEROR_THROTTLE:
		uwsgi.emperor_throttle = atoi(optarg);
		return 1;
	case LONG_ARGS_EMPEROR:
		uwsgi.emperor_dir = optarg;
		return 1;
	case LONG_ARGS_EMPEROR_AMQP_VHOST:
		uwsgi.emperor_amqp_vhost = optarg;
		return 1;
	case LONG_ARGS_EMPEROR_AMQP_USERNAME:
		uwsgi.emperor_amqp_username = optarg;
		return 1;
	case LONG_ARGS_EMPEROR_AMQP_PASSWORD:
		uwsgi.emperor_amqp_password = optarg;
		return 1;
	case LONG_ARGS_RELOAD_MERCY:
		uwsgi.reload_mercy = atoi(optarg);
		return 1;
	case LONG_ARGS_AUTO_SNAPSHOT:
		uwsgi.auto_snapshot = -1;
		if (optarg) {
			uwsgi.auto_snapshot = atoi(optarg);
		}
		uwsgi.lazy = 1;
		return 1;
	case LONG_ARGS_LOG_MAXSIZE:
		uwsgi.log_master = 1;
		uwsgi.log_maxsize = atoi(optarg);
		return 1;
	case LONG_ARGS_LOG_BACKUPNAME:
		uwsgi.log_backupname = optarg;
		return 1;
	case LONG_ARGS_LOG_MASTER:
		uwsgi.log_master = 1;
		return 1;
	case LONG_ARGS_LOG_SOCKET:
		uwsgi.log_master = 1;
		uwsgi.master_process = 1;
		uwsgi.requested_logger = uwsgi_concat2("socket:", optarg);
		return 1;
	case LONG_ARGS_LOGGER:
		uwsgi.log_master = 1;
		uwsgi.master_process = 1;
		uwsgi.requested_logger = uwsgi_str(optarg);
		return 1;
	case LONG_ARGS_LOG_SYSLOG:
		uwsgi.log_master = 1;
		uwsgi.master_process = 1;
		if (optarg) {
			uwsgi.requested_logger = uwsgi_concat2("syslog:", optarg);
		}
		else {
			uwsgi.requested_logger = "syslog";
		}
		return 1;
#ifdef UWSGI_ZEROMQ
	case LONG_ARGS_LOG_ZEROMQ:
		uwsgi.log_master = 1;
		uwsgi.master_process = 1;
		uwsgi.requested_logger = uwsgi_concat2("zeromq:", optarg);
		return 1;
#endif
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
#ifdef UWSGI_CAP
	case LONG_ARGS_CAP:
		uwsgi_build_cap(optarg);
		return 1;
#endif
#ifdef __linux__
	case LONG_ARGS_UNSHARE:
		uwsgi_build_unshare(optarg);
		return 1;
#endif
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
	case LONG_ARGS_ADD_HEADER:
		uwsgi_string_new_list(&uwsgi.additional_headers, optarg);
		return 1;
	case LONG_ARGS_MIMEFILE:
		uwsgi.mime_file = optarg;
		return 1;
	case LONG_ARGS_CHECK_STATIC:
		uwsgi_dyn_dict_new(&uwsgi.check_static, optarg, strlen(optarg), NULL, 0);
		uwsgi_log("[uwsgi-static] added check for %s\n", optarg);
		uwsgi.build_mime_dict = 1;
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
	case LONG_ARGS_PROFILER:
		uwsgi.profiler = optarg;
		return 1;
	case LONG_ARGS_INHERIT:
		uct = uwsgi.config_templates;
		if (!uct) {
			uct = uwsgi_malloc(sizeof(struct uwsgi_config_template));
			uwsgi.config_templates = uct;
		}
		else {
			old_uct = uct;
			while (uct->next) {
				uct = uct->next;
				old_uct = uct;
			}

			old_uct->next = uwsgi_malloc(sizeof(struct uwsgi_config_template));
			uct = old_uct->next;
		}

		uct->filename = optarg;
		uct->next = NULL;
		uct->applied = 0;

		return 1;
	case LONG_ARGS_VASSAL_SOS_BACKLOG:
		uwsgi.vassal_sos_backlog = atoi(optarg);
		return 1;
	case LONG_ARGS_VASSALS_START_HOOK:
		uwsgi.vassals_start_hook = optarg;
		return 1;
	case LONG_ARGS_VASSALS_STOP_HOOK:
		uwsgi.vassals_stop_hook = optarg;
		return 1;
	case LONG_ARGS_VASSALS_INHERIT:
		uct = uwsgi.vassals_templates;
		if (!uct) {
			uct = uwsgi_malloc(sizeof(struct uwsgi_config_template));
			uwsgi.vassals_templates = uct;
		}
		else {
			old_uct = uct;
			while (uct->next) {
				uct = uct->next;
				old_uct = uct;
			}

			old_uct->next = uwsgi_malloc(sizeof(struct uwsgi_config_template));
			uct = old_uct->next;
		}

		uct->filename = optarg;
		uct->next = NULL;

		return 1;
	case LONG_ARGS_CRON:
		uwsgi.master_process = 1;
		uc = uwsgi.crons;
		if (!uc) {
			uc = uwsgi_malloc(sizeof(struct uwsgi_cron));
			uwsgi.crons = uc;
		}
		else {
			old_uc = uc;
			while(uc->next) {
				uc = uc->next;
				old_uc = uc;
			}

			old_uc->next = uwsgi_malloc(sizeof(struct uwsgi_cron));
			uc = old_uc->next;
		}

		memset(uc, 0, sizeof(struct uwsgi_cron));

		if (sscanf(optarg, "%d %d %d %d %d %n", &uc->minute, &uc->hour, &uc->day, &uc->month, &uc->week, &i) != 5) {
			uwsgi_log("invalid cron syntax\n");
			exit(1);
		}	
		uc->command = optarg+i;
		return 1;
	case LONG_ARGS_STATIC_SKIP_EXT:
		uwsgi_string_new_list(&uwsgi.static_skip_ext, optarg);
		return 1;
	case LONG_ARGS_STATIC_INDEX:
		uwsgi_string_new_list(&uwsgi.static_index, optarg);
		return 1;
	case LONG_ARGS_STATIC_MAP:
		mountpoint = uwsgi_str(optarg);
		docroot = strchr(mountpoint, '=');
		if (!docroot) {
			uwsgi_log("invalid document root in static map, syntax mountpoint=docroot\n");
			exit(1);
		}
		docroot[0] = 0;
		docroot++;
		uwsgi_dyn_dict_new(&uwsgi.static_maps, mountpoint, strlen(mountpoint), docroot, strlen(docroot));
		uwsgi_log("[uwsgi-static] added mapping for %s => %s\n", mountpoint, docroot);
		uwsgi.build_mime_dict = 1;
		return 1;
	case LONG_ARGS_STOP:
		signal_pidfile(SIGINT, optarg);
		exit(0);
	case LONG_ARGS_RELOAD:
		signal_pidfile(SIGHUP, optarg);
		exit(0);
	case LONG_ARGS_PAUSE:
		signal_pidfile(SIGTSTP, optarg);
		exit(0);
	case LONG_ARGS_ATTACH_DAEMON:
		uwsgi_daemon_new(&uwsgi.daemons, optarg);
		return 1;
	case LONG_ARGS_SUBSCRIBE_TO:
		uwsgi.master_process = 1;
		uwsgi_string_new_list(&uwsgi.subscriptions, optarg);
		uwsgi_log("[uwsgi-subscription] subscribed to %s\n", optarg);
		return 1;
	case LONG_ARGS_SUBSCR_TOLERANCE:
		uwsgi.subscription_tolerance = atoi(optarg);
		return 1;
	case LONG_ARGS_SUBSCRIBE_FREQ:
		uwsgi.subscribe_freq = atoi(optarg);
		return 1;
#ifdef __linux__
	case LONG_ARGS_CGROUP:
		uwsgi_string_new_list(&uwsgi.cgroup, optarg);
		return 1;
	case LONG_ARGS_CGROUP_OPT:
		uwsgi_string_new_list(&uwsgi.cgroup_opt, optarg);
		return 1;
	case LONG_ARGS_LINUX_NS:
		uwsgi.ns = optarg;
		return 1;
	case LONG_ARGS_LINUX_NS_NET:
		uwsgi.ns_net = optarg;
		return 1;
#endif
	case LONG_ARGS_LIMIT_AS:
		uwsgi.rl.rlim_cur = (strtoul(optarg, NULL, 10)) * 1024 * 1024;
		uwsgi.rl.rlim_max = uwsgi.rl.rlim_cur;
		return 1;
	case LONG_ARGS_LIMIT_POST:
		uwsgi.limit_post = (int) strtol(optarg, NULL, 10);
		return 1;
#ifdef __linux__
#ifdef MADV_MERGEABLE
	case LONG_ARGS_KSM:
		uwsgi.linux_ksm = 1;
		if (optarg) {
			uwsgi.linux_ksm = atoi(optarg);
		}
		return 1;
#endif
#endif
	case LONG_ARGS_RELOAD_ON_AS:
		uwsgi.force_get_memusage = 1;
		uwsgi.reload_on_as = (strtoul(optarg, NULL, 10)) * 1024 * 1024;
		return 1;
	case LONG_ARGS_RELOAD_ON_RSS:
		uwsgi.force_get_memusage = 1;
		uwsgi.reload_on_rss = (strtoul(optarg, NULL, 10)) * 1024 * 1024;
		return 1;
	case LONG_ARGS_EVIL_RELOAD_ON_AS:
		uwsgi.master_process = 1;
		uwsgi.force_get_memusage = 1;
		uwsgi.evil_reload_on_as = (strtoul(optarg, NULL, 10)) * 1024 * 1024;
		return 1;
	case LONG_ARGS_EVIL_RELOAD_ON_RSS:
		uwsgi.master_process = 1;
		uwsgi.force_get_memusage = 1;
		uwsgi.evil_reload_on_rss = (strtoul(optarg, NULL, 10)) * 1024 * 1024;
		return 1;
	case LONG_ARGS_TOUCH_RELOAD:
		uwsgi_string_new_list(&uwsgi.touch_reload, optarg);
		uwsgi.master_process = 1;
		return 1;
	case LONG_ARGS_EXEC_AS_ROOT:
		uwsgi_string_new_list(&uwsgi.exec_as_root, optarg);
		return 1;
	case LONG_ARGS_EXEC_AS_USER:
		uwsgi_string_new_list(&uwsgi.exec_as_user, optarg);
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
#ifdef UWSGI_JSON
	case 'j':
		uwsgi.json = optarg;
		return 1;
#endif
#ifdef UWSGI_INI
	case LONG_ARGS_INI:
		uwsgi_string_new_list(&uwsgi.ini, optarg);
		return 1;
#endif
	case LONG_ARGS_LOCKS:
		uwsgi.locks = atoi(optarg);
		return 1;
	case LONG_ARGS_MULE:
		uwsgi.master_process = 1;
		uwsgi.mules_cnt++;
		uwsgi_string_new_list(&uwsgi.mules_patches, optarg);
		return 1;
	case LONG_ARGS_SIGNAL:
		uwsgi_command_signal(optarg);
		return 1;
	case LONG_ARGS_SIGNAL_BUFSIZE:
		uwsgi.signal_bufsize = atoi(optarg);
		return 1;
	case LONG_ARGS_MULES:
		uwsgi.master_process = 1;
		for(i=0;i<atoi(optarg);i++) {
			uwsgi.mules_cnt++;
			uwsgi_string_new_list(&uwsgi.mules_patches, optarg);
		}
		return 1;
	case LONG_ARGS_FARM:
		uwsgi.master_process = 1;
		uwsgi.farms_cnt++;
		uwsgi_string_new_list(&uwsgi.farms_list, optarg);
		return 1;
	case LONG_ARGS_SOCKET_PROTOCOL:
		// TODO map each socket to a specific protocol
		return 1;
	case LONG_ARGS_MAP_SOCKET:
		p = strchr(optarg, ':');
		if (!p) {
			uwsgi_log("invalid map-socket syntax, must be socketnum:workerN[,workerN...]\n");
			exit(1);
		}
		uwsgi_string_new_list(&uwsgi.map_socket, optarg);
		return 1;
	case LONG_ARGS_CHECK_INTERVAL:
		uwsgi.shared->options[UWSGI_OPTION_MASTER_INTERVAL] = atoi(optarg);
		return 1;
	case LONG_ARGS_CACHE_SERVER:
		uwsgi.cache_server = optarg;
		return 1;
	case LONG_ARGS_STATS:
		uwsgi.stats = optarg;
		uwsgi.master_process = 1;
		return 1;
	case LONG_ARGS_EMPEROR_STATS:
		uwsgi.emperor_stats = optarg;
		return 1;
	case LONG_ARGS_CACHE_SERVER_THREADS:
		uwsgi.cache_server_threads = atoi(optarg);
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
		}
		else {
			uwsgi_log("you can specify at most %d --mount options\n", MAX_APPS);
		}
		return 1;
#ifdef UWSGI_PCRE
	case LONG_ARGS_REGEXP_MOUNT:
		if (uwsgi.mounts_cnt < MAX_APPS) {
			uwsgi.mounts[uwsgi.mounts_cnt] = uwsgi_concat2("regexp://", optarg);
			uwsgi.mounts_cnt++;
		}
		else {
			uwsgi_log("you can specify at most %d --regexp-mount options\n", MAX_APPS);
		}
		return 1;
#endif
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
		// do not daemonize in emperor mode
		if (uwsgi.has_emperor) {
			logto(optarg);
		}
		else {
			if (!uwsgi.is_a_reload) {
				daemonize(optarg);
			}
			else if (uwsgi.log_reopen) {
				logto(optarg);
			}
		}
		return 1;
	case 's':
		uwsgi_sock = uwsgi_new_socket(generate_socket_name(optarg));
		uwsgi_sock->proto_name = "uwsgi";
		return 1;
	case 'S':
		p = strchr(optarg, '=');
		if (!p) {
			uwsgi_log("invalid --set value\n");
			exit(1);
		}
		p[0] = 0;
		add_exported_option(uwsgi_str(optarg), p+1, 1);
		p[0] = '=';
		return 1;
	case LONG_ARGS_HTTP_SOCKET:
		uwsgi_sock = uwsgi_new_socket(generate_socket_name(optarg));
		uwsgi_sock->proto_name = "http";
		return 1;
	case LONG_ARGS_FASTCGI_SOCKET:
		uwsgi_sock = uwsgi_new_socket(generate_socket_name(optarg));
		uwsgi_sock->proto_name = "fastcgi";
		return 1;
	case LONG_ARGS_ZERG:
		zerg_fd = uwsgi_connect(optarg, 30, 0);
		if (zerg_fd < 0) {
			uwsgi_log("--- unable to connect to zerg server ---\n");
			exit(1);
		}
		uwsgi.zerg = uwsgi_attach_fd(zerg_fd, 8, "uwsgi-zerg", 11);
		if (uwsgi.zerg == NULL) {
			uwsgi_log("--- invalid data received from zerg-server ---\n");
			exit(1);
		}
		close(zerg_fd);
		return 1;
	case LONG_ARGS_ZERG_SERVER:
		uwsgi.zerg_server = optarg;
		uwsgi.master_process = 1;
		return 1;
	case LONG_ARGS_SHARED_SOCKET:
		uwsgi_new_shared_socket(generate_socket_name(optarg));
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
						uwsgi.numproc = (sysconf(_SC_NPROCESSORS_ONLN)) * 2;
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
#ifdef UWSGI_SPOOLER
	case LONG_ARGS_SPOOLER_HARAKIRI:
		uwsgi.shared->options[UWSGI_OPTION_SPOOLER_HARAKIRI] = atoi(optarg);
		return 1;
	case LONG_ARGS_SPOOLER_CHDIR:
		uwsgi.spooler_chdir = optarg;
		return 1;
#endif
	case LONG_ARGS_MULE_HARAKIRI:
		uwsgi.shared->options[UWSGI_OPTION_MULE_HARAKIRI] = atoi(optarg);
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
	case LONG_ARGS_CHOWN_SOCKET:
		uwsgi.chown_socket = optarg;
		return 1;
	case LONG_ARGS_UMASK:
		if (strlen(optarg) < 3) {
			uwsgi_log("invalid umask: %s\n", optarg);
		}
		umask_mode = 0;
		if (strlen(optarg) == 3) {
			umask_mode = (umask_mode << 3) + (optarg[0] - '0');
			umask_mode = (umask_mode << 3) + (optarg[1] - '0');
			umask_mode = (umask_mode << 3) + (optarg[2] - '0');
		}	
		else {
			umask_mode = (umask_mode << 3) + (optarg[1] - '0');
			umask_mode = (umask_mode << 3) + (optarg[2] - '0');
			umask_mode = (umask_mode << 3) + (optarg[3] - '0');
		}
		umask(umask_mode);
		return 1;
	case LONG_ARGS_LOGFILE_CHMOD:
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

                uwsgi.chmod_logfile_value = (uwsgi.chmod_logfile_value << 3) + (optarg[0] - '0');
                uwsgi.chmod_logfile_value = (uwsgi.chmod_logfile_value << 3) + (optarg[1] - '0');
                uwsgi.chmod_logfile_value = (uwsgi.chmod_logfile_value << 3) + (optarg[2] - '0');

		return 1;
	case 'C':
		uwsgi.chmod_socket = 1;
		if (optarg) {
			if (strlen(optarg) == 1 && *optarg == '1') {
				return 1;
			}
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

void manage_opt(int i, char *p) {
	int j;

	if (manage_base_opt(i, p)) {
                        return;
                }

                for (j = 0; j < 0xFF; j++) {
                        if (uwsgi.p[j]->manage_opt) {
                                if (uwsgi.p[j]->manage_opt(i, p)) {
                                        return;
                                }
                        }
                }

                for (j = 0; j < uwsgi.gp_cnt; j++) {
                        if (uwsgi.gp[j]->manage_opt) {
                                if (uwsgi.gp[j]->manage_opt(i, p)) {
                                        return;
                                }
                        }
                }

	// never here
	exit(1);
}

void build_options() {
	int i;
	struct option *lopt, *aopt;
	char *so_ptr;

	int opt_count = count_options(long_base_options);
	size_t short_opt_size = strlen(base_short_options);

	for (i = 0; i < 0xFF; i++) {
		if (uwsgi.p[i]->short_options) {
			short_opt_size += strlen(uwsgi.p[i]->short_options);
		}
	}

	for (i = 0; i < uwsgi.gp_cnt; i++) {
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

#ifdef UWSGI_DEBUG
	uwsgi_log("%s = %s\n", key2, val2);
#endif
	add_exported_option(key2, val2, 0);
}


void uwsgi_stdin_sendto(char *socket_name, uint8_t modifier1, uint8_t modifier2) {

	char buf[4096];
	ssize_t rlen;
	size_t delta = 4096-4;
	// leave space for uwsgi header
	char *ptr = buf+4;

	rlen = read(0, ptr, delta);
	while (rlen > 0) {
		uwsgi_log("%.*s\n", rlen, ptr);
		ptr += rlen;
		delta -= rlen;
		if (delta <= 0)
			break;
		rlen = read(0, ptr, delta);
	}

	if (ptr > buf+4) {
		send_udp_message(modifier1, modifier2, socket_name, buf, (ptr - buf)-4);
		uwsgi_log("sent string \"%.*s\" to cluster node %s", (ptr - buf)-4, buf+4, socket_name);
	}

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
	{"memory-report", "enable memory usage report"},
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
	{"loop <engine>", "use the <engine> loop engine"},
	{"worker-exec <command>", "execve() <command> after each worker's fork()"},
	{"autoload", "try to automatically load plugins"},
	{"lazy", "load applications after each worker's fork()"},
	{"cheap", "postpone workers startup until the first request"},
	{"idle <secs>", "destroy workers (the server will go in cheap mode) after <secs> of inactivity"},
	{"freebind (Linux only)", "allows binding on non-existent network address"},
	{"xml <file>", "load config from an xml file"},
	{"protocol <proto>", "set the default communication protocol (uwsgi, http, fastcgi)"},
	{"reuse-port (BSD only)", "allows multiple instances bining on the same address"},
	{"set KEY=VALUE", "set a placeholder"},
	{"reload-mercy <secs>", "brutally kill workers not reloading in <secs>"},
	{"emperor <dir|glob>", "start the emperor monitoring <dir|glob>"},
	{"touch-reload <file>", "issue a graceful reload on <file> modifications/touch"},

	{0, 0},

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

	while ((uhi = all_help)) {

		if (uhi->key == 0)
			break;

		if ((int) strlen(uhi->key) > max_size) {
			max_size = (int) strlen(uhi->key);
		}

		all_help++;
	}


	for (i = 0; i < 0xFF; i++) {
		if (uwsgi.p[i]->help) {

			all_help = uwsgi.p[i]->help;
			while ((uhi = all_help)) {
				if (uhi->key == 0)
					break;
				if ((int) strlen(uhi->key) > max_size)
					max_size = (int) strlen(uhi->key);
				all_help++;
			}

		}
	}

	for (i = 0; i < uwsgi.gp_cnt; i++) {
		if (uwsgi.gp[i]->help) {

			all_help = uwsgi.gp[i]->help;
			while ((uhi = all_help)) {
				if (uhi->key == 0)
					break;
				if ((int) strlen(uhi->key) > max_size)
					max_size = (int) strlen(uhi->key);
				all_help++;
			}

		}
	}

	fprintf(stdout, "Usage: %s [options...]\n", uwsgi.binary_path);

	lopt = uwsgi.long_options;

	max_size += 4;

	while (lopt->name) {

		found = 0;

		all_help = main_help;
		while ((uhi = all_help)) {
			if (uhi->key == 0)
				break;

			tmp_option = uwsgi_concat2(uhi->key, "");
			space = strchr(tmp_option, ' ');
			if (!space)
				space = strstr(tmp_option, "[=");
			if (space)
				space[0] = 0;

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
					while ((uhi = all_help)) {
						if (uhi->key == 0)
							break;
						tmp_option = uwsgi_concat2(uhi->key, "");
						space = strchr(tmp_option, ' ');
						if (!space)
							space = strstr(tmp_option, "[=");
						if (space)
							space[0] = 0;

						if (!strcmp(tmp_option, lopt->name)) {
							found = 1;
							break;
						}

						free(tmp_option);
						all_help++;
					}
				}
				if (found)
					break;
			}
		}

		if (!found) {
			for (i = 0; i < uwsgi.gp_cnt; i++) {
				if (uwsgi.gp[i]->help) {
					all_help = uwsgi.gp[i]->help;
					while ((uhi = all_help)) {
						if (uhi->key == 0)
							break;
						tmp_option = uwsgi_concat2(uhi->key, "");
						space = strchr(tmp_option, ' ');
						if (!space)
							space = strstr(tmp_option, "[=");
						if (space)
							space[0] = 0;

						if (!strcmp(tmp_option, lopt->name)) {
							found = 1;
							break;
						}

						free(tmp_option);
						all_help++;
					}
				}
				if (found)
					break;
			}
		}


		if (found) {
			if (!lopt->flag && ((lopt->val >= 'a' && lopt->val <= 'z') || (lopt->val >= 'A' && lopt->val <= 'Z'))) {
				fprintf(stdout, "    -%c|--%-*s %s\n", lopt->val, max_size - 3, uhi->key, uhi->value);
			}
			else {
				fprintf(stdout, "    --%-*s %s\n", max_size, uhi->key, uhi->value);
			}
			if (tmp_option)
				free(tmp_option);
		}
		else {
			fprintf(stdout, "    --%-*s *** UNDOCUMENTED OPTION ***\n", max_size, lopt->name);
		}

		lopt++;
	}

	exit(0);
}

void uwsgi_init_all_apps() {

	int i, j;

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
		uwsgi_xml_config(uwsgi.xml_config, uwsgi.wsgi_req, 1, NULL);
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
					if (!uwsgi_startswith(uwsgi.mounts[i], "regexp://", 9)) {
						if (uwsgi.p[j]->mount_app(uwsgi.mounts[i]+9, what, 1) != -1)
							break;
					}
					else {
						if (uwsgi.p[j]->mount_app(uwsgi.mounts[i], what, 0) != -1)
							break;
					}
				}
			}
			what--;
			what[0] = '=';
		}
		else {
			uwsgi_log("invalid mountpoint: %s\n", uwsgi.mounts[i]);
			exit(1);
		}
	}

	// no app initialized and virtualhosting enabled
	if (uwsgi_apps_cnt == 0) {
		uwsgi_log("*** no app loaded. going in full dynamic mode ***\n");
	}

}
