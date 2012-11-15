/*

 *** uWSGI ***

 Copyright (C) 2009-2012 Unbit S.a.s. <info@unbit.it>

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

UWSGI_DECLARE_EMBEDDED_PLUGINS;

static struct uwsgi_option uwsgi_base_options[] = {
	{"socket", required_argument, 's', "bind to the specified UNIX/TCP socket using default protocol", uwsgi_opt_add_socket, NULL, 0},
	{"uwsgi-socket", required_argument, 's', "bind to the specified UNIX/TCP socket using uwsgi protocol", uwsgi_opt_add_socket, "uwsgi", 0},
	{"http-socket", required_argument, 0, "bind to the specified UNIX/TCP socket using HTTP protocol", uwsgi_opt_add_socket, "http", 0},
	{"fastcgi-socket", required_argument, 0, "bind to the specified UNIX/TCP socket using FastCGI protocol", uwsgi_opt_add_socket, "fastcgi", 0},
	{"protocol", required_argument, 0, "force the specified protocol for default sockets", uwsgi_opt_set_str, &uwsgi.protocol, 0},
	{"socket-protocol", required_argument, 0, "force the specified protocol for default sockets", uwsgi_opt_set_str, &uwsgi.protocol, 0},
	{"shared-socket", required_argument, 0, "create a shared sacket for advanced jailing or ipc", uwsgi_opt_add_shared_socket, NULL, 0},
	{"undeferred-shared-socket", required_argument, 0, "create a shared sacket for advanced jailing or ipc (undeferred mode)", uwsgi_opt_add_shared_socket, NULL, 0},
	{"processes", required_argument, 'p', "spawn the specified number of workers/processes", uwsgi_opt_set_int, &uwsgi.numproc, 0},
	{"workers", required_argument, 'p', "spawn the specified number of workers/processes", uwsgi_opt_set_int, &uwsgi.numproc, 0},
	{"harakiri", required_argument, 't', "set harakiri timeout", uwsgi_opt_set_dyn, (void *) UWSGI_OPTION_HARAKIRI, 0},
	{"harakiri-verbose", no_argument, 0, "enable verbose mode for harakiri", uwsgi_opt_true, &uwsgi.harakiri_verbose, 0},
	{"harakiri-no-arh", no_argument, 0, "do not enable harakiri during after-request-hook", uwsgi_opt_true, &uwsgi.harakiri_no_arh, 0},
	{"no-harakiri-arh", no_argument, 0, "do not enable harakiri during after-request-hook", uwsgi_opt_true, &uwsgi.harakiri_no_arh, 0},
	{"no-harakiri-after-req-hook", no_argument, 0, "do not enable harakiri during after-request-hook", uwsgi_opt_true, &uwsgi.harakiri_no_arh, 0},
	{"backtrace-depth", no_argument, 0, "set backtrace depth", uwsgi_opt_set_int, &uwsgi.backtrace_depth, 0},
	{"mule-harakiri", required_argument, 0, "set harakiri timeout for mule tasks", uwsgi_opt_set_dyn, (void *) UWSGI_OPTION_MULE_HARAKIRI, 0},
#ifdef UWSGI_XML
	{"xmlconfig", required_argument, 'x', "load config from xml file", uwsgi_opt_load_xml, NULL, UWSGI_OPT_IMMEDIATE},
	{"xml", required_argument, 'x', "load config from xml file", uwsgi_opt_load_xml, NULL, UWSGI_OPT_IMMEDIATE},
#endif

	{"skip-zero", no_argument, 0, "skip check of file descriptor 0", uwsgi_opt_true, &uwsgi.skip_zero, 0},

	{"set", required_argument, 'S', "set a custom placeholder", uwsgi_opt_set_placeholder, NULL, UWSGI_OPT_IMMEDIATE},
	{"declare-option", required_argument, 0, "declare a new uWSGI custom option", uwsgi_opt_add_custom_option, NULL, UWSGI_OPT_IMMEDIATE},

	{"for", required_argument, 0, "(opt logic) for cycle", uwsgi_opt_logic, (void *) uwsgi_logic_opt_for, UWSGI_OPT_IMMEDIATE},
	{"endfor", optional_argument, 0, "(opt logic) end for cycle", uwsgi_opt_noop, NULL, UWSGI_OPT_IMMEDIATE},

	{"if-opt", required_argument, 0, "(opt logic) check for option", uwsgi_opt_logic, (void *) uwsgi_logic_opt_if_opt, UWSGI_OPT_IMMEDIATE},
	{"if-not-opt", required_argument, 0, "(opt logic) check for option", uwsgi_opt_logic, (void *) uwsgi_logic_opt_if_not_opt, UWSGI_OPT_IMMEDIATE},

	{"if-env", required_argument, 0, "(opt logic) check for environment variable", uwsgi_opt_logic, (void *) uwsgi_logic_opt_if_env, UWSGI_OPT_IMMEDIATE},
	{"if-not-env", required_argument, 0, "(opt logic) check for environment variable", uwsgi_opt_logic, (void *) uwsgi_logic_opt_if_not_env, UWSGI_OPT_IMMEDIATE},
	{"ifenv", required_argument, 0, "(opt logic) check for environment variable", uwsgi_opt_logic, (void *) uwsgi_logic_opt_if_env, UWSGI_OPT_IMMEDIATE},

	{"if-reload", no_argument, 0, "(opt logic) check for reload", uwsgi_opt_logic, (void *) uwsgi_logic_opt_if_reload, UWSGI_OPT_IMMEDIATE},
	{"if-not-reload", no_argument, 0, "(opt logic) check for reload", uwsgi_opt_logic, (void *) uwsgi_logic_opt_if_not_reload, UWSGI_OPT_IMMEDIATE},

	{"if-exists", required_argument, 0, "(opt logic) check for file/directory existance", uwsgi_opt_logic, (void *) uwsgi_logic_opt_if_exists, UWSGI_OPT_IMMEDIATE},
	{"if-not-exists", required_argument, 0, "(opt logic) check for file/directory existance", uwsgi_opt_logic, (void *) uwsgi_logic_opt_if_not_exists, UWSGI_OPT_IMMEDIATE},
	{"ifexists", required_argument, 0, "(opt logic) check for file/directory existance", uwsgi_opt_logic, (void *) uwsgi_logic_opt_if_exists, UWSGI_OPT_IMMEDIATE},

	{"if-file", required_argument, 0, "(opt logic) check for file existance", uwsgi_opt_logic, (void *) uwsgi_logic_opt_if_file, UWSGI_OPT_IMMEDIATE},
	{"if-not-file", required_argument, 0, "(opt logic) check for file existance", uwsgi_opt_logic, (void *) uwsgi_logic_opt_if_not_file, UWSGI_OPT_IMMEDIATE},
	{"if-dir", required_argument, 0, "(opt logic) check for directory existance", uwsgi_opt_logic, (void *) uwsgi_logic_opt_if_dir, UWSGI_OPT_IMMEDIATE},
	{"if-not-dir", required_argument, 0, "(opt logic) check for directory existance", uwsgi_opt_logic, (void *) uwsgi_logic_opt_if_not_dir, UWSGI_OPT_IMMEDIATE},

	{"ifdir", required_argument, 0, "(opt logic) check for directory existance", uwsgi_opt_logic, (void *) uwsgi_logic_opt_if_dir, UWSGI_OPT_IMMEDIATE},
	{"if-directory", required_argument, 0, "(opt logic) check for directory existance", uwsgi_opt_logic, (void *) uwsgi_logic_opt_if_dir, UWSGI_OPT_IMMEDIATE},

	{"endif", optional_argument, 0, "(opt logic) end if", uwsgi_opt_noop, NULL, UWSGI_OPT_IMMEDIATE},

	{"ignore-sigpipe", no_argument, 0, "do not report (annoying) SIGPIPE", uwsgi_opt_true, &uwsgi.ignore_sigpipe, 0},
	{"ignore-write-errors", no_argument, 0, "do not report (annoying) write()/writev() errors", uwsgi_opt_true, &uwsgi.ignore_write_errors, 0},
	{"write-errors-tolerance", required_argument, 0, "set the maximum number of allowed write errors (default: no tolerance)", uwsgi_opt_set_int, &uwsgi.write_errors_tolerance, 0},
	{"write-errors-exception-only", no_argument, 0, "only raise an exception on write errors giving control to the app itself", uwsgi_opt_true, &uwsgi.write_errors_exception_only, 0},
	{"disable-write-exception", no_argument, 0, "disable exception generation on write()/writev()", uwsgi_opt_true, &uwsgi.disable_write_exception, 0},

	{"inherit", required_argument, 0, "use the specified file as config template", uwsgi_opt_load, NULL, 0},
	{"include", required_argument, 0, "include the specified file as immediate configuration", uwsgi_opt_load, NULL, UWSGI_OPT_IMMEDIATE},
	{"daemonize", required_argument, 'd', "daemonize uWSGI", uwsgi_opt_set_str, &uwsgi.daemonize, 0},
	{"daemonize2", required_argument, 0, "daemonize uWSGI after app loading", uwsgi_opt_set_str, &uwsgi.daemonize2, 0},
	{"stop", required_argument, 0, "stop an instance", uwsgi_opt_pidfile_signal, (void *) SIGINT, UWSGI_OPT_IMMEDIATE},
	{"reload", required_argument, 0, "reload an instance", uwsgi_opt_pidfile_signal, (void *) SIGHUP, UWSGI_OPT_IMMEDIATE},
	{"pause", required_argument, 0, "pause an instance", uwsgi_opt_pidfile_signal, (void *) SIGTSTP, UWSGI_OPT_IMMEDIATE},
	{"suspend", required_argument, 0, "suspend an instance", uwsgi_opt_pidfile_signal, (void *) SIGTSTP, UWSGI_OPT_IMMEDIATE},
	{"resume", required_argument, 0, "resume an instance", uwsgi_opt_pidfile_signal, (void *) SIGTSTP, UWSGI_OPT_IMMEDIATE},

	{"connect-and-read", required_argument, 0, "connect to a scoekt and wait for data from it", uwsgi_opt_connect_and_read, NULL, UWSGI_OPT_IMMEDIATE},

	{"listen", required_argument, 'l', "set the socket listen queue size", uwsgi_opt_set_int, &uwsgi.listen_queue, 0},
	{"max-vars", required_argument, 'v', "set the amount of internal iovec/vars structures", uwsgi_opt_max_vars, NULL, 0},
	{"max-apps", required_argument, 0, "set the maximum number of per-worker applications", uwsgi_opt_set_int, &uwsgi.max_apps, 0},
	{"buffer-size", required_argument, 'b', "set internal buffer size", uwsgi_opt_set_int, &uwsgi.buffer_size, 0},
	{"memory-report", no_argument, 'm', "enable memory report", uwsgi_opt_dyn_true, (void *) UWSGI_OPTION_MEMORY_DEBUG, 0},
	{"profiler", required_argument, 0, "enable the specified profiler", uwsgi_opt_set_str, &uwsgi.profiler, 0},
	{"cgi-mode", no_argument, 'c', "force CGI-mode for plugins supporting it", uwsgi_opt_dyn_true, (void *) UWSGI_OPTION_CGI_MODE, 0},
	{"abstract-socket", no_argument, 'a', "force UNIX socket in abstract mode (Linux only)", uwsgi_opt_true, &uwsgi.abstract_socket, 0},
	{"chmod-socket", optional_argument, 'C', "chmod-socket", uwsgi_opt_chmod_socket, NULL, 0},
	{"chmod", optional_argument, 'C', "chmod-socket", uwsgi_opt_chmod_socket, NULL, 0},
	{"chown-socket", required_argument, 0, "chown unix sockets", uwsgi_opt_set_str, &uwsgi.chown_socket, 0},
	{"umask", required_argument, 0, "set umask", uwsgi_opt_set_umask, NULL, UWSGI_OPT_IMMEDIATE},
#ifdef __linux__
	{"freebind", no_argument, 0, "put socket in freebind mode", uwsgi_opt_true, &uwsgi.freebind, 0},
#endif
	{"map-socket", required_argument, 0, "map sockets to specific workers", uwsgi_opt_add_string_list, &uwsgi.map_socket, 0},
#ifdef UWSGI_THREADING
	{"enable-threads", no_argument, 'T', "enable threads", uwsgi_opt_true, &uwsgi.has_threads, 0},
	{"no-threads-wait", no_argument, 0, "do not wait for threads cancellation on quit/reload", uwsgi_opt_true, &uwsgi.no_threads_wait, 0},
#endif

	{"auto-procname", no_argument, 0, "automatically set processes name to something meaningful", uwsgi_opt_true, &uwsgi.auto_procname, 0},
	{"procname-prefix", required_argument, 0, "add a prefix to the process names", uwsgi_opt_set_str, &uwsgi.procname_prefix, UWSGI_OPT_PROCNAME},
	{"procname-prefix-spaced", required_argument, 0, "add a spaced prefix to the process names", uwsgi_opt_set_str_spaced, &uwsgi.procname_prefix, UWSGI_OPT_PROCNAME},
	{"procname-append", required_argument, 0, "append a string to process names", uwsgi_opt_set_str, &uwsgi.procname_append, UWSGI_OPT_PROCNAME},
	{"procname", required_argument, 0, "set process names", uwsgi_opt_set_str, &uwsgi.procname, UWSGI_OPT_PROCNAME},
	{"procname-master", required_argument, 0, "set master process name", uwsgi_opt_set_str, &uwsgi.procname_master, UWSGI_OPT_PROCNAME},

	{"single-interpreter", no_argument, 'i', "do not use multiple interpreters (where available)", uwsgi_opt_true, &uwsgi.single_interpreter, 0},
	{"need-app", no_argument, 0, "exit if no app can be loaded", uwsgi_opt_true, &uwsgi.need_app, 0},
	{"master", no_argument, 'M', "enable master process", uwsgi_opt_true, &uwsgi.master_process, 0},
	{"emperor", required_argument, 0, "run the Emperor", uwsgi_opt_add_string_list, &uwsgi.emperor, 0},
	{"emperor-freq", required_argument, 0, "set the Emperor scan frequency (default 3 seconds)", uwsgi_opt_set_int, &uwsgi.emperor_freq, 0},
	{"emperor-required-heartbeat", required_argument, 0, "set the Emperor tolerance about heartbeats", uwsgi_opt_set_int, &uwsgi.emperor_heartbeat, 0},
	{"emperor-pidfile", required_argument, 0, "write the Emperor pid in the specified file", uwsgi_opt_set_str, &uwsgi.emperor_pidfile, 0},
	{"emperor-tyrant", no_argument, 0, "put the Emperor in Tyrant mode", uwsgi_opt_true, &uwsgi.emperor_tyrant, 0},
	{"emperor-stats", required_argument, 0, "run the Emperor stats server", uwsgi_opt_set_str, &uwsgi.emperor_stats, 0},
	{"emperor-stats-server", required_argument, 0, "run the Emperor stats server", uwsgi_opt_set_str, &uwsgi.emperor_stats, 0},
	{"early-emperor", no_argument, 0, "spawn the emperor as soon as possibile", uwsgi_opt_true, &uwsgi.early_emperor, 0},
	{"emperor-broodlord", required_argument, 0, "run the emperor in BroodLord mode", uwsgi_opt_set_int, &uwsgi.emperor_broodlord, 0},
	{"emperor-throttle", required_argument, 0, "set throttling level (in milliseconds) for bad behaving vassals (default 1000)", uwsgi_opt_set_int, &uwsgi.emperor_throttle, 0},
	{"emperor-max-throttle", required_argument, 0, "set max throttling level (in milliseconds) for bad behaving vassals (default 3 minutes)", uwsgi_opt_set_int, &uwsgi.emperor_max_throttle, 0},
	{"emperor-magic-exec", no_argument, 0, "prefix vassals config files with exec:// if they have the executable bit", uwsgi_opt_true, &uwsgi.emperor_magic_exec, 0},
	{"imperial-monitor-list", no_argument, 0, "list enabled imperial monitors", uwsgi_opt_true, &uwsgi.imperial_monitor_list, 0},
	{"imperial-monitors-list", no_argument, 0, "list enabled imperial monitors", uwsgi_opt_true, &uwsgi.imperial_monitor_list, 0},
	{"vassals-inherit", required_argument, 0, "add config templates to vassals config", uwsgi_opt_add_string_list, &uwsgi.vassals_templates, 0},
	{"vassals-start-hook", required_argument, 0, "run the specified command before each vassal starts", uwsgi_opt_set_str, &uwsgi.vassals_start_hook, 0},
	{"vassals-stop-hook", required_argument, 0, "run the specified command after vassal's death", uwsgi_opt_set_str, &uwsgi.vassals_stop_hook, 0},
	{"vassal-sos-backlog", required_argument, 0, "ask emperor for sos if backlog queue has more items than the value specified", uwsgi_opt_set_int, &uwsgi.vassal_sos_backlog, 0},
	{"heartbeat", required_argument, 0, "announce healtness to the emperor", uwsgi_opt_set_int, &uwsgi.heartbeat, 0},
	{"auto-snapshot", optional_argument, 0, "automatically make workers snaphost after reload", uwsgi_opt_set_int, &uwsgi.auto_snapshot, UWSGI_OPT_LAZY},
	{"reload-mercy", required_argument, 0, "set the maximum time (in seconds) a worker can take to reload/shutdown", uwsgi_opt_set_int, &uwsgi.reload_mercy, 0},
	{"exit-on-reload", no_argument, 0, "force exit even if a reload is requested", uwsgi_opt_true, &uwsgi.exit_on_reload, 0},
	{"die-on-term", no_argument, 0, "exit instead of brutal reload on SIGTERM", uwsgi_opt_true, &uwsgi.die_on_term, 0},
	{"help", no_argument, 'h', "show this help", uwsgi_help, NULL, UWSGI_OPT_IMMEDIATE},
	{"usage", no_argument, 'h', "show this help", uwsgi_help, NULL, UWSGI_OPT_IMMEDIATE},

	{"reaper", no_argument, 'r', "call waitpid(-1,...) after each request to get rid of zombies", uwsgi_opt_dyn_true, (void *) UWSGI_OPTION_REAPER, 0},
	{"max-requests", required_argument, 'R', "reload workers after the specified amount of managed requests", uwsgi_opt_set_dyn, (void *) UWSGI_OPTION_MAX_REQUESTS, 0},

	{"socket-timeout", required_argument, 'z', "set internal sockets timeout", uwsgi_opt_set_dyn, (void *) UWSGI_OPTION_SOCKET_TIMEOUT, 0},
	{"no-fd-passing", no_argument, 0, "disable file descriptor passing", uwsgi_opt_true, &uwsgi.no_fd_passing, 0},
	{"locks", required_argument, 0, "create the specified number of shared locks", uwsgi_opt_set_int, &uwsgi.locks, 0},
	{"lock-engine", required_argument, 0, "set the lock engine", uwsgi_opt_set_str, &uwsgi.lock_engine, 0},
	{"ftok", required_argument, 0, "set the ipcsem key via ftok() for avoiding duplicates", uwsgi_opt_set_str, &uwsgi.ftok, 0},
	{"sharedarea", required_argument, 'A', "create a raw shared memory area of specified pages", uwsgi_opt_set_int, &uwsgi.sharedareasize, 0},

	{"cache", required_argument, 0, "create a shared cache containing given elements", uwsgi_opt_set_int, &uwsgi.cache_max_items, 0},
	{"cache-blocksize", required_argument, 0, "set cache blocksize", uwsgi_opt_set_int, &uwsgi.cache_blocksize, 0},
	{"cache-store", required_argument, 0, "enable persistent cache to disk", uwsgi_opt_set_str, &uwsgi.cache_store, UWSGI_OPT_MASTER},
	{"cache-store-sync", required_argument, 0, "set frequency of sync for persistent cache", uwsgi_opt_set_int, &uwsgi.cache_store_sync, 0},
	{"cache-server", required_argument, 0, "enable the threaded cache server", uwsgi_opt_set_str, &uwsgi.cache_server, 0},
	{"cache-server-threads", required_argument, 0, "set the number of threads for the cache server", uwsgi_opt_set_int, &uwsgi.cache_server_threads, 0},
	{"cache-no-expire", no_argument, 0, "disable auto sweep of expired items", uwsgi_opt_true, &uwsgi.cache_no_expire, 0},
	{"cache-expire-freq", required_argument, 0, "set the frequency of cache sweeper scans (default 3 seconds)", uwsgi_opt_set_int, &uwsgi.cache_expire_freq, 0},
	{"cache-report-freed-items", no_argument, 0, "constantly report the cache item freed by the sweeper (use only for debug)", uwsgi_opt_true, &uwsgi.cache_report_freed_items, 0},

	{"queue", required_argument, 0, "enable shared queue", uwsgi_opt_set_int, &uwsgi.queue_size, 0},
	{"queue-blocksize", required_argument, 0, "set queue blocksize", uwsgi_opt_set_int, &uwsgi.queue_store_sync, 0},
	{"queue-store", required_argument, 0, "enable persistent queue to disk", uwsgi_opt_set_str, &uwsgi.queue_store, UWSGI_OPT_MASTER},
	{"queue-store-sync", required_argument, 0, "set frequency of sync for persistent queue", uwsgi_opt_set_int, &uwsgi.queue_store_sync, 0},

#ifdef UWSGI_SPOOLER
	{"spooler", required_argument, 'Q', "run a spooler on the specified directory", uwsgi_opt_add_spooler, NULL, UWSGI_OPT_MASTER},
	{"spooler-external", required_argument, 0, "map spoolers requests to a spooler directory managed by an external instance", uwsgi_opt_add_spooler, (void *) UWSGI_SPOOLER_EXTERNAL, UWSGI_OPT_MASTER},
	{"spooler-ordered", no_argument, 0, "try to order the execution of spooler tasks", uwsgi_opt_true, &uwsgi.spooler_ordered, 0},
	{"spooler-chdir", required_argument, 0, "chdir() to specified directory before each spooler task", uwsgi_opt_set_str, &uwsgi.spooler_chdir, 0},
	{"spooler-processes", required_argument, 0, "set the number of processes for spoolers", uwsgi_opt_set_int, &uwsgi.spooler_numproc, 0},
	{"spooler-quiet", no_argument, 0, "do not be verbose with spooler tasks", uwsgi_opt_true, &uwsgi.spooler_quiet, 0},
	{"spooler-max-tasks", required_argument, 0, "set the maximum number of tasks to run before recycling a spooler", uwsgi_opt_set_int, &uwsgi.spooler_max_tasks, 0},
	{"spooler-harakiri", required_argument, 0, "set harakiri timeout for spooler tasks", uwsgi_opt_set_dyn, (void *) UWSGI_OPTION_SPOOLER_HARAKIRI, 0},
#endif
	{"mule", optional_argument, 0, "add a mule", uwsgi_opt_add_mule, NULL, UWSGI_OPT_MASTER},
	{"mules", required_argument, 0, "add the specified number of mules", uwsgi_opt_add_mules, NULL, UWSGI_OPT_MASTER},
	{"farm", required_argument, 0, "add a mule farm", uwsgi_opt_add_farm, NULL, UWSGI_OPT_MASTER},

	{"signal", required_argument, 0, "send a uwsgi signal to a server", uwsgi_opt_signal, NULL, UWSGI_OPT_IMMEDIATE},
	{"signal-bufsize", required_argument, 0, "set buffer size for signal queue", uwsgi_opt_set_int, &uwsgi.signal_bufsize, 0},
	{"signals-bufsize", required_argument, 0, "set buffer size for signal queue", uwsgi_opt_set_int, &uwsgi.signal_bufsize, 0},

	{"disable-logging", no_argument, 'L', "disable request logging", uwsgi_opt_dyn_false, (void *) UWSGI_OPTION_LOGGING, 0},

	{"flock", required_argument, 0, "lock the specified file before starting, exit if locked", uwsgi_opt_flock, NULL, UWSGI_OPT_IMMEDIATE},
	{"flock-wait", required_argument, 0, "lock the specified file before starting, wait if locked", uwsgi_opt_flock_wait, NULL, UWSGI_OPT_IMMEDIATE},

	{"flock2", required_argument, 0, "lock the specified file after logging/daemon setup, exit if locked", uwsgi_opt_set_str, &uwsgi.flock2, UWSGI_OPT_IMMEDIATE},
	{"flock-wait2", required_argument, 0, "lock the specified file after logging/daemon setup, wait if locked", uwsgi_opt_set_str, &uwsgi.flock_wait2, UWSGI_OPT_IMMEDIATE},

	{"pidfile", required_argument, 0, "create pidfile (before privileges drop)", uwsgi_opt_set_str, &uwsgi.pidfile, 0},
	{"pidfile2", required_argument, 0, "create pidfile (after privileges drop)", uwsgi_opt_set_str, &uwsgi.pidfile2, 0},
	{"chroot", required_argument, 0, "chroot() to the specified directory", uwsgi_opt_set_str, &uwsgi.chroot, 0},
	{"uid", required_argument, 0, "setuid to the specified user/uid", uwsgi_opt_set_uid, NULL, 0},
	{"gid", required_argument, 0, "setgid to the specified group/gid", uwsgi_opt_set_gid, NULL, 0},
	{"no-initgroups", no_argument, 0, "disable additional groups set via initgroups()", uwsgi_opt_true, &uwsgi.no_initgroups, 0},
#ifdef UWSGI_CAP
	{"cap", required_argument, 0, "set process capability", uwsgi_opt_set_cap, NULL, 0},
#endif
#ifdef __linux__
	{"unshare", required_argument, 0, "unshare() part of the processes and put it in a new namespace", uwsgi_opt_set_unshare, 0},
#endif
	{"exec-pre-jail", required_argument, 0, "run the specified command before jailing", uwsgi_opt_add_string_list, &uwsgi.exec_pre_jail, 0},
	{"exec-post-jail", required_argument, 0, "run the specified command after jailing", uwsgi_opt_add_string_list, &uwsgi.exec_post_jail, 0},
	{"exec-in-jail", required_argument, 0, "run the specified command in jail after initialization", uwsgi_opt_add_string_list, &uwsgi.exec_in_jail, 0},
	{"exec-as-root", required_argument, 0, "run the specified command before privileges drop", uwsgi_opt_add_string_list, &uwsgi.exec_as_root, 0},
	{"exec-as-user", required_argument, 0, "run the specified command after privileges drop", uwsgi_opt_add_string_list, &uwsgi.exec_as_user, 0},
	{"exec-as-user-atexit", required_argument, 0, "run the specified command before app exit and reload", uwsgi_opt_add_string_list, &uwsgi.exec_as_user_atexit, 0},
	{"exec-pre-app", required_argument, 0, "run the specified command before app loading", uwsgi_opt_add_string_list, &uwsgi.exec_pre_app, 0},
#ifdef UWSGI_INI
	{"ini", required_argument, 0, "load config from ini file", uwsgi_opt_load_ini, NULL, UWSGI_OPT_IMMEDIATE},
#endif
#ifdef UWSGI_YAML
	{"yaml", required_argument, 'y', "load config from yaml file", uwsgi_opt_load_yml, NULL, UWSGI_OPT_IMMEDIATE},
	{"yal", required_argument, 'y', "load config from yaml file", uwsgi_opt_load_yml, NULL, UWSGI_OPT_IMMEDIATE},
#endif
#ifdef UWSGI_JSON
	{"json", required_argument, 'j', "load config from json file", uwsgi_opt_load_json, NULL, UWSGI_OPT_IMMEDIATE},
	{"js", required_argument, 'j', "load config from json file", uwsgi_opt_load_json, NULL, UWSGI_OPT_IMMEDIATE},
#endif
#ifdef UWSGI_SQLITE3
	{"sqlite3", required_argument, 0, "load config from sqlite3 db", uwsgi_opt_load_sqlite3, NULL, UWSGI_OPT_IMMEDIATE},
	{"sqlite", required_argument, 0, "load config from sqlite3 db", uwsgi_opt_load_sqlite3, NULL, UWSGI_OPT_IMMEDIATE},
#endif
#ifdef UWSGI_ZEROMQ
	{"zeromq", required_argument, 0, "create a zeromq pub/sub pair", uwsgi_opt_add_lazy_socket, "zmq", 0},
	{"zmq", required_argument, 0, "create a zeromq pub/sub pair", uwsgi_opt_add_lazy_socket, "zmq", 0},
	{"zeromq-socket", required_argument, 0, "create a zeromq pub/sub pair", uwsgi_opt_add_lazy_socket, "zmq", 0},
	{"zmq-socket", required_argument, 0, "create a zeromq pub/sub pair", uwsgi_opt_add_lazy_socket, "zmq", 0},
#endif
#ifdef UWSGI_LDAP
	{"ldap", required_argument, 0, "load configuration from ldap server", uwsgi_opt_load_ldap, NULL, UWSGI_OPT_IMMEDIATE},
	{"ldap-schema", no_argument, 0, "dump uWSGI ldap schema", uwsgi_opt_ldap_dump, NULL, UWSGI_OPT_IMMEDIATE},
	{"ldap-schema-ldif", no_argument, 0, "dump uWSGI ldap schema in ldif format", uwsgi_opt_ldap_dump_ldif, NULL, UWSGI_OPT_IMMEDIATE},
#endif
	{"weight", required_argument, 0, "weight of the instance (used by clustering/lb/subscriptions)", uwsgi_opt_set_64bit, &uwsgi.weight, 0},
	{"auto-weight", required_argument, 0, "set weight of the instance (used by clustering/lb/subscriptions) automatically", uwsgi_opt_true, &uwsgi.auto_weight, 0},
	{"no-server", no_argument, 0, "force no-server mode", uwsgi_opt_true, &uwsgi.no_server, 0},
	{"command-mode", no_argument, 0, "force command mode", uwsgi_opt_true, &uwsgi.command_mode, UWSGI_OPT_IMMEDIATE},
	{"no-defer-accept", no_argument, 0, "disable deferred-accept on sockets", uwsgi_opt_true, &uwsgi.no_defer_accept, 0},
	{"so-keepalive", no_argument, 0, "enable TCP KEEPALIVEs", uwsgi_opt_true, &uwsgi.so_keepalive, 0},
	{"so-send-timeout", no_argument, 0, "set SO_SNDTIMEO", uwsgi_opt_set_int, &uwsgi.so_send_timeout, 0},
	{"socket-send-timeout", no_argument, 0, "set SO_SNDTIMEO", uwsgi_opt_set_int, &uwsgi.so_send_timeout, 0},
	{"so-write-timeout", no_argument, 0, "set SO_SNDTIMEO", uwsgi_opt_set_int, &uwsgi.so_send_timeout, 0},
	{"socket-write-timeout", no_argument, 0, "set SO_SNDTIMEO", uwsgi_opt_set_int, &uwsgi.so_send_timeout, 0},
	{"limit-as", required_argument, 0, "limit processes address space/vsz", uwsgi_opt_set_megabytes, &uwsgi.rl.rlim_max, 0},
	{"limit-nproc", required_argument, 0, "limit the number of spawnable processes", uwsgi_opt_set_int, &uwsgi.rl_nproc.rlim_max, 0},
	{"reload-on-as", required_argument, 0, "reload if address space is higher than specified megabytes", uwsgi_opt_set_megabytes, &uwsgi.reload_on_as, UWSGI_OPT_MEMORY},
	{"reload-on-rss", required_argument, 0, "reload if rss memory is higher than specified megabytes", uwsgi_opt_set_megabytes, &uwsgi.reload_on_rss, UWSGI_OPT_MEMORY},
	{"evil-reload-on-as", required_argument, 0, "force the master to reload a worker if its address space is higher than specified megabytes", uwsgi_opt_set_megabytes, &uwsgi.evil_reload_on_as, UWSGI_OPT_MASTER | UWSGI_OPT_MEMORY},
	{"evil-reload-on-rss", required_argument, 0, "force the master to reload a worker if its rss memory is higher than specified megabytes", uwsgi_opt_set_megabytes, &uwsgi.evil_reload_on_rss, UWSGI_OPT_MASTER | UWSGI_OPT_MEMORY},

#ifdef __linux__
#ifdef MADV_MERGEABLE
	{"ksm", optional_argument, 0, "enable Linux KSM", uwsgi_opt_set_int, &uwsgi.linux_ksm, 0},
#endif
#endif
#ifdef UWSGI_PCRE
	{"pcre-jit", no_argument, 0, "enable pcre jit (if available)", uwsgi_opt_pcre_jit, NULL, UWSGI_OPT_IMMEDIATE},
#endif
	{"never-swap", no_argument, 0, "lock all memory pages avoiding swapping", uwsgi_opt_true, &uwsgi.never_swap, 0},
	{"touch-reload", required_argument, 0, "reload uWSGI if the specified file is modified/touched", uwsgi_opt_add_string_list, &uwsgi.touch_reload, UWSGI_OPT_MASTER},
	{"touch-logrotate", required_argument, 0, "trigger logrotation if the specified file is modified/touched", uwsgi_opt_add_string_list, &uwsgi.touch_logrotate, UWSGI_OPT_MASTER | UWSGI_OPT_LOG_MASTER},
	{"touch-logreopen", required_argument, 0, "trigger log reopen if the specified file is modified/touched", uwsgi_opt_add_string_list, &uwsgi.touch_logreopen, UWSGI_OPT_MASTER | UWSGI_OPT_LOG_MASTER},
	{"propagate-touch", no_argument, 0, "over-engineering option for system with flaky signal mamagement", uwsgi_opt_true, &uwsgi.propagate_touch, 0},
	{"limit-post", required_argument, 0, "limit request body", uwsgi_opt_set_64bit, &uwsgi.limit_post, 0},
	{"no-orphans", no_argument, 0, "automatically kill workers if master dies (can be dangerous for availability)", uwsgi_opt_true, &uwsgi.no_orphans, 0},
	{"prio", required_argument, 0, "set processes/threads priority", uwsgi_opt_set_rawint, &uwsgi.prio, 0},
	{"cpu-affinity", required_argument, 0, "set cpu affinity", uwsgi_opt_set_int, &uwsgi.cpu_affinity, 0},
	{"post-buffering", required_argument, 0, "enable post buffering", uwsgi_opt_set_64bit, &uwsgi.post_buffering, 0},
	{"post-buffering-bufsize", required_argument, 0, "set buffer size for read() in post buffering mode", uwsgi_opt_set_64bit, &uwsgi.post_buffering_bufsize, 0},
	{"upload-progress", required_argument, 0, "enable creation of .json files in the specified directory during a file upload", uwsgi_opt_set_str, &uwsgi.upload_progress, 0},
	{"no-default-app", no_argument, 0, "do not fallback to default app", uwsgi_opt_true, &uwsgi.no_default_app, 0},
	{"manage-script-name", no_argument, 0, "automatically rewrite SCRIPT_NAME and PATH_INFO", uwsgi_opt_true, &uwsgi.manage_script_name, 0},
	{"ignore-script-name", no_argument, 0, "ignore SCRIPT_NAME", uwsgi_opt_true, &uwsgi.ignore_script_name, 0},
	{"catch-exceptions", no_argument, 0, "report exception has http output (discouraged)", uwsgi_opt_true, &uwsgi.catch_exceptions, 0},
	{"reload-on-exception", no_argument, 0, "reload a worker when an exception is raised", uwsgi_opt_true, &uwsgi.reload_on_exception, 0},
	{"reload-on-exception-type", required_argument, 0, "reload a worker when a specific exception type is raised", uwsgi_opt_add_string_list, &uwsgi.reload_on_exception_type, 0},
	{"reload-on-exception-value", required_argument, 0, "reload a worker when a specific exception value is raised", uwsgi_opt_add_string_list, &uwsgi.reload_on_exception_value, 0},
	{"reload-on-exception-repr", required_argument, 0, "reload a worker when a specific exception type+value (language-specific) is raised", uwsgi_opt_add_string_list, &uwsgi.reload_on_exception_repr, 0},
#ifdef UWSGI_UDP
	{"udp", required_argument, 0, "run the udp server on the specified address", uwsgi_opt_set_str, &uwsgi.udp_socket, UWSGI_OPT_MASTER},
#endif
	{"stats", required_argument, 0, "enable the stats server on the specified address", uwsgi_opt_set_str, &uwsgi.stats, UWSGI_OPT_MASTER},
	{"stats-server", required_argument, 0, "enable the stats server on the specified address", uwsgi_opt_set_str, &uwsgi.stats, UWSGI_OPT_MASTER},
	{"stats-http", no_argument, 0, "prefix stats server json output with http headers", uwsgi_opt_true, &uwsgi.stats_http, UWSGI_OPT_MASTER},
	{"stats-minified", no_argument, 0, "minify statistics json output", uwsgi_opt_true, &uwsgi.stats_minified, UWSGI_OPT_MASTER},
	{"stats-min", no_argument, 0, "minify statistics json output", uwsgi_opt_true, &uwsgi.stats_minified, UWSGI_OPT_MASTER},
	{"stats-push", required_argument, 0, "push the stats json to the specified destination", uwsgi_opt_add_string_list, &uwsgi.requested_stats_pushers, UWSGI_OPT_MASTER},
	{"stats-pusher-default-freq", required_argument, 0, "set the default frequency of stats pushers", uwsgi_opt_set_int, &uwsgi.stats_pusher_default_freq, UWSGI_OPT_MASTER},
	{"stats-pushers-default-freq", required_argument, 0, "set the default frequency of stats pushers", uwsgi_opt_set_int, &uwsgi.stats_pusher_default_freq, UWSGI_OPT_MASTER},
#ifdef UWSGI_MULTICAST
	{"multicast", required_argument, 0, "subscribe to specified multicast group", uwsgi_opt_set_str, &uwsgi.multicast_group, UWSGI_OPT_MASTER},
	{"multicast-ttl", required_argument, 0, "set multicast ttl", uwsgi_opt_set_int, &uwsgi.multicast_ttl, 0},
	{"cluster", required_argument, 0, "join specified uWSGI cluster", uwsgi_opt_set_str, &uwsgi.cluster, UWSGI_OPT_MASTER},
	{"cluster-nodes", required_argument, 0, "get nodes list from the specified cluster", uwsgi_opt_true, &uwsgi.cluster_nodes, UWSGI_OPT_MASTER | UWSGI_OPT_CLUSTER},
	{"cluster-reload", required_argument, 0, "send a reload message to the cluster", uwsgi_opt_cluster_reload, NULL, UWSGI_OPT_IMMEDIATE},
	{"cluster-log", required_argument, 0, "send a log line to the cluster", uwsgi_opt_cluster_log, NULL, UWSGI_OPT_IMMEDIATE},
#endif
#ifdef UWSGI_SSL
	{"subscriptions-sign-check", required_argument, 0, "set digest algorithm and certificate directory for secured subscription system", uwsgi_opt_scd, NULL, UWSGI_OPT_MASTER},
	{"subscriptions-sign-check-tolerance", required_argument, 0, "set the maximum tolerance (in seconds) of clock skew for secured subscription system", uwsgi_opt_set_int, &uwsgi.subscriptions_sign_check_tolerance, UWSGI_OPT_MASTER},
#endif
	{"subscription-algo", required_argument, 0, "set load balancing algorithm for the subscription system", uwsgi_opt_ssa, NULL, 0},
	{"subscription-dotsplit", no_argument, 0, "try to fallback to the next part (dot based) in subscription key", uwsgi_opt_true, &uwsgi.subscription_dotsplit, 0},
	{"subscribe-to", required_argument, 0, "subscribe to the specified subscription server", uwsgi_opt_add_string_list, &uwsgi.subscriptions, UWSGI_OPT_MASTER},
	{"st", required_argument, 0, "subscribe to the specified subscription server", uwsgi_opt_add_string_list, &uwsgi.subscriptions, UWSGI_OPT_MASTER},
	{"subscribe", required_argument, 0, "subscribe to the specified subscription server", uwsgi_opt_add_string_list, &uwsgi.subscriptions, UWSGI_OPT_MASTER},
	{"subscribe-freq", required_argument, 0, "send subscription announce at the specified interval", uwsgi_opt_set_int, &uwsgi.subscribe_freq, 0},
	{"subscription-tolerance", required_argument, 0, "set tolerance for subscription servers", uwsgi_opt_set_int, &uwsgi.subscription_tolerance, 0},
	{"unsubscribe-on-graceful-reload", no_argument, 0, "force unsubscribe request even during graceful reload", uwsgi_opt_true, &uwsgi.unsubscribe_on_graceful_reload, 0},
#ifdef UWSGI_SNMP
	{"snmp", optional_argument, 0, "enable the embedded snmp server", uwsgi_opt_snmp, NULL, 0},
	{"snmp-community", required_argument, 0, "set the snmp community string", uwsgi_opt_snmp_community, NULL, 0},
#endif
#ifdef UWSGI_SSL
	{"ssl-verbose", no_argument, 0, "be verbose about SSL errors", uwsgi_opt_true, &uwsgi.ssl_verbose, 0},
#endif
	{"check-interval", required_argument, 0, "set the interval (in seconds) of master checks", uwsgi_opt_set_dyn, (void *) UWSGI_OPTION_MASTER_INTERVAL, 0},
	{"forkbomb-delay", required_argument, 0, "sleep for the specified number of seconds when a forkbomb is detected", uwsgi_opt_set_int, &uwsgi.forkbomb_delay, UWSGI_OPT_MASTER},
	{"binary-path", required_argument, 0, "force binary path", uwsgi_opt_set_str, &uwsgi.binary_path, 0},
	{"privileged-binary-patch", required_argument, 0, "patch the uwsgi binary with a new command (before privileges drop)", uwsgi_opt_set_str, &uwsgi.privileged_binary_patch, 0},
	{"unprivileged-binary-patch", required_argument, 0, "patch the uwsgi binary with a new command (after privileges drop)", uwsgi_opt_set_str, &uwsgi.unprivileged_binary_patch, 0},
	{"privileged-binary-patch-arg", required_argument, 0, "patch the uwsgi binary with a new command and arguments (before privileges drop)", uwsgi_opt_set_str, &uwsgi.privileged_binary_patch_arg, 0},
	{"unprivileged-binary-patch-arg", required_argument, 0, "patch the uwsgi binary with a new command and arguments (after privileges drop)", uwsgi_opt_set_str, &uwsgi.unprivileged_binary_patch_arg, 0},
#ifdef UWSGI_ASYNC
	{"async", required_argument, 0, "enable async mode with specified cores", uwsgi_opt_set_int, &uwsgi.async, 0},
#endif
	{"max-fd", required_argument, 0, "set maximum number of file descriptors (requires root privileges)", uwsgi_opt_set_int, &uwsgi.requested_max_fd, 0},
	{"logto", required_argument, 0, "set logfile/udp address", uwsgi_opt_set_str, &uwsgi.logfile, 0},
	{"logto2", required_argument, 0, "log to specified file or udp address after privileges drop", uwsgi_opt_set_str, &uwsgi.logto2, 0},
	{"log-format", required_argument, 0, "set advanced format for request logging", uwsgi_opt_set_str, &uwsgi.logformat, 0},
	{"logformat", required_argument, 0, "set advanced format for request logging", uwsgi_opt_set_str, &uwsgi.logformat, 0},
	{"logformat-strftime", no_argument, 0, "apply strftime to logformat output", uwsgi_opt_true, &uwsgi.logformat_strftime, 0},
	{"log-format-strftime", no_argument, 0, "apply strftime to logformat output", uwsgi_opt_true, &uwsgi.logformat_strftime, 0},
	{"logfile-chown", no_argument, 0, "chown logfiles", uwsgi_opt_true, &uwsgi.logfile_chown, 0},
	{"logfile-chmod", required_argument, 0, "chmod logfiles", uwsgi_opt_logfile_chmod, NULL, 0},
	{"log-syslog", optional_argument, 0, "log to syslog", uwsgi_opt_set_logger, "syslog", UWSGI_OPT_MASTER | UWSGI_OPT_LOG_MASTER},
	{"log-socket", required_argument, 0, "send logs to the specified socket", uwsgi_opt_set_logger, "socket", UWSGI_OPT_MASTER | UWSGI_OPT_LOG_MASTER},
	{"logger", required_argument, 0, "set/append a logger", uwsgi_opt_set_logger, NULL, UWSGI_OPT_MASTER | UWSGI_OPT_LOG_MASTER},
	{"logger-list", no_argument, 0, "list enabled loggers", uwsgi_opt_true, &uwsgi.loggers_list, 0},
	{"loggers-list", no_argument, 0, "list enabled loggers", uwsgi_opt_true, &uwsgi.loggers_list, 0},
	{"threaded-logger", no_argument, 0, "offload log writing to a thread", uwsgi_opt_true, &uwsgi.threaded_logger, UWSGI_OPT_MASTER | UWSGI_OPT_LOG_MASTER},
#ifdef UWSGI_PCRE
	{"log-drain", required_argument, 0, "drain (do not show) log lines matching the specified regexp", uwsgi_opt_add_regexp_list, &uwsgi.log_drain_rules, UWSGI_OPT_MASTER | UWSGI_OPT_LOG_MASTER},
	{"log-filter", required_argument, 0, "show only log lines matching the specified regexp", uwsgi_opt_add_regexp_list, &uwsgi.log_filter_rules, UWSGI_OPT_MASTER | UWSGI_OPT_LOG_MASTER},
	{"log-route", required_argument, 0, "log to the specified named logger if regexp applied on logline matches", uwsgi_opt_add_regexp_custom_list, &uwsgi.log_route, UWSGI_OPT_MASTER | UWSGI_OPT_LOG_MASTER},
#endif
#ifdef UWSGI_ALARM
	{"alarm", required_argument, 0, "create a new alarm, syntax: <alarm> <plugin:args>", uwsgi_opt_add_string_list, &uwsgi.alarm_list, UWSGI_OPT_MASTER | UWSGI_OPT_LOG_MASTER},
	{"alarm-freq", required_argument, 0, "tune the anti-loop alam system (default 3 seconds)", uwsgi_opt_set_int, &uwsgi.alarm_freq, 0},
	{"log-alarm", required_argument, 0, "raise the specified alarm when a log line matches the specified regexp, syntax: <alarm>[,alarm...] <regexp>", uwsgi_opt_add_string_list, &uwsgi.alarm_logs_list, UWSGI_OPT_MASTER | UWSGI_OPT_LOG_MASTER},
	{"alarm-list", no_argument, 0, "list enabled alarms", uwsgi_opt_true, &uwsgi.alarms_list, 0},
	{"alarms-list", no_argument, 0, "list enabled alarms", uwsgi_opt_true, &uwsgi.alarms_list, 0},
#endif
#ifdef UWSGI_ZEROMQ
	{"log-zeromq", required_argument, 0, "send logs to a zeromq server", uwsgi_opt_set_logger, "zeromq", UWSGI_OPT_MASTER | UWSGI_OPT_LOG_MASTER},
#endif
	{"log-master", no_argument, 0, "delegate logging to master process", uwsgi_opt_true, &uwsgi.log_master, UWSGI_OPT_MASTER},
	{"log-master-bufsize", required_argument, 0, "set the buffer size for the master logger. bigger log messages will be truncated", uwsgi_opt_set_64bit, &uwsgi.log_master_bufsize, 0},
	{"log-reopen", no_argument, 0, "reopen log after reload", uwsgi_opt_true, &uwsgi.log_reopen, 0},
	{"log-truncate", no_argument, 0, "truncate log on startup", uwsgi_opt_true, &uwsgi.log_truncate, 0},
	{"log-maxsize", required_argument, 0, "set maximum logfile size", uwsgi_opt_set_int, &uwsgi.log_maxsize, UWSGI_OPT_LOG_MASTER},
	{"log-backupname", required_argument, 0, "set logfile name after rotation", uwsgi_opt_set_str, &uwsgi.log_backupname, 0},

	{"logdate", optional_argument, 0, "prefix logs with date or a strftime string", uwsgi_opt_log_date, NULL, 0},
	{"log-date", optional_argument, 0, "prefix logs with date or a strftime string", uwsgi_opt_log_date, NULL, 0},
	{"log-prefix", optional_argument, 0, "prefix logs with a string", uwsgi_opt_log_date, NULL, 0},

	{"log-zero", no_argument, 0, "log responses without body", uwsgi_opt_dyn_true, (void *) UWSGI_OPTION_LOG_ZERO, 0},
	{"log-slow", required_argument, 0, "log requests slower than the specified number of milliseconds", uwsgi_opt_set_dyn, (void *) UWSGI_OPTION_LOG_SLOW, 0},
	{"log-4xx", no_argument, 0, "log requests with a 4xx response", uwsgi_opt_dyn_true, (void *) UWSGI_OPTION_LOG_4xx, 0},
	{"log-5xx", no_argument, 0, "log requests with a 5xx response", uwsgi_opt_dyn_true, (void *) UWSGI_OPTION_LOG_5xx, 0},
	{"log-big", required_argument, 0, "log requestes bigger than the specified size", uwsgi_opt_set_dyn, (void *) UWSGI_OPTION_LOG_BIG, 0},
	{"log-sendfile", required_argument, 0, "log sendfile requests", uwsgi_opt_dyn_true, (void *) UWSGI_OPTION_LOG_SENDFILE, 0},
	{"log-micros", no_argument, 0, "report response time in microseconds instead of milliseconds", uwsgi_opt_true, &uwsgi.log_micros, 0},
	{"log-x-forwarded-for", no_argument, 0, "use the ip from X-Forwarded-For header instead of REMOTE_ADDR", uwsgi_opt_true, &uwsgi.log_x_forwarded_for, 0},
	{"master-as-root", no_argument, 0, "leave master process running as root", uwsgi_opt_true, &uwsgi.master_as_root, 0},
	{"chdir", required_argument, 0, "chdir to specified directory before apps loading", uwsgi_opt_set_str, &uwsgi.chdir, 0},
	{"chdir2", required_argument, 0, "chdir to specified directory after apps loading", uwsgi_opt_set_str, &uwsgi.chdir2, 0},
	{"lazy", no_argument, 0, "set lazy mode (load apps in workers instead of master)", uwsgi_opt_true, &uwsgi.lazy, 0},
	{"lazy-apps", no_argument, 0, "load apps in each worker instead of the master", uwsgi_opt_true, &uwsgi.lazy_apps, 0},
	{"cheap", no_argument, 0, "set cheap mode (spawn workers only after the first request)", uwsgi_opt_true, &uwsgi.cheap, UWSGI_OPT_MASTER},
	{"cheaper", required_argument, 0, "set cheaper mode (adaptive process spawning)", uwsgi_opt_set_int, &uwsgi.cheaper_count, UWSGI_OPT_MASTER | UWSGI_OPT_CHEAPER},
	{"cheaper-initial", required_argument, 0, "set the initial number of processes to spawn in cheaper mode", uwsgi_opt_set_int, &uwsgi.cheaper_initial, UWSGI_OPT_MASTER | UWSGI_OPT_CHEAPER},
	{"cheaper-algo", required_argument, 0, "choose to algorithm used for adaptive process spawning)", uwsgi_opt_set_str, &uwsgi.requested_cheaper_algo, UWSGI_OPT_MASTER},
	{"cheaper-step", required_argument, 0, "number of additional processes to spawn at each overload", uwsgi_opt_set_int, &uwsgi.cheaper_step, UWSGI_OPT_MASTER | UWSGI_OPT_CHEAPER},
	{"cheaper-overload", required_argument, 0, "increase workers after specified overload", uwsgi_opt_set_64bit, &uwsgi.cheaper_overload, UWSGI_OPT_MASTER | UWSGI_OPT_CHEAPER},
	{"cheaper-algo-list", no_argument, 0, "list enabled cheapers algorithms", uwsgi_opt_true, &uwsgi.cheaper_algo_list, 0},
	{"cheaper-algos-list", no_argument, 0, "list enabled cheapers algorithms", uwsgi_opt_true, &uwsgi.cheaper_algo_list, 0},
	{"cheaper-list", no_argument, 0, "list enabled cheapers algorithms", uwsgi_opt_true, &uwsgi.cheaper_algo_list, 0},
	{"idle", required_argument, 0, "set idle mode (put uWSGI in cheap mode after inactivity)", uwsgi_opt_set_int, &uwsgi.idle, UWSGI_OPT_MASTER},
	{"die-on-idle", no_argument, 0, "shutdown uWSGI when idle", uwsgi_opt_true, &uwsgi.die_on_idle, 0},
	{"mount", required_argument, 0, "load application under mountpoint", uwsgi_opt_add_string_list, &uwsgi.mounts, 0},
	{"worker-mount", required_argument, 0, "load application under mountpoint in the specified worker or after workers spawn", uwsgi_opt_add_string_list, &uwsgi.mounts, 0},
	{"grunt", no_argument, 0, "enable grunt mode (in-request fork)", uwsgi_opt_true, &uwsgi.grunt, 0},

	{"threads", required_argument, 0, "run each worker in prethreaded mode with the specified number of threads", uwsgi_opt_set_int, &uwsgi.threads, UWSGI_OPT_THREADS},
	{"thread-stacksize", required_argument, 0, "set threads stacksize", uwsgi_opt_set_int, &uwsgi.threads_stacksize, UWSGI_OPT_THREADS},
	{"threads-stacksize", required_argument, 0, "set threads stacksize", uwsgi_opt_set_int, &uwsgi.threads_stacksize, UWSGI_OPT_THREADS},
	{"thread-stack-size", required_argument, 0, "set threads stacksize", uwsgi_opt_set_int, &uwsgi.threads_stacksize, UWSGI_OPT_THREADS},
	{"threads-stack-size", required_argument, 0, "set threads stacksize", uwsgi_opt_set_int, &uwsgi.threads_stacksize, UWSGI_OPT_THREADS},

	{"vhost", no_argument, 0, "enable virtualhosting mode (based on SERVER_NAME variable)", uwsgi_opt_true, &uwsgi.vhost, 0},
	{"vhost-host", no_argument, 0, "enable virtualhosting mode (based on HTTP_HOST variable)", uwsgi_opt_true, &uwsgi.vhost_host, UWSGI_OPT_VHOST},
#ifdef UWSGI_ROUTING
	{"route", required_argument, 0, "add a route", uwsgi_opt_add_route, "path_info", 0},
	{"route-host", required_argument, 0, "add a route based on Host header", uwsgi_opt_add_route, "http_host", 0},
	{"route-uri", required_argument, 0, "add a route based on REQUEST_URI", uwsgi_opt_add_route, "request_uri", 0},
	{"route-qs", required_argument, 0, "add a route based on QUERY_STRING", uwsgi_opt_add_route, "query_string", 0},
	{"router-list", no_argument, 0, "list enabled routers", uwsgi_opt_true, &uwsgi.router_list, 0},
	{"routers-list", no_argument, 0, "list enabled routers", uwsgi_opt_true, &uwsgi.router_list, 0},
#endif

	{"clock", required_argument, 0, "set a clock source", uwsgi_opt_set_str, &uwsgi.requested_clock, 0},

	{"clock-list", no_argument, 0, "list enabled clocks", uwsgi_opt_true, &uwsgi.clock_list, 0},
	{"clocks-list", no_argument, 0, "list enabled clocks", uwsgi_opt_true, &uwsgi.clock_list, 0},

	{"add-header", required_argument, 0, "automatically add HTTP headers to response", uwsgi_opt_add_string_list, &uwsgi.additional_headers, 0},

	{"check-static", required_argument, 0, "check for static files in the specified directory", uwsgi_opt_check_static, NULL, UWSGI_OPT_MIME},
	{"check-static-docroot", no_argument, 0, "check for static files in the requested DOCUMENT_ROOT", uwsgi_opt_true, &uwsgi.check_static_docroot, UWSGI_OPT_MIME},
	{"static-check", required_argument, 0, "check for static files in the specified directory", uwsgi_opt_check_static, NULL, UWSGI_OPT_MIME},
	{"static-map", required_argument, 0, "map mountpoint to static directory (or file)", uwsgi_opt_static_map, &uwsgi.static_maps, UWSGI_OPT_MIME},
	{"static-map2", required_argument, 0, "like static-map but completely appending the requested resource to the docroot", uwsgi_opt_static_map, &uwsgi.static_maps2, UWSGI_OPT_MIME},
	{"static-skip-ext", required_argument, 0, "skip specified extension from staticfile checks", uwsgi_opt_add_string_list, &uwsgi.static_skip_ext, UWSGI_OPT_MIME},
	{"static-index", required_argument, 0, "search for specified file if a directory is requested", uwsgi_opt_add_string_list, &uwsgi.static_index, UWSGI_OPT_MIME},
	{"mimefile", required_argument, 0, "set mime types file path (default /etc/mime.types)", uwsgi_opt_add_string_list, &uwsgi.mime_file, UWSGI_OPT_MIME},
	{"mime-file", required_argument, 0, "set mime types file path (default /etc/mime.types)", uwsgi_opt_add_string_list, &uwsgi.mime_file, UWSGI_OPT_MIME},

	{"static-expires-type", required_argument, 0, "set the Expires header based on content type", uwsgi_opt_add_dyn_dict, &uwsgi.static_expires_type, UWSGI_OPT_MIME},
	{"static-expires-type-mtime", required_argument, 0, "set the Expires header based on content type and file mtime", uwsgi_opt_add_dyn_dict, &uwsgi.static_expires_type_mtime, UWSGI_OPT_MIME},

#ifdef UWSGI_PCRE
	{"static-expires", required_argument, 0, "set the Expires header based on filename regexp", uwsgi_opt_add_regexp_dyn_dict, &uwsgi.static_expires, UWSGI_OPT_MIME},
	{"static-expires-mtime", required_argument, 0, "set the Expires header based on filename regexp and file mtime", uwsgi_opt_add_regexp_dyn_dict, &uwsgi.static_expires_mtime, UWSGI_OPT_MIME},

	{"static-expires-uri", required_argument, 0, "set the Expires header based on REQUEST_URI regexp", uwsgi_opt_add_regexp_dyn_dict, &uwsgi.static_expires_uri, UWSGI_OPT_MIME},
	{"static-expires-uri-mtime", required_argument, 0, "set the Expires header based on REQUEST_URI regexp and file mtime", uwsgi_opt_add_regexp_dyn_dict, &uwsgi.static_expires_uri_mtime, UWSGI_OPT_MIME},

	{"static-expires-path-info", required_argument, 0, "set the Expires header based on PATH_INFO regexp", uwsgi_opt_add_regexp_dyn_dict, &uwsgi.static_expires_path_info, UWSGI_OPT_MIME},
	{"static-expires-path-info-mtime", required_argument, 0, "set the Expires header based on PATH_INFO regexp and file mtime", uwsgi_opt_add_regexp_dyn_dict, &uwsgi.static_expires_path_info_mtime, UWSGI_OPT_MIME},
#endif

	{"offload-threads", required_argument, 0, "set the number of offload threads to spawn (per-worker, default 0)", uwsgi_opt_set_int, &uwsgi.offload_threads, 0},

	{"file-serve-mode", required_argument, 0, "set static file serving mode", uwsgi_opt_fileserve_mode, NULL, UWSGI_OPT_MIME},
	{"fileserve-mode", required_argument, 0, "set static file serving mode", uwsgi_opt_fileserve_mode, NULL, UWSGI_OPT_MIME},

	{"check-cache", no_argument, 0, "check for response data in the cache", uwsgi_opt_true, &uwsgi.check_cache, 0},
	{"close-on-exec", no_argument, 0, "set close-on-exec on sockets (could be required for spawning processes in requests)", uwsgi_opt_true, &uwsgi.close_on_exec, 0},
	{"mode", required_argument, 0, "set uWSGI custom mode", uwsgi_opt_set_str, &uwsgi.mode, 0},
	{"env", required_argument, 0, "set environment variable", uwsgi_opt_set_env, NULL, 0},
	{"unenv", required_argument, 0, "unset environment variable", uwsgi_opt_unset_env, NULL, 0},
	{"vacuum", no_argument, 0, "try to remove all of the generated file/sockets", uwsgi_opt_true, &uwsgi.vacuum, 0},
#ifdef __linux__
	{"cgroup", required_argument, 0, "put the processes in the specified cgroup", uwsgi_opt_add_string_list, &uwsgi.cgroup, 0},
	{"cgroup-opt", required_argument, 0, "set value in specified cgroup option", uwsgi_opt_add_string_list, &uwsgi.cgroup_opt, 0},
	{"namespace", required_argument, 0, "run in a new namespace under the specified rootfs", uwsgi_opt_set_str, &uwsgi.ns, 0},
	{"namespace-keep-mount", required_argument, 0, "keep the specified mountpoint in your namespace", uwsgi_opt_add_string_list, &uwsgi.ns_keep_mount, 0},
	{"ns", required_argument, 0, "run in a new namespace under the specified rootfs", uwsgi_opt_set_str, &uwsgi.ns, 0},
	{"namespace-net", required_argument, 0, "add network namespace", uwsgi_opt_set_str, &uwsgi.ns_net, 0},
	{"ns-net", required_argument, 0, "add network namespace", uwsgi_opt_set_str, &uwsgi.ns_net, 0},
#endif
	{"reuse-port", no_argument, 0, "enable REUSE_PORT flag on socket (BSD only)", uwsgi_opt_true, &uwsgi.reuse_port, 0},
	{"zerg", required_argument, 0, "attach to a zerg server", uwsgi_opt_add_string_list, &uwsgi.zerg_node, 0},
	{"zerg-fallback", no_argument, 0, "fallback to normal sockets if the zerg server is not available", uwsgi_opt_true, &uwsgi.zerg_fallback, 0},
	{"zerg-server", required_argument, 0, "enable the zerg server on the specified UNIX socket", uwsgi_opt_set_str, &uwsgi.zerg_server, UWSGI_OPT_MASTER},

	{"cron", required_argument, 0, "add a cron task", uwsgi_opt_add_cron, NULL, UWSGI_OPT_MASTER},
	{"loop", required_argument, 0, "select the uWSGI loop engine", uwsgi_opt_set_str, &uwsgi.loop, 0},
	{"loop-list", no_argument, 0, "list enabled loop engines", uwsgi_opt_true, &uwsgi.loop_list, 0},
	{"loops-list", no_argument, 0, "list enabled loop engines", uwsgi_opt_true, &uwsgi.loop_list, 0},
	{"worker-exec", required_argument, 0, "run the specified command as worker", uwsgi_opt_set_str, &uwsgi.worker_exec, 0},
	{"attach-daemon", required_argument, 0, "attach a command/daemon to the master process (the command has to not go in background)", uwsgi_opt_add_daemon, NULL, UWSGI_OPT_MASTER},
	{"smart-attach-daemon", required_argument, 0, "attach a command/daemon to the master process managed by a pidfile (the command has to daemonize)", uwsgi_opt_add_daemon, NULL, UWSGI_OPT_MASTER},
	{"smart-attach-daemon2", required_argument, 0, "attach a command/daemon to the master process managed by a pidfile (the command has to NOT daemonize)", uwsgi_opt_add_daemon, NULL, UWSGI_OPT_MASTER},
	{"plugins", required_argument, 0, "load uWSGI plugins", uwsgi_opt_load_plugin, NULL, UWSGI_OPT_IMMEDIATE},
	{"plugin", required_argument, 0, "load uWSGI plugins", uwsgi_opt_load_plugin, NULL, UWSGI_OPT_IMMEDIATE},
	{"plugins-dir", required_argument, 0, "add a directory to uWSGI plugin search path", uwsgi_opt_add_string_list, &uwsgi.plugins_dir, UWSGI_OPT_IMMEDIATE},
	{"plugin-dir", required_argument, 0, "add a directory to uWSGI plugin search path", uwsgi_opt_add_string_list, &uwsgi.plugins_dir, UWSGI_OPT_IMMEDIATE},
	{"plugins-list", no_argument, 0, "list enabled plugins", uwsgi_opt_true, &uwsgi.plugins_list, 0},
	{"plugin-list", no_argument, 0, "list enabled plugins", uwsgi_opt_true, &uwsgi.plugins_list, 0},
	{"autoload", no_argument, 0, "try to automatically load plugins when unknown options are found", uwsgi_opt_true, &uwsgi.autoload, UWSGI_OPT_IMMEDIATE},
	{"dlopen", required_argument, 0, "blindly load a shared library", uwsgi_opt_load_dl, NULL, UWSGI_OPT_IMMEDIATE},
	{"allowed-modifiers", required_argument, 0, "comma separated list of allowed modifiers", uwsgi_opt_set_str, &uwsgi.allowed_modifiers, 0},
	{"remap-modifier", required_argument, 0, "remap request modifier from one id to another", uwsgi_opt_set_str, &uwsgi.remap_modifier, 0},

	{"app", required_argument, 0, "*** deprecated ***", uwsgi_opt_deprecated, (void *) "use the more advanced \"mount\" option", 0},
	{"static-offload-to-thread", required_argument, 0, "*** deprecated ***", uwsgi_opt_deprecated, (void *) "use the more advanced \"offload-threads\" option", 0},

	{"dump-options", no_argument, 0, "dump the full list of available options", uwsgi_opt_true, &uwsgi.dump_options, 0},
	{"show-config", no_argument, 0, "show the current config reformatted as ini", uwsgi_opt_true, &uwsgi.show_config, 0},
	{"print", required_argument, 0, "simple print", uwsgi_opt_print, NULL, 0},
	{"cflags", no_argument, 0, "report uWSGI CFLAGS (useful for building external plugins)", uwsgi_opt_cflags, NULL, UWSGI_OPT_IMMEDIATE},
	{"version", no_argument, 0, "print uWSGI version", uwsgi_opt_print, UWSGI_VERSION, 0},
	{0, 0, 0, 0, 0, 0, 0}
};

void show_config(void) {
	int i;
	uwsgi_log("\n;uWSGI instance configuration\n[uwsgi]\n");
	for (i = 0; i < uwsgi.exported_opts_cnt; i++) {
		if (uwsgi.exported_opts[i]->value) {
			uwsgi_log("%s = %s\n", uwsgi.exported_opts[i]->key, uwsgi.exported_opts[i]->value);
		}
		else {
			uwsgi_log("%s = true\n", uwsgi.exported_opts[i]->key);
		}
	}
	uwsgi_log(";end of configuration\n\n");

}

int uwsgi_manage_custom_option(struct uwsgi_custom_option *uco, char *key, char *value) {
	size_t i, count = 1;
	size_t value_len = 0;
	if (value)
		value_len = strlen(value);
	off_t pos = 0;
	char **opt_argv;
	char *tmp_val = NULL, *p = NULL;

	if (strcmp(uco->name, key)) {
		return 0;
	}

	// now count the number of args
	for (i = 0; i < value_len; i++) {
		if (value[i] == ' ') {
			count++;
		}
	}

	// allocate a tmp array
	opt_argv = uwsgi_calloc(sizeof(char *) * count);
	//make a copy of the value;
	if (value_len > 0) {
		tmp_val = uwsgi_str(value);
		// fill the array of options
		p = strtok(tmp_val, " ");
		while (p) {
			opt_argv[pos] = p;
			pos++;
			p = strtok(NULL, " ");
		}
	}
	else {
		// no argument specified
		opt_argv[0] = "";
	}

#ifdef UWSGI_DEBUG
	uwsgi_log("found custom option %s with %d args\n", key, count);
#endif

	// now make a copy of the option template
	char *tmp_opt = uwsgi_str(uco->value);
	// split it
	p = strtok(tmp_opt, ";");
	while (p) {
		char *equal = strchr(p, '=');
		if (!equal)
			goto clear;
		*equal = '\0';

		// build the key
		char *new_key = uwsgi_str(p);
		for (i = 0; i < count; i++) {
			char *old_key = new_key;
			char *tmp_num = uwsgi_num2str(i + 1);
			char *placeholder = uwsgi_concat2((char *) "$", tmp_num);
			free(tmp_num);
			new_key = uwsgi_substitute(old_key, placeholder, opt_argv[i]);
			if (new_key != old_key)
				free(old_key);
			free(placeholder);
		}

		// build the value
		char *new_value = uwsgi_str(equal + 1);
		for (i = 0; i < count; i++) {
			char *old_value = new_value;
			char *tmp_num = uwsgi_num2str(i + 1);
			char *placeholder = uwsgi_concat2((char *) "$", tmp_num);
			free(tmp_num);
			new_value = uwsgi_substitute(old_value, placeholder, opt_argv[i]);
			if (new_value != old_value)
				free(old_value);
			free(placeholder);
		}
		// we can ignore its return value
		(void) uwsgi_manage_opt(new_key, new_value);
		p = strtok(NULL, ";");
	}

clear:
	free(tmp_val);
	free(tmp_opt);
	free(opt_argv);
	return 1;

}

int uwsgi_manage_opt(char *key, char *value) {

	struct uwsgi_option *op = uwsgi.options;
	while (op->name) {
		if (!strcmp(key, op->name)) {
			op->func(key, value, op->data);
			return 1;
		}
		op++;
	}

	struct uwsgi_custom_option *uco = uwsgi.custom_options;
	while (uco) {
		if (uwsgi_manage_custom_option(uco, key, value)) {
			return 1;
		}
		uco = uco->next;
	}
	return 0;

}

void uwsgi_configure() {

	int i;

	// and now apply the remaining configs
restart:
	for (i = 0; i < uwsgi.exported_opts_cnt; i++) {
		if (uwsgi.exported_opts[i]->configured)
			continue;
		uwsgi.dirty_config = 0;
		uwsgi.exported_opts[i]->configured = uwsgi_manage_opt(uwsgi.exported_opts[i]->key, uwsgi.exported_opts[i]->value);
		if (uwsgi.exported_opts[i]->configured == 0 && uwsgi.autoload) {
			uwsgi.dirty_config = uwsgi_try_autoload(uwsgi.exported_opts[i]->key);
		}
		if (uwsgi.dirty_config)
			goto restart;
	}

}

void config_magic_table_fill(char *filename, char **magic_table) {

	char *tmp = NULL;
	char *fullname = filename;

	magic_table['o'] = filename;

	if (uwsgi_check_scheme(filename) || !strcmp(filename, "-")) {
		return;
	}
	// we have a special case for symlinks
	else if (uwsgi_is_link(filename)) {
		if (filename[0] != '/') {
			fullname = uwsgi_concat3(uwsgi.cwd, "/", filename);
		}
	}
	else {

		fullname = uwsgi_expand_path(filename, strlen(filename), NULL);
		if (fullname) {
			char *minimal_name = uwsgi_malloc(strlen(fullname) + 1);
			memcpy(minimal_name, fullname, strlen(fullname));
			minimal_name[strlen(fullname)] = 0;
			free(fullname);
			fullname = minimal_name;
		}
		else {
			fullname = filename;
		}
	}

	magic_table['p'] = fullname;
	magic_table['s'] = uwsgi_get_last_char(fullname, '/') + 1;
	magic_table['d'] = uwsgi_concat2n(magic_table['p'], magic_table['s'] - magic_table['p'], "", 0);
	if (magic_table['d'][strlen(magic_table['d']) - 1] == '/') {
		tmp = magic_table['d'] + (strlen(magic_table['d']) - 1);
#ifdef UWSGI_DEBUG
		uwsgi_log("tmp = %c\n", *tmp);
#endif
		*tmp = 0;
	}
	if (uwsgi_get_last_char(magic_table['d'], '/')) {
		magic_table['c'] = uwsgi_str(uwsgi_get_last_char(magic_table['d'], '/') + 1);
		if (magic_table['c'][strlen(magic_table['c']) - 1] == '/') {
			magic_table['c'][strlen(magic_table['c']) - 1] = 0;
		}
	}

	int base = '0';
	char *to_split = uwsgi_str(magic_table['d']);
	char *p = strtok(to_split, "/");
	while (p && base <= '9') {
		magic_table[base] = p;
		base++;
		p = strtok(NULL, "/");
	}

	if (tmp)
		*tmp = '/';

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

	// on some platform thread cancellation is REALLY flaky
	if (uwsgi.no_threads_wait) return;

	int sudden_death = 0;

	pthread_mutex_lock(&uwsgi.six_feet_under_lock);
	for (i = 0; i < uwsgi.threads; i++) {
		if (!pthread_equal(uwsgi.workers[uwsgi.mywid].cores[i].thread_id, pthread_self())) {
			if (pthread_cancel(uwsgi.workers[uwsgi.mywid].cores[i].thread_id)) {
				uwsgi_error("pthread_cancel()\n");
				sudden_death = 1;
			}
		}
	}

	if (sudden_death)
		goto end;

	// wait for thread termination
	for (i = 0; i < uwsgi.threads; i++) {
		if (!pthread_equal(uwsgi.workers[uwsgi.mywid].cores[i].thread_id, pthread_self())) {
			ret = pthread_join(uwsgi.workers[uwsgi.mywid].cores[i].thread_id, NULL);
			if (ret) {
				uwsgi_log("pthread_join() = %d\n", ret);
			}
		}
	}

end:

	pthread_mutex_unlock(&uwsgi.six_feet_under_lock);
}
#endif


void gracefully_kill(int signum) {

	uwsgi_log("Gracefully killing worker %d (pid: %d)...\n", uwsgi.mywid, uwsgi.mypid);
	uwsgi.workers[uwsgi.mywid].manage_next_request = 0;
#ifdef UWSGI_THREADING
	if (uwsgi.threads > 1) {
		struct wsgi_request *wsgi_req = current_wsgi_req();
		wait_for_threads();
		if (!uwsgi.workers[uwsgi.mywid].cores[wsgi_req->async_id].in_request) {
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

	if (!uwsgi.workers[uwsgi.mywid].cores[0].in_request) {
		exit(UWSGI_RELOAD_CODE);
	}
}

void end_me(int signum) {
	exit(UWSGI_END_CODE);
}

void simple_goodbye_cruel_world() {

#ifdef UWSGI_THREADING
	if (uwsgi.threads > 1 && !uwsgi.to_hell) {
		wait_for_threads();
	}
#endif

	uwsgi.workers[uwsgi.mywid].manage_next_request = 0;
	uwsgi_log("...The work of process %d is done. Seeya!\n", getpid());
	exit(0);
}

void goodbye_cruel_world() {

	if (!uwsgi.gbcw_hook) {
		simple_goodbye_cruel_world();
	}
	else {
		uwsgi.gbcw_hook();
	}
}

#ifdef UWSGI_SPOOLER
static void uwsgi_signal_spoolers(int signum) {

	struct uwsgi_spooler *uspool = uwsgi.spoolers;
	while (uspool) {
		if (uspool->pid > 0) {
			kill(uspool->pid, SIGKILL);
			uwsgi_log("killing the spooler with pid %d\n", uspool->pid);
		}
		uspool = uspool->next;
	}

}
#endif

void kill_them_all(int signum) {
	int i;

	if (uwsgi.to_hell == 1)
		return;

	// count the number of active workers
	int active_workers = 0;
	for (i = 1; i <= uwsgi.numproc; i++) {
		if (uwsgi.workers[i].cheaped == 0 && uwsgi.workers[i].pid > 0) {
			active_workers++;
		}
	}
	uwsgi.marked_workers = active_workers;

	uwsgi.to_hell = 1;

	if (uwsgi.reload_mercy > 0) {
		uwsgi.master_mercy = uwsgi_now() + uwsgi.reload_mercy;
	}
	else {
		uwsgi.master_mercy = uwsgi_now() + 5;
	}

	uwsgi_log("SIGINT/SIGQUIT received...killing workers...\n");

	// unsubscribe if needed
	struct uwsgi_string_list *subscriptions = uwsgi.subscriptions;
	while (subscriptions) {
		uwsgi_log("unsubscribing from %s\n", subscriptions->value);
		uwsgi_subscribe(subscriptions->value, 1);
		subscriptions = subscriptions->next;
	}


	for (i = 1; i <= uwsgi.numproc; i++) {
		if (uwsgi.workers[i].pid > 0)
			kill(uwsgi.workers[i].pid, SIGINT);
	}

#ifdef UWSGI_SPOOLER
	uwsgi_signal_spoolers(SIGKILL);
#endif

	if (uwsgi.emperor_pid >= 0) {
		kill(uwsgi.emperor_pid, SIGKILL);
		waitpid(uwsgi.emperor_pid, &i, 0);
		uwsgi_log("killing the emperor with pid %d\n", uwsgi.emperor_pid);
	}


	uwsgi_detach_daemons();

	for (i = 0; i < ushared->gateways_cnt; i++) {
		if (ushared->gateways[i].pid > 0)
			kill(ushared->gateways[i].pid, SIGKILL);
	}

	for (i = 0; i < uwsgi.mules_cnt; i++) {
		if (uwsgi.mules[i].pid > 0)
			kill(uwsgi.mules[i].pid, SIGKILL);
	}

}

void grace_them_all(int signum) {
	int i;
	int waitpid_status;

	if (uwsgi.to_heaven == 1 || uwsgi.to_outworld == 1 || uwsgi.lazy_respawned > 0)
		return;

	// count the number of active workers
	int active_workers = 0;
	for (i = 1; i <= uwsgi.numproc; i++) {
		if (uwsgi.workers[i].cheaped == 0 && uwsgi.workers[i].pid > 0) {
			active_workers++;
		}
	}
	uwsgi.marked_workers = active_workers;

	if (!uwsgi.lazy)
		uwsgi.to_heaven = 1;
	else
		uwsgi.to_outworld = 1;

	if (uwsgi.reload_mercy > 0) {
		uwsgi.master_mercy = uwsgi_now() + uwsgi.reload_mercy;
	}
	else {
		// wait max 60 seconds for graceful reload
		uwsgi.master_mercy = uwsgi_now() + 60;
	}

#ifdef UWSGI_SPOOLER
	uwsgi_signal_spoolers(SIGKILL);
#endif

	if (uwsgi.emperor_pid >= 0) {
		kill(uwsgi.emperor_pid, SIGKILL);
		waitpid(uwsgi.emperor_pid, &i, 0);
		uwsgi_log("killing the emperor with pid %d\n", uwsgi.emperor_pid);
	}

	uwsgi_detach_daemons();

	for (i = 0; i < ushared->gateways_cnt; i++) {
		if (ushared->gateways[i].pid > 0)
			kill(ushared->gateways[i].pid, SIGKILL);
	}

	for (i = 0; i < uwsgi.mules_cnt; i++) {
		if (uwsgi.mules[i].pid > 0)
			kill(uwsgi.mules[i].pid, SIGKILL);
	}


	uwsgi_log("...gracefully killing workers...\n");

	if (uwsgi.unsubscribe_on_graceful_reload) {
		struct uwsgi_string_list *subscriptions = uwsgi.subscriptions;
		while (subscriptions) {
			uwsgi_log("unsubscribing from %s\n", subscriptions->value);
			uwsgi_subscribe(subscriptions->value, 1);
			subscriptions = subscriptions->next;
		}
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
					uwsgi.workers[i].destroy = 1;
					kill(uwsgi.workers[i].pid, SIGHUP);
				}
				else {
					uwsgi.workers[i].snapshot = uwsgi.workers[i].pid;
					kill(uwsgi.workers[i].pid, SIGURG);
					uwsgi.lazy_respawned++;
				}
			}
		}
		else if (uwsgi.workers[i].pid > 0) {
			if (uwsgi.lazy)
				uwsgi.workers[i].destroy = 1;
			kill(uwsgi.workers[i].pid, SIGHUP);
		}
	}

	if (uwsgi.auto_snapshot) {
		uwsgi.respawn_workers = uwsgi.numproc - uwsgi.auto_snapshot;
		if (!uwsgi.respawn_workers)
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
	if (uwsgi.to_outworld == 1 || uwsgi.lazy_respawned > 0)
		return;


	if (!uwsgi.workers) return;

	// count the number of active workers
	int active_workers = 0;
	for (i = 1; i <= uwsgi.numproc; i++) {
		if (uwsgi.workers[i].cheaped == 0 && uwsgi.workers[i].pid > 0) {
			active_workers++;
		}
	}
	uwsgi.marked_workers = active_workers;

	if (!uwsgi.lazy)
		uwsgi.to_heaven = 1;
	else
		uwsgi.to_outworld = 1;

	uwsgi_detach_daemons();

	for (i = 0; i < ushared->gateways_cnt; i++) {
		if (ushared->gateways[i].pid > 0)
			kill(ushared->gateways[i].pid, SIGKILL);
	}

	for (i = 0; i < uwsgi.mules_cnt; i++) {
		if (!uwsgi.mules)
			break;
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
	while (subscriptions) {
		uwsgi_log("unsubscribing from %s\n", subscriptions->value);
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
		uwsgi_set_processname(uwsgi.workers[uwsgi.mywid].name);
		return;
	}

	uwsgi.workers[uwsgi.mywid].manage_next_request = 0;
#ifdef UWSGI_THREADING
	if (uwsgi.threads > 1) {
		wait_for_threads();
	}
#endif
	uwsgi.snapshot = 1;
	uwsgi_set_processname(uwsgi.workers[uwsgi.mywid].snapshot_name);
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
		for (j = 1; j <= uwsgi.numproc; j++) {
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
	char ctime_storage[26];

	uwsgi_backtrace(uwsgi.backtrace_depth);

	if (uwsgi.cores > 1) {
		for (i = 0; i < uwsgi.cores; i++) {
			wsgi_req = &uwsgi.workers[uwsgi.mywid].cores[i].req;
			if (wsgi_req->uri_len > 0) {
#ifdef __sun__
				ctime_r((const time_t *) &wsgi_req->start_of_request_in_sec, ctime_storage, 26);
#else
				ctime_r((const time_t *) &wsgi_req->start_of_request_in_sec, ctime_storage);
#endif
				if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0 && uwsgi.workers[uwsgi.mywid].harakiri < uwsgi_now()) {
					uwsgi_log("HARAKIRI: --- uWSGI worker %d core %d (pid: %d) WAS managing request %.*s since %.*s ---\n", (int) uwsgi.mywid, i, (int) uwsgi.mypid, wsgi_req->uri_len, wsgi_req->uri, 24, ctime_storage);
				}
				else {
					uwsgi_log("SIGUSR2: --- uWSGI worker %d core %d (pid: %d) is managing request %.*s since %.*s ---\n", (int) uwsgi.mywid, i, (int) uwsgi.mypid, wsgi_req->uri_len, wsgi_req->uri, 24, ctime_storage);
				}
			}
		}
	}
	else {
		wsgi_req = &uwsgi.workers[uwsgi.mywid].cores[0].req;
		if (wsgi_req->uri_len > 0) {
#ifdef __sun__
			ctime_r((const time_t *) &wsgi_req->start_of_request_in_sec, ctime_storage, 26);
#else
			ctime_r((const time_t *) &wsgi_req->start_of_request_in_sec, ctime_storage);
#endif
			if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0 && uwsgi.workers[uwsgi.mywid].harakiri < uwsgi_now()) {
				uwsgi_log("HARAKIRI: --- uWSGI worker %d (pid: %d) WAS managing request %.*s since %.*s ---\n", (int) uwsgi.mywid, (int) uwsgi.mypid, wsgi_req->uri_len, wsgi_req->uri, 24, ctime_storage);
			}
			else {
				uwsgi_log("SIGUSR2: --- uWSGI worker %d (pid: %d) is managing request %.*s since %.*s ---\n", (int) uwsgi.mywid, (int) uwsgi.mypid, wsgi_req->uri_len, wsgi_req->uri, 24, ctime_storage);
			}
		}
		else if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0 && uwsgi.workers[uwsgi.mywid].harakiri < uwsgi_now() && uwsgi.workers[uwsgi.mywid].sig) {
			uwsgi_log("HARAKIRI: --- uWSGI worker %d (pid: %d) WAS handling signal %d ---\n", (int) uwsgi.mywid, (int) uwsgi.mypid, uwsgi.workers[uwsgi.mywid].signum);
		}
	}
}


pid_t masterpid;

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

void uwsgi_exec_atexit(void) {
	if (getpid() == masterpid) {
		// now run exit scripts needed by the user
		struct uwsgi_string_list *usl = uwsgi.exec_as_user_atexit;
		while (usl) {
			uwsgi_log("running \"%s\" (as uid: %d gid: %d) ...\n", usl->value, (int) getuid(), (int) getgid());
			int ret = uwsgi_run_command_and_wait(NULL, usl->value);
			if (ret != 0) {
				uwsgi_log("command \"%s\" exited with non-zero code: %d\n", usl->value, ret);
			}
			usl = usl->next;
		}
	}
}

static void vacuum(void) {

	struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;

	if (uwsgi.restore_tc) {
		if (tcsetattr(0, TCSANOW, &uwsgi.termios)) {
			uwsgi_error("tcsetattr()");
		}
	}

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
				if (uwsgi_sock->family == AF_UNIX && uwsgi_sock->name[0] != '@') {
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

/*static*/ void uwsgi_command_signal(char *opt) {

	int tmp_signal;
	char *colon = strchr(opt, ',');
	if (!colon) {
		uwsgi_log("invalid syntax for signal, must be addr,signal\n");
		exit(1);
	}

	colon[0] = 0;
	tmp_signal = atoi(colon + 1);

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

	uwsgi.argv = uwsgi_malloc(sizeof(char *) * (argc + 1));

	for (i = 0; i < argc; i++) {
		if (i == 0 || argv[0] + uwsgi.max_procname + 1 == argv[i]) {
			uwsgi.max_procname += strlen(argv[i]) + 1;
		}
		uwsgi.argv[i] = strdup(argv[i]);
	}

	// required by execve
	uwsgi.argv[i] = NULL;

	uwsgi.max_procname++;

	for (i = 0; environ[i] != NULL; i++) {
		// useless
		//if ((environ[0] + uwsgi.max_procname + 1) == environ[i]) {
		uwsgi.max_procname += strlen(environ[i]) + 1;
		//}
		env_count++;
	}

	uwsgi.environ = uwsgi_malloc(sizeof(char *) * env_count);
	for (i = 0; i < env_count; i++) {
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


void uwsgi_plugins_atexit(void) {

	int j;

	if (!uwsgi.workers)
		return;

	// the master cannot run atexit handlers...
	if (uwsgi.master_process && uwsgi.workers[0].pid == getpid())
		return;

	for (j = 0; j < uwsgi.gp_cnt; j++) {
		if (uwsgi.gp[j]->atexit) {
			uwsgi.gp[j]->atexit();
		}
	}

	for (j = 0; j < 256; j++) {
		if (uwsgi.p[j]->atexit) {
			uwsgi.p[j]->atexit();
		}
	}

}

void uwsgi_backtrace(int depth) {

#if defined(__linux__) || defined(__APPLE__) || defined(UWSGI_HAS_EXECINFO)

#include <execinfo.h>

	void **btrace = uwsgi_malloc(sizeof(void *) * depth);
	size_t bt_size, i;
	char **bt_strings;

	bt_size = backtrace(btrace, depth);

	bt_strings = backtrace_symbols(btrace, bt_size);

	uwsgi_log("*** backtrace of %d ***\n", (int) getpid());
	for (i = 0; i < bt_size; i++) {
		uwsgi_log("%s\n", bt_strings[i]);
	}

	free(btrace);
	uwsgi_log("*** end of backtrace ***\n");


#endif

}

void uwsgi_segfault(int signum) {

	uwsgi_log("!!! uWSGI process %d got Segmentation Fault !!!\n", (int) getpid());
	uwsgi_backtrace(uwsgi.backtrace_depth);

	// restore default handler to generate core
	signal(signum, SIG_DFL);
	kill(getpid(), signum);

	// never here...
	exit(1);
}

void uwsgi_fpe(int signum) {

	uwsgi_log("!!! uWSGI process %d got Floating Point Exception !!!\n", (int) getpid());
	uwsgi_backtrace(uwsgi.backtrace_depth);

	// restore default handler to generate core
	signal(signum, SIG_DFL);
	kill(getpid(), signum);

	// never here...
	exit(1);
}

void uwsgi_flush_logs() {

	struct pollfd pfd;

	if (!uwsgi.master_process)
		return;
	if (!uwsgi.log_master)
		return;

	if (uwsgi.workers) {
		if (uwsgi.workers[0].pid == getpid()) {
			goto check;
		}
	}


	if (uwsgi.mywid == 0)
		goto check;

	return;

check:
	// this buffer could not be initialized !!!
	if (uwsgi.log_master) {
		uwsgi.log_master_buf = uwsgi_malloc(uwsgi.log_master_bufsize);
	}

	// check for data in logpipe
	pfd.events = POLLIN;
	pfd.fd = uwsgi.shared->worker_log_pipe[0];
	if (pfd.fd == -1)
		pfd.fd = 2;

	while (poll(&pfd, 1, 0) > 0) {
		if (uwsgi_master_log()) {
			break;
		}
	}
}

static void plugins_list(void) {
	int i;
	uwsgi_log("\n*** uWSGI loaded generic plugins ***\n");
	for (i = 0; i < uwsgi.gp_cnt; i++) {
		uwsgi_log("%s\n", uwsgi.gp[i]->name);
	}

	uwsgi_log("\n*** uWSGI loaded request plugins ***\n");
	for (i = 0; i < 256; i++) {
		if (uwsgi.p[i] == &unconfigured_plugin)
			continue;
		uwsgi_log("%d: %s\n", i, uwsgi.p[i]->name);
	}

	uwsgi_log("--- end of plugins list ---\n\n");
}

static void loggers_list(void) {
	struct uwsgi_logger *ul = uwsgi.loggers;
	uwsgi_log("\n*** uWSGI loaded loggers ***\n");
	while (ul) {
		uwsgi_log("%s\n", ul->name);
		ul = ul->next;
	}
	uwsgi_log("--- end of loggers list ---\n\n");
}

static void cheaper_algo_list(void) {
	struct uwsgi_cheaper_algo *uca = uwsgi.cheaper_algos;
	uwsgi_log("\n*** uWSGI loaded cheaper algorithms ***\n");
	while (uca) {
		uwsgi_log("%s\n", uca->name);
		uca = uca->next;
	}
	uwsgi_log("--- end of cheaper algorithms list ---\n\n");
}

#ifdef UWSGI_ROUTING
static void router_list(void) {
	struct uwsgi_router *ur = uwsgi.routers;
	uwsgi_log("\n*** uWSGI loaded routers ***\n");
	while (ur) {
		uwsgi_log("%s\n", ur->name);
		ur = ur->next;
	}
	uwsgi_log("--- end of routers list ---\n\n");
}
#endif

static void loop_list(void) {
	struct uwsgi_loop *loop = uwsgi.loops;
	uwsgi_log("\n*** uWSGI loaded loop engines ***\n");
	while (loop) {
		uwsgi_log("%s\n", loop->name);
		loop = loop->next;
	}
	uwsgi_log("--- end of loop engines list ---\n\n");
}

static void imperial_monitor_list(void) {
	struct uwsgi_imperial_monitor *uim = uwsgi.emperor_monitors;
	uwsgi_log("\n*** uWSGI loaded imperial monitors ***\n");
	while (uim) {
		uwsgi_log("%s\n", uim->scheme);
		uim = uim->next;
	}
	uwsgi_log("--- end of imperial monitors list ---\n\n");
}

static void clocks_list(void) {
	struct uwsgi_clock *clocks = uwsgi.clocks;
	uwsgi_log("\n*** uWSGI loaded clocks ***\n");
	while (clocks) {
		uwsgi_log("%s\n", clocks->name);
		clocks = clocks->next;
	}
	uwsgi_log("--- end of clocks list ---\n\n");
}

#ifdef UWSGI_ALARM
static void alarms_list(void) {
	struct uwsgi_alarm *alarms = uwsgi.alarms;
	uwsgi_log("\n*** uWSGI loaded alarms ***\n");
	while (alarms) {
		uwsgi_log("%s\n", alarms->name);
		alarms = alarms->next;
	}
	uwsgi_log("--- end of alarms list ---\n\n");
}
#endif

static time_t uwsgi_unix_seconds() {
	return time(NULL);
}

static uint64_t uwsgi_unix_microseconds() {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return ((uint64_t) tv.tv_sec * 1000000) + tv.tv_usec;
}

static struct uwsgi_clock uwsgi_unix_clock = {
	.name = "unix",
	.seconds = uwsgi_unix_seconds,
	.microseconds = uwsgi_unix_microseconds,
};

#ifdef UWSGI_AS_SHARED_LIBRARY
int uwsgi_init(int argc, char *argv[], char *envp[]) {

#ifdef __APPLE__
	char ***envPtr = _NSGetEnviron();
	environ = *envPtr;
#endif

#else
int main(int argc, char *argv[], char *envp[]) {
#endif

	int i;

#ifdef UNBIT
	//struct uidsec_struct us;
#endif

	struct utsname uuts;

	signal(SIGSEGV, uwsgi_segfault);
	signal(SIGFPE, uwsgi_fpe);
	signal(SIGHUP, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);


	//initialize masterpid with a default value
	masterpid = getpid();

	memset(&uwsgi, 0, sizeof(struct uwsgi_server));
	uwsgi.cwd = uwsgi_get_cwd();

	init_magic_table(uwsgi.magic_table);

	// initialize the clock
	uwsgi_register_clock(&uwsgi_unix_clock);
	uwsgi_set_clock("unix");

	// manage/flush logs
	atexit(uwsgi_flush_logs);
	// clear sockets, pidfiles...
	atexit(vacuum);
	// call user scripts
	atexit(uwsgi_exec_atexit);
	// call plugin specific exit hooks
	atexit(uwsgi_plugins_atexit);

	// allocate main shared memory
	uwsgi.shared = (struct uwsgi_shared *) uwsgi_calloc_shared(sizeof(struct uwsgi_shared));

	// initialize request plugin to void
	for (i = 0; i < 256; i++) {
		uwsgi.p[i] = &unconfigured_plugin;
	}

	// set default values
	uwsgi_init_default();

	// set default logit hook
	uwsgi.logit = uwsgi_logit_simple;

#ifdef UWSGI_BLACKLIST
	if (!uwsgi_file_to_string_list(UWSGI_BLACKLIST, &uwsgi.blacklist)) {
		uwsgi_log("you cannot run this build of uWSGI without a blacklist file\n");
		exit(1);
	}
#endif

#ifdef UWSGI_WHITELIST
	if (!uwsgi_file_to_string_list(UWSGI_WHITELIST, &uwsgi.whitelist)) {
		uwsgi_log("you cannot run this build of uWSGI without a whitelist file\n");
		exit(1);
	}
#endif

	// get startup time
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

	// check if we are under the Emperor
	uwsgi_check_emperor();

	char *screen_env = getenv("TERM");
	if (screen_env) {
		if (!strcmp(screen_env, "screen")) {
			uwsgi.screen_session = getenv("STY");
		}
	}


	// count/set the current reload status
	uwsgi_setup_reload();

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
	uwsgi_autoload_plugins_by_name(argv[0]);


	// build the options structure
	build_options();

	// set a couple of 'static' magic vars
	uwsgi.magic_table['v'] = uwsgi.cwd;
	uwsgi.magic_table['h'] = uwsgi.hostname;

	// you can embed a ini file in the uWSGi binary with default options
#ifdef UWSGI_EMBED_CONFIG
	uwsgi_ini_config("", uwsgi.magic_table);
	// rebuild options if a custom ini is set
	build_options();
#endif
	//parse environ
	parse_sys_envs(environ);

	// parse commandline options
	uwsgi_commandline_config();

	// second pass: ENVs
	uwsgi_apply_config_pass('$', (char *(*)(char *)) getenv);

	// third pass: FILEs
	uwsgi_apply_config_pass('@', uwsgi_simple_file_read);

	// last pass: REFERENCEs
	uwsgi_apply_config_pass('%', uwsgi_get_exported_opt);

#ifdef UWSGI_MATHEVAL
	// optional pass: MATH
	uwsgi_apply_config_pass('=', uwsgi_matheval_str);
#endif

	// ok, the options dictionary is available, lets manage it
	uwsgi_configure();

	// initial log setup (files and daemonization)
	uwsgi_setup_log();

	// enable never-swap mode
	if (uwsgi.never_swap) {
		if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
			uwsgi_error("mlockall()");
		}
	}

	if (uwsgi.flock2)
		uwsgi_opt_flock(NULL, uwsgi.flock2, NULL);

	if (uwsgi.flock_wait2)
		uwsgi_opt_flock(NULL, uwsgi.flock_wait2, NULL);

	// setup master logging
	if (uwsgi.log_master)
		uwsgi_setup_log_master();

	// setup main loops
	uwsgi_register_loop("simple", simple_loop);
#ifdef UWSGI_ASYNC
	uwsgi_register_loop("async", async_loop);
#endif

	// setup cheaper algos
	uwsgi_register_cheaper_algo("spare", uwsgi_cheaper_algo_spare);
	uwsgi_register_cheaper_algo("backlog", uwsgi_cheaper_algo_backlog);

	// setup imperial monitors
	uwsgi_register_imperial_monitor("dir", uwsgi_imperial_monitor_directory_init, uwsgi_imperial_monitor_directory);
	uwsgi_register_imperial_monitor("glob", uwsgi_imperial_monitor_glob_init, uwsgi_imperial_monitor_glob);

	// setup stats pushers
	uwsgi_register_stats_pusher("file", uwsgi_stats_pusher_file);
	uwsgi_stats_pusher_setup();


#ifdef UWSGI_ALARM
	// register embedded alarms
	uwsgi_register_embedded_alarms();
#endif


	/* uWSGI IS CONFIGURED !!! */

	if (uwsgi.dump_options) {
		struct option *lopt = uwsgi.long_options;
		while (lopt && lopt->name) {
			fprintf(stdout, "%s\n", lopt->name);
			lopt++;
		}
		exit(0);
	}

	if (uwsgi.show_config)
		show_config();

	if (uwsgi.plugins_list)
		plugins_list();

	if (uwsgi.loggers_list)
		loggers_list();

	if (uwsgi.cheaper_algo_list)
		cheaper_algo_list();


#ifdef UWSGI_ROUTING
	if (uwsgi.router_list)
		router_list();
#endif


	if (uwsgi.loop_list)
		loop_list();

	if (uwsgi.imperial_monitor_list)
		imperial_monitor_list();

	if (uwsgi.clock_list)
		clocks_list();

#ifdef UWSGI_ALARM
	if (uwsgi.alarms_list)
		alarms_list();
#endif

	// set the clock
	if (uwsgi.requested_clock)
		uwsgi_set_clock(uwsgi.requested_clock);

	// call cluster initialization procedures
#ifdef UWSGI_MULTICAST
	cluster_setup();
#endif

	if (uwsgi.binary_path == uwsgi.argv[0]) {
		uwsgi.binary_path = uwsgi_str(uwsgi.argv[0]);
	}

	uwsgi_log_initial("*** Starting uWSGI %s (%dbit) on [%.*s] ***\n", UWSGI_VERSION, (int) (sizeof(void *)) * 8, 24, ctime((const time_t *) &uwsgi.start_tv.tv_sec));

#ifdef UWSGI_DEBUG
	uwsgi_log("***\n*** You are running a DEBUG version of uWSGI, please disable debug in your build profile and recompile it ***\n***\n");
#endif

	uwsgi_log_initial("compiled with version: %s on %s\n", __VERSION__, UWSGI_BUILD_DATE);

#ifdef __sun__
	if (uname(&uuts) < 0) {
#else
	if (uname(&uuts)) {
#endif
		uwsgi_error("uname()");
	}
	else {
		uwsgi_log_initial("os: %s-%s %s\n", uuts.sysname, uuts.release, uuts.version);
		uwsgi_log_initial("nodename: %s\n", uuts.nodename);
		uwsgi_log_initial("machine: %s\n", uuts.machine);
	}

	uwsgi_log_initial("clock source: %s\n", uwsgi.clock->name);
#ifdef UWSGI_PCRE
	if (uwsgi.pcre_jit) {
		uwsgi_log_initial("pcre jit enabled\n");
	}
	else {
		uwsgi_log_initial("pcre jit disabled\n");
	}
#endif

#ifdef __BIG_ENDIAN__
	uwsgi_log_initial("*** big endian arch detected ***\n");
#endif

#if defined(_SC_NPROCESSORS_ONLN)
	uwsgi.cpus = sysconf(_SC_NPROCESSORS_ONLN);
#elif defined(_SC_NPROCESSORS_CONF)
	uwsgi.cpus = sysconf(_SC_NPROCESSORS_CONF);
#endif

	uwsgi_log_initial("detected number of CPU cores: %d\n", uwsgi.cpus);


	uwsgi_log_initial("current working directory: %s\n", uwsgi.cwd);

	if (uwsgi.screen_session) {
		uwsgi_log("*** running under screen session %s ***\n", uwsgi.screen_session);
	}

	if (uwsgi.pidfile && !uwsgi.is_a_reload) {
		uwsgi_write_pidfile(uwsgi.pidfile);
	}

	uwsgi_log_initial("detected binary path: %s\n", uwsgi.binary_path);

	if (uwsgi.is_a_reload) {
		struct rlimit rl;
		if (!getrlimit(RLIMIT_NOFILE, &rl)) {
			uwsgi.max_fd = rl.rlim_cur;
		}
	}

	// initialize shared sockets
	uwsgi_setup_shared_sockets();

	// start the Emperor if needed
	if (uwsgi.early_emperor && uwsgi.emperor) {
		uwsgi_emperor_start();
	}

	// run the pre-jail scripts
	struct uwsgi_string_list *usl = uwsgi.exec_pre_jail;
	while (usl) {
		uwsgi_log("running \"%s\" (pre-jail)...\n", usl->value);
		int ret = uwsgi_run_command_and_wait(NULL, usl->value);
		if (ret != 0) {
			uwsgi_log("command \"%s\" exited with non-zero code: %d\n", usl->value, ret);
			exit(1);
		}
		usl = usl->next;
	}

	// we could now patch the binary
	if (uwsgi.privileged_binary_patch) {
		uwsgi.argv[0] = uwsgi.privileged_binary_patch;
		execvp(uwsgi.privileged_binary_patch, uwsgi.argv);
		uwsgi_error("execvp()");
		exit(1);
	}

	if (uwsgi.privileged_binary_patch_arg) {
		uwsgi_exec_command_with_args(uwsgi.privileged_binary_patch_arg);
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

	int i, j;

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
		if (!uwsgi.is_a_reload || uwsgi.log_reopen) {
			logto(uwsgi.logto2);
		}
	}

	if (uwsgi.chdir) {
		if (chdir(uwsgi.chdir)) {
			uwsgi_error("chdir()");
			exit(1);
		}
	}

	if (uwsgi.pidfile2 && !uwsgi.is_a_reload) {
		uwsgi_write_pidfile(uwsgi.pidfile2);
	}

	if (!uwsgi.master_process && !uwsgi.command_mode) {
		uwsgi_log_initial("*** WARNING: you are running uWSGI without its master process manager ***\n");
	}

#ifdef RLIMIT_NPROC
	if (uwsgi.rl_nproc.rlim_max > 0) {
		uwsgi.rl_nproc.rlim_cur = uwsgi.rl_nproc.rlim_max;
		uwsgi_log_initial("limiting number of processes to %d...\n", (int) uwsgi.rl_nproc.rlim_max);
		if (setrlimit(RLIMIT_NPROC, &uwsgi.rl_nproc)) {
			uwsgi_error("setrlimit()");
		}
	}

	if (!getrlimit(RLIMIT_NPROC, &uwsgi.rl_nproc)) {
		if (uwsgi.rl_nproc.rlim_cur != RLIM_INFINITY) {
			uwsgi_log_initial("your processes number limit is %d\n", (int) uwsgi.rl_nproc.rlim_cur);
			if ((int) uwsgi.rl_nproc.rlim_cur < uwsgi.numproc + uwsgi.master_process) {
				uwsgi.numproc = uwsgi.rl_nproc.rlim_cur - 1;
				uwsgi_log_initial("!!! number of workers adjusted to %d due to system limits !!!\n", uwsgi.numproc);
			}
		}
	}
#endif
#ifndef __OpenBSD__

	if (uwsgi.rl.rlim_max > 0) {
		uwsgi.rl.rlim_cur = uwsgi.rl.rlim_max;
		uwsgi_log_initial("limiting address space of processes...\n");
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
			uwsgi_log_initial("scheduler priority set to %d\n", uwsgi.prio);
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

	// automatically fix options
	sanitize_args();

	// start the Emperor if needed
	if (!uwsgi.early_emperor && uwsgi.emperor) {
		uwsgi_emperor_start();
	}

	// end of generic initialization


	// build mime.types dictionary
	if (uwsgi.build_mime_dict) {
		if (!uwsgi.mime_file)
			uwsgi_string_new_list(&uwsgi.mime_file, "/etc/mime.types");
		struct uwsgi_string_list *umd = uwsgi.mime_file;
		while (umd) {
			if (!access(umd->value, R_OK)) {
				uwsgi_build_mime_dict(umd->value);
			}
			else {
				uwsgi_log("!!! no %s file found !!!\n", umd->value);
			}
			umd = umd->next;
		}
	}

	if (uwsgi.requested_max_fd) {
		uwsgi.rl.rlim_cur = uwsgi.requested_max_fd;
		uwsgi.rl.rlim_max = uwsgi.requested_max_fd;
		if (setrlimit(RLIMIT_NOFILE, &uwsgi.rl)) {
			uwsgi_error("setrlimit()");
		}
	}

	if (!getrlimit(RLIMIT_NOFILE, &uwsgi.rl)) {
		uwsgi.max_fd = uwsgi.rl.rlim_cur;
		uwsgi_log_initial("detected max file descriptor number: %lu\n", (unsigned long) uwsgi.max_fd);
	}

	if (uwsgi.async > 1) {
		if ((unsigned long) uwsgi.max_fd < (unsigned long) uwsgi.async) {
			uwsgi_log("- your current max open files limit is %lu, this is lower than requested async cores !!! -\n", (unsigned long) uwsgi.max_fd);
			uwsgi.rl.rlim_cur = uwsgi.async;
			uwsgi.rl.rlim_max = uwsgi.async;
			if (!setrlimit(RLIMIT_NOFILE, &uwsgi.rl)) {
				uwsgi_log("max open files limit raised to %lu\n", (unsigned long) uwsgi.rl.rlim_cur);
				uwsgi.async = uwsgi.rl.rlim_cur;
				uwsgi.max_fd = uwsgi.rl.rlim_cur;
			}
			else {
				uwsgi.async = (int) uwsgi.max_fd;
			}
		}
		uwsgi_log("- async cores set to %d - fd table size: %d\n", uwsgi.async, (int) uwsgi.max_fd);
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

#ifdef UWSGI_DEBUG
	uwsgi_log("cores allocated...\n");
#endif

	if (uwsgi.vhost) {
		uwsgi_log("VirtualHosting mode enabled.\n");
	}


	// setup locking
	uwsgi_setup_locking();

	// setup sharedarea
	if (uwsgi.sharedareasize > 0) {
		uwsgi.sharedarea = uwsgi_calloc_shared(uwsgi.page_size * uwsgi.sharedareasize);
		uwsgi_log("shared area mapped at %p, you can access it with uwsgi.sharedarea* functions.\n", uwsgi.sharedarea);
		uwsgi.sa_lock = uwsgi_rwlock_init("sharedarea");
	}

#ifdef UWSGI_SNMP
	uwsgi.snmp_lock = uwsgi_lock_init("snmp");
#endif

	// setup queue
	if (uwsgi.queue_size > 0) {
		uwsgi_init_queue();
	}

	// setup cache
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

		// systemd/upstart/zerg socket activation
		if (!uwsgi.is_a_reload) {
			uwsgi_setup_systemd();
			uwsgi_setup_upstart();
			uwsgi_setup_zerg();
		}


		//check for inherited sockets
		if (uwsgi.is_a_reload) {
			uwsgi_setup_inherited_sockets();
		}


		//now bind all the unbound sockets
		uwsgi_bind_sockets();

		// put listening socket in non-blocking state and set the protocol
		uwsgi_set_sockets_protocols();

	}


	// initialize request plugin only if workers or master are available
	if (uwsgi.sockets || uwsgi.master_process || uwsgi.no_server || uwsgi.command_mode || uwsgi.loop) {
		for (i = 0; i < 256; i++) {
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

	// again check for workers/sockets...
	if (uwsgi.sockets || uwsgi.master_process || uwsgi.no_server || uwsgi.command_mode || uwsgi.loop) {
		for (i = 0; i < 256; i++) {
			if (uwsgi.p[i]->post_init) {
				uwsgi.p[i]->post_init();
			}
		}
	}

	uwsgi.current_wsgi_req = simple_current_wsgi_req;


#ifdef UWSGI_THREADING
	if (uwsgi.has_threads) {
		if (uwsgi.threads > 1)
			uwsgi.current_wsgi_req = threaded_current_wsgi_req;
		(void) pthread_attr_init(&uwsgi.threads_attr);
		if (uwsgi.threads_stacksize) {
			if (pthread_attr_setstacksize(&uwsgi.threads_attr, uwsgi.threads_stacksize * 1024) == 0) {
				uwsgi_log("threads stack size set to %dk\n", uwsgi.threads_stacksize);
			}
			else {
				uwsgi_log("!!! unable to set requested threads stacksize !!!\n");
			}
		}

		pthread_mutex_init(&uwsgi.lock_static, NULL);

		// again check for workers/sockets...
		if (uwsgi.sockets || uwsgi.master_process || uwsgi.no_server || uwsgi.command_mode || uwsgi.loop) {
			for (i = 0; i < 256; i++) {
				if (uwsgi.p[i]->enable_threads)
					uwsgi.p[i]->enable_threads();
			}
		}
	}
#endif

	// users of the --loop option should know what they are doing... really...
#ifndef UWSGI_DEBUG
	if (uwsgi.loop)
		goto unsafe;
#endif

#ifdef UWSGI_UDP
	if (!uwsgi.sockets && !ushared->gateways_cnt && !uwsgi.no_server && !uwsgi.udp_socket && !uwsgi.emperor && !uwsgi.command_mode) {
#else
	if (!uwsgi.sockets && !ushared->gateways_cnt && !uwsgi.no_server && !uwsgi.emperor && !uwsgi.command_mode) {
#endif
		uwsgi_log("The -s/--socket option is missing and stdin is not a socket.\n");
		exit(1);
	}
	else if (!uwsgi.sockets && ushared->gateways_cnt && !uwsgi.no_server && !uwsgi.master_process) {
		// here we will have a zombie... sorry
		uwsgi_log("...you should enable the master process... really...\n");
		exit(0);
	}

	if (!uwsgi.sockets)
		uwsgi.numproc = 0;

	if (uwsgi.command_mode) {
		uwsgi.sockets = NULL;
		uwsgi.numproc = 1;
		uwsgi.to_hell = 1;
	}

#ifndef UWSGI_DEBUG
unsafe:
#endif

#ifdef UWSGI_DEBUG
	struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;
	int so_bufsize;
	socklen_t so_bufsize_len;
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
	if (uwsgi.sockets)
		uwsgi_log("your server socket listen backlog is limited to %d connections\n", uwsgi.listen_queue);
#endif

	if (uwsgi.crons) {
		struct uwsgi_cron *ucron = uwsgi.crons;
		while (ucron) {
			uwsgi_log("command \"%s\" registered as uWSGI-cron task\n", ucron->command);
			ucron = ucron->next;
		}
	}


	// initialize post buffering values
	if (uwsgi.post_buffering > 0)
		uwsgi_setup_post_buffering();

	// initialize workers/master shared memory segments
	uwsgi_setup_workers();

	// create signal pipes if master is enabled
	if (uwsgi.master_process) {
		for (i = 1; i <= uwsgi.numproc; i++) {
			create_signal_pipe(uwsgi.workers[i].signal_pipe);
		}
	}

	// set masterpid
	uwsgi.mypid = getpid();
	masterpid = uwsgi.mypid;
	uwsgi.workers[0].pid = masterpid;

	// initialize mules and farms
	uwsgi_setup_mules_and_farms();

	if (uwsgi.command_mode) {
		uwsgi_log("*** Operational MODE: command ***\n");
	}
	else if (!uwsgi.numproc) {
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

	// set a default request structure (for loading apps...)
	uwsgi.wsgi_req = &uwsgi.workers[0].cores[0].req;

	// cores are allocated, lets allocate logformat (if required)
	if (uwsgi.logformat) {
		uwsgi_build_log_format(uwsgi.logformat);
		uwsgi.logit = uwsgi_logit_lf;
		if (uwsgi.logformat_strftime) {
			uwsgi.logit = uwsgi_logit_lf_strftime;
		}
		uwsgi.logvectors = uwsgi_malloc(sizeof(struct iovec *) * uwsgi.cores);
		for (j = 0; j < uwsgi.cores; j++) {
			uwsgi.logvectors[j] = uwsgi_malloc(sizeof(struct iovec) * uwsgi.logformat_vectors);
			uwsgi.logvectors[j][uwsgi.logformat_vectors - 1].iov_base = "\n";
			uwsgi.logvectors[j][uwsgi.logformat_vectors - 1].iov_len = 1;
		}
	}

#ifdef UWSGI_SPOOLER
	// initialize locks and socket as soon as possibile, as the master could enqueue tasks
	if (uwsgi.spoolers != NULL && (uwsgi.sockets || uwsgi.loop)) {
		create_signal_pipe(uwsgi.shared->spooler_signal_pipe);
		struct uwsgi_spooler *uspool = uwsgi.spoolers;
		while (uspool) {
			// lock is required even in EXTERNAL mode
			uspool->lock = uwsgi_lock_init(uwsgi_concat2("spooler on ", uspool->dir));
			if (uspool->mode == UWSGI_SPOOLER_EXTERNAL)
				goto next;
			create_signal_pipe(uspool->signal_pipe);
next:
			uspool = uspool->next;
		}
	}
#endif


	// preinit apps (create the language environment)
	for (i = 0; i < 256; i++) {
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
	if (!uwsgi.lazy && !uwsgi.lazy_apps) {
		uwsgi_init_all_apps();
	}

	// postinit apps (setup specific features after app initialization)
	for (i = 0; i < 256; i++) {
		if (uwsgi.p[i]->postinit_apps) {
			uwsgi.p[i]->postinit_apps();
		}
	}

	for (i = 0; i < uwsgi.gp_cnt; i++) {
		if (uwsgi.gp[i]->postinit_apps) {
			uwsgi.gp[i]->postinit_apps();
		}
	}


	if (uwsgi.daemonize2) {
		masterpid = uwsgi_daemonize2();
	}

	if (uwsgi.no_server) {
		uwsgi_log("no-server mode requested. Goodbye.\n");
		exit(0);
	}


	if (!uwsgi.master_process && uwsgi.numproc == 0) {
		exit(0);
	}

#ifdef UWSGI_MINTERPRETERS
	if (!uwsgi.single_interpreter && uwsgi.numproc > 0) {
		uwsgi_log("*** uWSGI is running in multiple interpreter mode ***\n");
	}
#endif

	// check for request plugins, and eventually print a warning
	int rp_available = 0;
	for (i = 0; i < 256; i++) {
		if (uwsgi.p[i] != &unconfigured_plugin) {
			rp_available = 1;
			break;
		}
	}
	if (!rp_available && !ushared->gateways_cnt) {
		uwsgi_log("!!!!!!!!!!!!!! WARNING !!!!!!!!!!!!!!\n");
		uwsgi_log("no request plugin is loaded, you will not be able to manage requests.\n");
		uwsgi_log("you may need to install the package for your language of choice, or simply load it with --plugin.\n");
		uwsgi_log("!!!!!!!!!!! END OF WARNING !!!!!!!!!!\n");
	}

#ifdef __linux__
#ifdef MADV_MERGEABLE
	if (uwsgi.linux_ksm > 0) {
		uwsgi_log("[uwsgi-KSM] enabled with frequency: %d\n", uwsgi.linux_ksm);
	}
#endif
#endif

	if (uwsgi.master_process) {
		// initialize a mutex to avoid glibc problem with pthread+fork()
		if (uwsgi.threaded_logger) {
			pthread_mutex_init(&uwsgi.threaded_logger_lock, NULL);
		}

		if (uwsgi.is_a_reload) {
			uwsgi_log("gracefully (RE)spawned uWSGI master process (pid: %d)\n", uwsgi.mypid);
		}
		else {
			uwsgi_log("spawned uWSGI master process (pid: %d)\n", uwsgi.mypid);
		}
	}



	// security in multiuser environment: allow only a subset of modifiers
	if (uwsgi.allowed_modifiers) {
		for (i = 0; i < 256; i++) {
			if (!uwsgi_list_has_num(uwsgi.allowed_modifiers, i)) {
				uwsgi.p[i]->request = unconfigured_hook;
				uwsgi.p[i]->after_request = unconfigured_after_hook;
			}
		}
	}

	// master fixup
	for (i = 0; i < 256; i++) {
		if (uwsgi.p[i]->master_fixup) {
			uwsgi.p[i]->master_fixup(0);
		}
	}



#ifdef UWSGI_SPOOLER
	if (uwsgi.spoolers != NULL && (uwsgi.sockets || uwsgi.loop)) {
		struct uwsgi_spooler *uspool = uwsgi.spoolers;
		while (uspool) {
			if (uspool->mode == UWSGI_SPOOLER_EXTERNAL)
				goto next2;
			uspool->pid = spooler_start(uspool);
next2:
			uspool = uspool->next;
		}
	}
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
		uwsgi.workers[1].last_spawn = uwsgi_now();
		uwsgi.workers[1].manage_next_request = 1;
		uwsgi.mywid = 1;
		uwsgi.respawn_delta = uwsgi_now();
	}
	else {
		// setup internal signalling system
		create_signal_pipe(uwsgi.shared->worker_signal_pipe);
		uwsgi.signal_socket = uwsgi.shared->worker_signal_pipe[1];
	}

	// uWSGI is ready
	uwsgi_notify_ready();
	uwsgi.current_time = uwsgi_now();

	// here we spawn the workers...
	if (!uwsgi.cheap) {
		if (uwsgi.cheaper && uwsgi.cheaper_count) {
			int nproc = uwsgi.cheaper_initial;
			if (!nproc)
				nproc = uwsgi.cheaper_count;
			for (i = 1; i <= uwsgi.numproc; i++) {
				if (i <= nproc) {
					if (uwsgi_respawn_worker(i))
						break;
					uwsgi.respawn_delta = uwsgi_now();
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
				uwsgi.respawn_delta = uwsgi_now();
			}
		}
	}

	// END OF INITIALIZATION

	// !!! from now on, we could be in the master or in a worker !!!


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

	// eventually maps (or disable) sockets for the  worker
	uwsgi_map_sockets();

	// eventually set cpu affinity poilicies (OS-dependent)
	uwsgi_set_cpu_affinity();

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

	// set default wsgi_req (for loading apps);
	uwsgi.wsgi_req = &uwsgi.workers[uwsgi.mywid].cores[0].req;

	if (uwsgi.offload_threads > 0) {
		uwsgi.offload_thread = uwsgi_malloc(sizeof(struct uwsgi_thread *) * uwsgi.offload_threads);
		for(i=0;i<uwsgi.offload_threads;i++) {
			uwsgi.offload_thread[i] = uwsgi_offload_thread_start();
			if (!uwsgi.offload_thread[i]) {
				uwsgi_log("unable to start offload thread %d for worker %d !!!\n", i, uwsgi.mywid);
				uwsgi.offload_threads = i;
				break;
			}
		}
		uwsgi_log("spawned %d offload threads for uWSGI worker %d\n", uwsgi.offload_threads, uwsgi.mywid);
	}

	// must be run before running apps
	for (i = 0; i < 256; i++) {
		if (uwsgi.p[i]->post_fork) {
			uwsgi.p[i]->post_fork();
		}
	}

	if (uwsgi.lazy || uwsgi.lazy_apps) {
		uwsgi_init_all_apps();
	}

	// some apps could be mounted only on specific workers
	uwsgi_init_worker_mount_apps();


#ifdef UWSGI_ZEROMQ
	// setup zeromq context (if required) one per-worker
	if (uwsgi.zeromq) {
		uwsgi_zeromq_init_sockets();
	}
#endif

	//postpone the queue initialization as kevent
	//do not pass kfd after fork()
#ifdef UWSGI_ASYNC
	if (uwsgi.async > 1) {
		uwsgi_async_init();
	}
#endif

	// setup UNIX signals for the worker
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
	if (!uwsgi.ignore_sigpipe) {
		signal(SIGPIPE, (void *) &warn_pipe);
	}

	// worker initialization done

	// run fixup handler
	for (i = 0; i < 256; i++) {
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
		memset(&uwsgi.workers[uwsgi.mywid].cores[i].req, 0, sizeof(struct wsgi_request));
		uwsgi.workers[uwsgi.mywid].cores[i].req.async_id = i;
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
		uwsgi.workers[uwsgi.mywid].cores[0].thread_id = pthread_self();
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

	for (i = 0; i < 256; i++) {
		if (uwsgi.p[i]->hijack_worker) {
			uwsgi.p[i]->hijack_worker();
		}
	}

	for (i = 0; i < uwsgi.gp_cnt; i++) {
		if (uwsgi.gp[i]->hijack_worker) {
			uwsgi.gp[i]->hijack_worker();
		}
	}

#ifdef UWSGI_THREADING
	// create a pthread key, storing per-thread wsgi_request structure
	if (uwsgi.threads > 1) {
		if (pthread_key_create(&uwsgi.tur_key, NULL)) {
			uwsgi_error("pthread_key_create()");
			exit(1);
		}
	}
#endif


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
		if (uwsgi.async < 2) {
			simple_loop();
		}
#ifdef UWSGI_ASYNC
		else {
			async_loop();
		}
#endif
	}

	if (uwsgi.snapshot) {
		uwsgi_ignition();
	}
	// never here
	pthread_exit(NULL);
}

/*

what happens here ?

we transform the uwsgi_option structure to a struct option
for passing it to getopt_long
A short options string is built.

This function could be called multiple times, so it will free previous areas

*/

void build_options() {

	int options_count = 0;
	int pos = 0;
	int i;
	// first count the base options

	struct uwsgi_option *op = uwsgi_base_options;
	while (op->name) {
		options_count++;
		op++;
	}

	for (i = 0; i < 256; i++) {
		if (uwsgi.p[i]->options) {
			options_count += uwsgi_count_options(uwsgi.p[i]->options);
		}
	}

	for (i = 0; i < uwsgi.gp_cnt; i++) {
		if (uwsgi.gp[i]->options) {
			options_count += uwsgi_count_options(uwsgi.gp[i]->options);
		}
	}

	// add custom options
	struct uwsgi_custom_option *uco = uwsgi.custom_options;
	while (uco) {
		options_count++;
		uco = uco->next;
	}

	if (uwsgi.options)
		free(uwsgi.options);


	// rebuild uwsgi.options area
	uwsgi.options = uwsgi_calloc(sizeof(struct uwsgi_option) * (options_count + 1));

	op = uwsgi_base_options;
	while (op->name) {
		memcpy(&uwsgi.options[pos], op, sizeof(struct uwsgi_option));
		pos++;
		op++;
	}

	for (i = 0; i < 256; i++) {
		if (uwsgi.p[i]->options) {
			int c = uwsgi_count_options(uwsgi.p[i]->options);
			memcpy(&uwsgi.options[pos], uwsgi.p[i]->options, sizeof(struct uwsgi_option) * c);
			pos += c;
		}
	}

	for (i = 0; i < uwsgi.gp_cnt; i++) {
		if (uwsgi.gp[i]->options) {
			int c = uwsgi_count_options(uwsgi.gp[i]->options);
			memcpy(&uwsgi.options[pos], uwsgi.gp[i]->options, sizeof(struct uwsgi_option) * c);
			pos += c;
		}
	}
	// custom_options are not added to uwsgi.options


	pos = 0;

	if (uwsgi.long_options)
		free(uwsgi.long_options);

	uwsgi.long_options = uwsgi_calloc(sizeof(struct option) * (options_count + 1));

	if (uwsgi.short_options)
		free(uwsgi.short_options);

	uwsgi.short_options = uwsgi_calloc((options_count * 3) + 1);

	// build long_options (this time with custom_options)
	op = uwsgi.options;
	while (op->name) {
		uwsgi.long_options[pos].name = op->name;
		uwsgi.long_options[pos].has_arg = op->type;
		uwsgi.long_options[pos].flag = 0;
		// add 1000 to avoid short_options collision
		uwsgi.long_options[pos].val = 1000 + pos;
		if (op->shortcut) {
			char shortcut = (char) op->shortcut;
			// avoid duplicates in short_options
			if (!strchr(uwsgi.short_options, shortcut)) {
				strncat(uwsgi.short_options, &shortcut, 1);
				if (op->type == optional_argument) {
					strcat(uwsgi.short_options, "::");
				}
				else if (op->type == required_argument) {
					strcat(uwsgi.short_options, ":");
				}
			}
		}
		op++;
		pos++;
	}
	uco = uwsgi.custom_options;
	while (uco) {
		uwsgi.long_options[pos].name = uco->name;
		if (uco->has_args) {
			uwsgi.long_options[pos].has_arg = required_argument;
		}
		else {
			uwsgi.long_options[pos].has_arg = no_argument;
		}
		uwsgi.long_options[pos].flag = 0;
		// add 1000 to avoid short_options collision
		uwsgi.long_options[pos].val = 1000 + pos;
		pos++;
		uco = uco->next;
	}
}

void uwsgi_stdin_sendto(char *socket_name, uint8_t modifier1, uint8_t modifier2) {

	char buf[4096];
	ssize_t rlen;
	size_t delta = 4096 - 4;
	// leave space for uwsgi header
	char *ptr = buf + 4;

	rlen = read(0, ptr, delta);
	while (rlen > 0) {
#ifdef UWSGI_DEBUG
		uwsgi_log("%.*s\n", rlen, ptr);
#endif
		ptr += rlen;
		delta -= rlen;
		if (delta == 0)
			break;
		rlen = read(0, ptr, delta);
	}

	if (ptr > buf + 4) {
		send_udp_message(modifier1, modifier2, socket_name, buf, (ptr - buf) - 4);
		uwsgi_log("sent string \"%.*s\" to cluster node %s\n", (ptr - buf) - 4, buf + 4, socket_name);
	}

}

/*

this function build the help output from the uwsgi.options structure

*/
void uwsgi_help(char *opt, char *val, void *none) {

	size_t max_size = 0;

	fprintf(stdout, "Usage: %s [options...]\n", uwsgi.binary_path);

	struct uwsgi_option *op = uwsgi.options;
	while (op && op->name) {
		if (strlen(op->name) > max_size) {
			max_size = strlen(op->name);
		}
		op++;
	}

	max_size++;

	op = uwsgi.options;
	while (op && op->name) {
		if (op->shortcut) {
			fprintf(stdout, "    -%c|--%-*s %s\n", op->shortcut, (int) max_size - 3, op->name, op->help);
		}
		else {
			fprintf(stdout, "    --%-*s %s\n", (int) max_size, op->name, op->help);
		}
		op++;
	}

	exit(0);
}

/*

initialize all apps

*/
void uwsgi_init_all_apps() {

	int i, j;

	// now run the pre-app scripts
	struct uwsgi_string_list *usl = uwsgi.exec_pre_app;
	while (usl) {
		uwsgi_log("running \"%s\" (pre app)...\n", usl->value);
		int ret = uwsgi_run_command_and_wait(NULL, usl->value);
		if (ret != 0) {
			uwsgi_log("command \"%s\" exited with non-zero code: %d\n", usl->value, ret);
			exit(1);
		}
		usl = usl->next;
	}


	for (i = 0; i < 256; i++) {
		if (uwsgi.p[i]->init_apps) {
			uwsgi.p[i]->init_apps();
		}
	}

	for (i = 0; i < uwsgi.gp_cnt; i++) {
		if (uwsgi.gp[i]->init_apps) {
			uwsgi.gp[i]->init_apps();
		}
	}

	struct uwsgi_string_list *app_mps = uwsgi.mounts;
	while (app_mps) {
		char *what = strchr(app_mps->value, '=');
		if (what) {
			what[0] = 0;
			what++;
			for (j = 0; j < 256; j++) {
				if (uwsgi.p[j]->mount_app) {
					uwsgi_log("mounting %s on %s\n", what, app_mps->value);
					if (uwsgi.p[j]->mount_app(app_mps->value, what) != -1)
						break;
				}
			}
			what--;
			what[0] = '=';
		}
		else {
			uwsgi_log("invalid mountpoint: %s\n", app_mps->value);
			exit(1);
		}
		app_mps = app_mps->next;
	}

	// no app initialized and virtualhosting enabled
	if (uwsgi_apps_cnt == 0 && uwsgi.numproc > 0 && !uwsgi.command_mode) {
		if (uwsgi.need_app) {
			if (!uwsgi.lazy)
				uwsgi_log("*** no app loaded. GAME OVER ***\n");
			exit(UWSGI_FAILED_APP_CODE);
		}
		else {
			uwsgi_log("*** no app loaded. going in full dynamic mode ***\n");
		}
	}

}

void uwsgi_init_worker_mount_apps() {
/*
	int i,j;
	for (i = 0; i < uwsgi.mounts_cnt; i++) {
                char *what = strchr(uwsgi.mounts[i], '=');
                if (what) {
                        what[0] = 0;
                        what++;
                        for (j = 0; j < 256; j++) {
                                if (uwsgi.p[j]->mount_app) {
                                        if (!uwsgi_startswith(uwsgi.mounts[i], "worker://", 9)) {
                        			uwsgi_log("mounting %s on %s\n", what, uwsgi.mounts[i]+9);
                                                if (uwsgi.p[j]->mount_app(uwsgi.mounts[i] + 9, what, 1) != -1)
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
*/

}

void uwsgi_opt_true(char *opt, char *value, void *key) {

	int *ptr = (int *) key;
	*ptr = 1;
	if (value) {
		if (!strcasecmp("false", value) || !strcasecmp("off", value) || !strcasecmp("no", value) || !strcmp("0", value)) {
			*ptr = 0;
		}
	}
}

void uwsgi_opt_cluster_reload(char *opt, char *value, void *foobar) {
	send_udp_message(98, 0, value, NULL, 0);
	exit(0);
}

void uwsgi_opt_cluster_log(char *opt, char *value, void *foobar) {
	uwsgi_stdin_sendto(value, 96, 0);
	exit(0);
}

void uwsgi_opt_set_int(char *opt, char *value, void *key) {
	int *ptr = (int *) key;
	if (value) {
		*ptr = atoi((char *) value);
	}
	else {
		*ptr = 1;
	}

	if (*ptr < 0) {
		uwsgi_log("invalid value for option \"%s\": must be > 0\n", opt);
		exit(1);
	}
}

void uwsgi_opt_set_rawint(char *opt, char *value, void *key) {
	int *ptr = (int *) key;
	if (value) {
		*ptr = atoi((char *) value);
	}
	else {
		*ptr = 1;
	}
}


void uwsgi_opt_set_64bit(char *opt, char *value, void *key) {
	uint64_t *ptr = (uint64_t *) key;

	if (value) {
		*ptr = (strtoul(value, NULL, 10));
	}
	else {
		*ptr = 1;
	}
}

void uwsgi_opt_set_megabytes(char *opt, char *value, void *key) {
	uint64_t *ptr = (uint64_t *) key;
	*ptr = (strtoul(value, NULL, 10)) * 1024 * 1024;
}

void uwsgi_opt_set_dyn(char *opt, char *value, void *key) {

	long *fake_ptr = (long *) key;
	uint8_t dyn_opt_id = (long) fake_ptr;
	uwsgi.shared->options[dyn_opt_id] = atoi(value);
}

void uwsgi_opt_dyn_true(char *opt, char *value, void *key) {

	long *fake_ptr = (long *) key;
	uint8_t dyn_opt_id = (long) fake_ptr;
	uwsgi.shared->options[dyn_opt_id] = 1;
}

void uwsgi_opt_dyn_false(char *opt, char *value, void *key) {

	long *fake_ptr = (long *) key;
	uint8_t dyn_opt_id = (long) fake_ptr;
	uwsgi.shared->options[dyn_opt_id] = 0;
}

void uwsgi_opt_set_str(char *opt, char *value, void *key) {
	char **ptr = (char **) key;
	*ptr = (char *) value;
}

void uwsgi_opt_set_logger(char *opt, char *value, void *prefix) {

	if (!value)
		value = "";

	if (prefix) {
		uwsgi_string_new_list(&uwsgi.requested_logger, uwsgi_concat3((char *) prefix, ":", value));
	}
	else {
		uwsgi_string_new_list(&uwsgi.requested_logger, uwsgi_str(value));
	}
}

void uwsgi_opt_set_str_spaced(char *opt, char *value, void *key) {
	char **ptr = (char **) key;
	*ptr = uwsgi_concat2((char *) value, " ");
}

void uwsgi_opt_add_string_list(char *opt, char *value, void *list) {
	struct uwsgi_string_list **ptr = (struct uwsgi_string_list **) list;
	uwsgi_string_new_list(ptr, value);
}

#ifdef UWSGI_PCRE
void uwsgi_opt_add_regexp_list(char *opt, char *value, void *list) {
	struct uwsgi_regexp_list **ptr = (struct uwsgi_regexp_list **) list;
	uwsgi_regexp_new_list(ptr, value);
}

void uwsgi_opt_add_regexp_custom_list(char *opt, char *value, void *list) {
	char *space = strchr(value, ' ');
	if (!space) {
		uwsgi_log("invalid custom regexp syntax: must be <custom> <regexp>\n");
		exit(1);
	}
	char *custom = uwsgi_concat2n(value, space - value, "", 0);
	struct uwsgi_regexp_list **ptr = (struct uwsgi_regexp_list **) list;
	uwsgi_regexp_custom_new_list(ptr, space + 1, custom);
}
#endif

void uwsgi_opt_add_shared_socket(char *opt, char *value, void *protocol) {
	struct uwsgi_socket *us = uwsgi_new_shared_socket(generate_socket_name(value));
	if (!strcmp(opt, "undeferred-shared-socket")) {
		us->no_defer = 1;
	}
}

void uwsgi_opt_add_socket(char *opt, char *value, void *protocol) {
	struct uwsgi_socket *uwsgi_sock = uwsgi_new_socket(generate_socket_name(value));
	uwsgi_sock->name_len = strlen(uwsgi_sock->name);
	uwsgi_sock->proto_name = protocol;
}

void uwsgi_opt_add_lazy_socket(char *opt, char *value, void *protocol) {
	struct uwsgi_socket *uwsgi_sock = uwsgi_new_socket(generate_socket_name(value));
	uwsgi_sock->proto_name = protocol;
	uwsgi_sock->bound = 1;
	uwsgi_sock->lazy = 1;
}


void uwsgi_opt_set_placeholder(char *opt, char *value, void *none) {

	char *p = strchr(value, '=');
	if (!p) {
		uwsgi_log("invalid placeholder/--set value\n");
		exit(1);
	}

	p[0] = 0;
	add_exported_option(uwsgi_str(value), p + 1, 1);
	p[0] = '=';

}

void uwsgi_opt_ssa(char *opt, char *value, void *foobar) {
	uwsgi_subscription_set_algo(value);
}

#ifdef UWSGI_SSL
void uwsgi_opt_scd(char *opt, char *value, void *foobar) {
	// openssl could not be initialized
	if (!uwsgi.ssl_initialized) {
		uwsgi_ssl_init();
	}

	char *colon = strchr(value, ':');
	if (!colon) {
		uwsgi_log("invalid syntax for '%s', must be: <digest>:<directory>\n", opt);
		exit(1);
	}

	char *algo = uwsgi_concat2n(value, (colon - value), "", 0);
	uwsgi.subscriptions_sign_check_md = EVP_get_digestbyname(algo);
	if (!uwsgi.subscriptions_sign_check_md) {
		uwsgi_log("unable to find digest algorithm: %s\n", algo);
		exit(1);
	}
	free(algo);

	uwsgi.subscriptions_sign_check_dir = colon + 1;
}
#endif

void uwsgi_opt_set_umask(char *opt, char *value, void *mode) {

	mode_t umask_mode = 0;

	if (strlen(value) < 3) {
		uwsgi_log("invalid umask: %s\n", value);
	}
	umask_mode = 0;
	if (strlen(value) == 3) {
		umask_mode = (umask_mode << 3) + (value[0] - '0');
		umask_mode = (umask_mode << 3) + (value[1] - '0');
		umask_mode = (umask_mode << 3) + (value[2] - '0');
	}
	else {
		umask_mode = (umask_mode << 3) + (value[1] - '0');
		umask_mode = (umask_mode << 3) + (value[2] - '0');
		umask_mode = (umask_mode << 3) + (value[3] - '0');
	}
	umask(umask_mode);

	uwsgi.do_not_change_umask = 1;

}

void uwsgi_opt_print(char *opt, char *value, void *str) {
	if (str) {
		fprintf(stdout, "%s\n", (char *) str);
		exit(0);
	}
	fprintf(stdout, "%s\n", value);
}

void uwsgi_opt_set_uid(char *opt, char *value, void *none) {

	uwsgi.uid = atoi(value);
	if (!uwsgi.uid)
		uwsgi.uidname = value;
}

void uwsgi_opt_set_gid(char *opt, char *value, void *none) {

	uwsgi.gid = atoi(value);
	if (!uwsgi.gid)
		uwsgi.gidname = value;
}

#ifdef UWSGI_CAP
void uwsgi_opt_set_cap(char *opt, char *value, void *none) {
	uwsgi_build_cap(value);
}
#endif
#ifdef __linux__
void uwsgi_opt_set_unshare(char *opt, char *value, void *none) {
	uwsgi_build_unshare(value);
}
#endif

void uwsgi_opt_set_env(char *opt, char *value, void *none) {
	if (putenv(value)) {
		uwsgi_error("putenv()");
	}
}

void uwsgi_opt_unset_env(char *opt, char *value, void *none) {
	if (unsetenv(value)) {
		uwsgi_error("unsetenv()");
	}
}

void uwsgi_opt_pidfile_signal(char *opt, char *pidfile, void *sig) {

	long *signum_fake_ptr = (long *) sig;
	int signum = (long) signum_fake_ptr;
	signal_pidfile(signum, pidfile);
	exit(0);
}

void uwsgi_opt_load_dl(char *opt, char *value, void *none) {
	if (!dlopen(value, RTLD_NOW | RTLD_GLOBAL)) {
		uwsgi_log("%s\n", dlerror());
	}
}

void uwsgi_opt_load_plugin(char *opt, char *value, void *none) {

	char *p = strtok(uwsgi_concat2(value, ""), ",");
	while (p != NULL) {
#ifdef UWSGI_DEBUG
		uwsgi_debug("loading plugin %s\n", p);
#endif
		if (uwsgi_load_plugin(-1, p, NULL)) {
			build_options();
		}
		p = strtok(NULL, ",");
	}
}

void uwsgi_opt_check_static(char *opt, char *value, void *foobar) {

	uwsgi_dyn_dict_new(&uwsgi.check_static, value, strlen(value), NULL, 0);
	uwsgi_log("[uwsgi-static] added check for %s\n", value);
	uwsgi.build_mime_dict = 1;

}

void uwsgi_opt_add_dyn_dict(char *opt, char *value, void *dict) {

	char *equal = strchr(value, '=');
	if (!equal) {
		uwsgi_log("invalid dictionary syntax for %s\n", opt);
		exit(1);
	}

	struct uwsgi_dyn_dict **udd = (struct uwsgi_dyn_dict **) dict;

	uwsgi_dyn_dict_new(udd, value, equal - value, equal + 1, strlen(equal + 1));

}

#ifdef UWSGI_PCRE
void uwsgi_opt_add_regexp_dyn_dict(char *opt, char *value, void *dict) {

	char *space = strchr(value, ' ');
	if (!space) {
		uwsgi_log("invalid dictionary syntax for %s\n", opt);
		exit(1);
	}

	struct uwsgi_dyn_dict **udd = (struct uwsgi_dyn_dict **) dict;

	struct uwsgi_dyn_dict *new_udd = uwsgi_dyn_dict_new(udd, value, space - value, space + 1, strlen(space + 1));

	char *regexp = uwsgi_concat2n(value, space - value, "", 0);

	if (uwsgi_regexp_build(regexp, &new_udd->pattern, &new_udd->pattern_extra)) {
		exit(1);
	}

	free(regexp);
}
#endif


void uwsgi_opt_fileserve_mode(char *opt, char *value, void *foobar) {

	if (!strcasecmp("x-sendfile", value)) {
		uwsgi.file_serve_mode = 2;
	}
	else if (!strcasecmp("xsendfile", value)) {
		uwsgi.file_serve_mode = 2;
	}
	else if (!strcasecmp("x-accel-redirect", value)) {
		uwsgi.file_serve_mode = 1;
	}
	else if (!strcasecmp("xaccelredirect", value)) {
		uwsgi.file_serve_mode = 1;
	}
	else if (!strcasecmp("nginx", value)) {
		uwsgi.file_serve_mode = 1;
	}

}

void uwsgi_opt_static_map(char *opt, char *value, void *static_maps) {

	struct uwsgi_dyn_dict **maps = (struct uwsgi_dyn_dict **) static_maps;
	char *mountpoint = uwsgi_str(value);

	char *docroot = strchr(mountpoint, '=');

	if (!docroot) {
		uwsgi_log("invalid document root in static map, syntax mountpoint=docroot\n");
		exit(1);
	}
	docroot[0] = 0;
	docroot++;
	uwsgi_dyn_dict_new(maps, mountpoint, strlen(mountpoint), docroot, strlen(docroot));
	uwsgi_log("[uwsgi-static] added mapping for %s => %s\n", mountpoint, docroot);
	uwsgi.build_mime_dict = 1;
}


int uwsgi_zerg_attach(char *value) {

	int count = 8;
	int zerg_fd = uwsgi_connect(value, 30, 0);
	if (zerg_fd < 0) {
		uwsgi_log("--- unable to connect to zerg server %s ---\n", value);
		return -1;
	}

	int last_count = count;

	int *zerg = uwsgi_attach_fd(zerg_fd, &count, "uwsgi-zerg", 10);
	if (zerg == NULL) {
		if (last_count != count) {
			close(zerg_fd);
			zerg_fd = uwsgi_connect(value, 30, 0);
			if (zerg_fd < 0) {
				uwsgi_log("--- unable to connect to zerg server %s ---\n", value);
				return -1;
			}
			zerg = uwsgi_attach_fd(zerg_fd, &count, "uwsgi-zerg", 10);
		}
	}

	if (zerg == NULL) {
		uwsgi_log("--- invalid data received from zerg-server ---\n");
		return -1;
	}

	if (!uwsgi.zerg) {
		uwsgi.zerg = zerg;
	}
	else {
		int pos = 0;
		for (;;) {
			if (uwsgi.zerg[pos] == -1) {
				uwsgi.zerg = realloc(uwsgi.zerg, (sizeof(int) * (pos)) + (sizeof(int) * count + 1));
				if (!uwsgi.zerg) {
					uwsgi_error("realloc()");
					exit(1);
				}
				memcpy(&uwsgi.zerg[pos], zerg, (sizeof(int) * count + 1));
				break;
			}
			pos++;
		}
	}

	close(zerg_fd);
	return 0;
}

void uwsgi_opt_signal(char *opt, char *value, void *foobar) {
	uwsgi_command_signal(value);
}

void uwsgi_opt_log_date(char *opt, char *value, void *foobar) {

	uwsgi.logdate = 1;
	if (value) {
		if (strcasecmp("true", value) && strcasecmp("1", value) && strcasecmp("on", value) && strcasecmp("yes", value)) {
			uwsgi.log_strftime = value;
		}
	}
}

void uwsgi_opt_chmod_socket(char *opt, char *value, void *foobar) {

	int i;

	uwsgi.chmod_socket = 1;
	if (value) {
		if (strlen(value) == 1 && *value == '1') {
			return;
		}
		if (strlen(value) != 3) {
			uwsgi_log("invalid chmod value: %s\n", value);
			exit(1);
		}
		for (i = 0; i < 3; i++) {
			if (value[i] < '0' || value[i] > '7') {
				uwsgi_log("invalid chmod value: %s\n", value);
				exit(1);
			}
		}

		uwsgi.chmod_socket_value = (uwsgi.chmod_socket_value << 3) + (value[0] - '0');
		uwsgi.chmod_socket_value = (uwsgi.chmod_socket_value << 3) + (value[1] - '0');
		uwsgi.chmod_socket_value = (uwsgi.chmod_socket_value << 3) + (value[2] - '0');
	}

}

void uwsgi_opt_logfile_chmod(char *opt, char *value, void *foobar) {

	int i;

	if (strlen(value) != 3) {
		uwsgi_log("invalid chmod value: %s\n", value);
		exit(1);
	}
	for (i = 0; i < 3; i++) {
		if (value[i] < '0' || value[i] > '7') {
			uwsgi_log("invalid chmod value: %s\n", value);
			exit(1);
		}
	}

	uwsgi.chmod_logfile_value = (uwsgi.chmod_logfile_value << 3) + (value[0] - '0');
	uwsgi.chmod_logfile_value = (uwsgi.chmod_logfile_value << 3) + (value[1] - '0');
	uwsgi.chmod_logfile_value = (uwsgi.chmod_logfile_value << 3) + (value[2] - '0');

}

void uwsgi_opt_max_vars(char *opt, char *value, void *foobar) {

	uwsgi.max_vars = atoi(value);
	uwsgi.vec_size = 4 + 1 + (4 * uwsgi.max_vars);
}

void uwsgi_opt_deprecated(char *opt, char *value, void *message) {
	uwsgi_log("[WARNING] option \"%s\" is deprecated: %s\n", opt, (char *) message);
}

void uwsgi_opt_load(char *opt, char *filename, void *none) {

#ifdef UWSGI_INI
	if (uwsgi_endswith(filename, ".ini")) {
		uwsgi_opt_load_ini(opt, filename, none);
		return;
	}
#endif
#ifdef UWSGI_XML
	if (uwsgi_endswith(filename, ".xml")) {
		uwsgi_opt_load_xml(opt, filename, none);
		return;
	}
#endif
#ifdef UWSGI_YAML
	if (uwsgi_endswith(filename, ".yaml")) {
		uwsgi_opt_load_yml(opt, filename, none);
		return;
	}
	if (uwsgi_endswith(filename, ".yml")) {
		uwsgi_opt_load_yml(opt, filename, none);
		return;
	}
#endif
#ifdef UWSGI_JSON
	if (uwsgi_endswith(filename, ".json")) {
		uwsgi_opt_load_json(opt, filename, none);
		return;
	}
	if (uwsgi_endswith(filename, ".js")) {
		uwsgi_opt_load_json(opt, filename, none);
		return;
	}
#endif
}

void uwsgi_opt_logic(char *opt, char *arg, void *func) {

	if (uwsgi.logic_opt) {
		uwsgi_log("recursive logic in options is not supported (option = %s)\n", opt);
		exit(1);
	}
	uwsgi.logic_opt = (int (*)(char *, char *)) func;
	uwsgi.logic_opt_cycles = 0;
	if (arg) {
		uwsgi.logic_opt_arg = uwsgi_str(arg);
	}
	else {
		uwsgi.logic_opt_arg = NULL;
	}
}

void uwsgi_opt_noop(char *opt, char *foo, void *bar) {
}

#ifdef UWSGI_INI
void uwsgi_opt_load_ini(char *opt, char *filename, void *none) {
	config_magic_table_fill(filename, uwsgi.magic_table);
	uwsgi_ini_config(filename, uwsgi.magic_table);
}
#endif

#ifdef UWSGI_XML
void uwsgi_opt_load_xml(char *opt, char *filename, void *none) {
	config_magic_table_fill(filename, uwsgi.magic_table);
	uwsgi_xml_config(filename, uwsgi.wsgi_req, uwsgi.magic_table);
}
#endif

#ifdef UWSGI_YAML
void uwsgi_opt_load_yml(char *opt, char *filename, void *none) {
	config_magic_table_fill(filename, uwsgi.magic_table);
	uwsgi_yaml_config(filename, uwsgi.magic_table);
}
#endif

#ifdef UWSGI_SQLITE3
void uwsgi_opt_load_sqlite3(char *opt, char *filename, void *none) {
	config_magic_table_fill(filename, uwsgi.magic_table);
	uwsgi_sqlite3_config(filename, uwsgi.magic_table);
}
#endif

#ifdef UWSGI_JSON
void uwsgi_opt_load_json(char *opt, char *filename, void *none) {
	config_magic_table_fill(filename, uwsgi.magic_table);
	uwsgi_json_config(filename, uwsgi.magic_table);
}
#endif

#ifdef UWSGI_LDAP
void uwsgi_opt_load_ldap(char *opt, char *url, void *none) {
	uwsgi_ldap_config(url);
}
#endif

void uwsgi_opt_add_custom_option(char *opt, char *value, void *none) {

	struct uwsgi_custom_option *uco = uwsgi.custom_options, *old_uco;

	if (!uco) {
		uwsgi.custom_options = uwsgi_malloc(sizeof(struct uwsgi_custom_option));
		uco = uwsgi.custom_options;
	}
	else {
		while (uco) {
			old_uco = uco;
			uco = uco->next;
		}

		uco = uwsgi_malloc(sizeof(struct uwsgi_custom_option));
		old_uco->next = uco;
	}

	char *copy = uwsgi_str(value);
	char *equal = strchr(copy, '=');
	if (!equal) {
		uwsgi_log("invalid %s syntax, must be newoption=template\n");
		exit(1);
	}
	*equal = 0;

	uco->name = copy;
	uco->value = equal + 1;
	uco->has_args = 0;
	// a little hack, we allow the user to skip the first 2 arguments (yes.. it is silly...but users tend to make silly things...)
	if (strstr(uco->value, "$1") || strstr(uco->value, "$2") || strstr(uco->value, "$3")) {
		uco->has_args = 1;
	}
	uco->next = NULL;
	build_options();
}


void uwsgi_opt_flock(char *opt, char *filename, void *none) {

	int fd = open(filename, O_RDWR);
	if (fd < 0) {
		uwsgi_error_open(filename);
		exit(1);
	}

	if (uwsgi_fcntl_is_locked(fd)) {
		uwsgi_log("uWSGI ERROR: %s is locked by another instance\n", filename);
		exit(1);
	}

}

void uwsgi_opt_flock_wait(char *opt, char *filename, void *none) {

	int fd = open(filename, O_RDWR);
	if (fd < 0) {
		uwsgi_error_open(filename);
		exit(1);
	}

	if (uwsgi_fcntl_lock(fd)) {
		exit(1);
	}

}

// report CFLAGS used for compiling the server
// use that values to build external plugins
void uwsgi_opt_cflags(char *opt, char *filename, void *foobar) {
	size_t len = sizeof(UWSGI_CFLAGS);
	char *src = UWSGI_CFLAGS;
	char *ptr = uwsgi_malloc(len / 2);
	char *base = ptr;
	size_t i;
	unsigned int u;
	for (i = 0; i < len; i += 2) {
		sscanf(src + i, "%2x", &u);
		*ptr++ = (char) u;
	}
	fprintf(stdout, "%.*s\n", (int) len / 2, base);
	exit(0);
}

void uwsgi_opt_connect_and_read(char *opt, char *address, void *foobar) {

	char buf[8192];

	int fd = uwsgi_connect(address, -1, 0);
	for (;;) {
		int ret = uwsgi_waitfd(fd, -1);
		if (ret <= 0) {
			exit(0);
		}
		ssize_t len = read(fd, buf, 8192);
		if (len <= 0) {
			exit(0);
		}
		uwsgi_log("%.*s", (int) len, buf);
	}
}
