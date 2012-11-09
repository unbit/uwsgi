/*

The uWSGI Emperor

a supervisor for multiple uWSGI instances

*/
#include "uwsgi.h"
#include <glob.h>


extern struct uwsgi_server uwsgi;
extern char **environ;

void emperor_send_stats(int);

time_t emperor_throttle;
int emperor_throttle_level;

struct uwsgi_instance *ui;

/*

	blacklist subsystem

	failed unloyal vassals are blacklisted and throttled

*/
struct uwsgi_emperor_blacklist_item {
	char id[0xff];
	struct timeval first_attempt;
	struct timeval last_attempt;
	int throttle_level;
	int attempt;
	struct uwsgi_emperor_blacklist_item *prev;
	struct uwsgi_emperor_blacklist_item *next;
};

struct uwsgi_emperor_blacklist_item *emperor_blacklist;

struct uwsgi_emperor_blacklist_item *uwsgi_emperor_blacklist_check(char *id) {
	struct uwsgi_emperor_blacklist_item *uebi = emperor_blacklist;
	while (uebi) {
		if (!strcmp(uebi->id, id)) {
			return uebi;
		}
		uebi = uebi->next;
	}
	return NULL;
}


void uwsgi_emperor_blacklist_add(char *id) {

	// check if the item is already in the blacklist        
	struct uwsgi_emperor_blacklist_item *uebi = uwsgi_emperor_blacklist_check(id);
	if (uebi) {
		gettimeofday(&uebi->last_attempt, NULL);
		if (uebi->throttle_level < (uwsgi.emperor_max_throttle * 1000)) {
			uebi->throttle_level += (uwsgi.emperor_throttle * 1000);
		}
		else {
			uwsgi_log("[emperor] maximum throttle level for vassal %s reached !!!\n", id);
			uebi->throttle_level = uebi->throttle_level / 2;
		}
		uebi->attempt++;
		if (uebi->attempt == 2) {
			uwsgi_log("[emperor] unloyal bad behaving vassal found: %s throttling it...\n", id);
		}
		return;
	}

	uebi = emperor_blacklist;
	if (!uebi) {
		uebi = uwsgi_calloc(sizeof(struct uwsgi_emperor_blacklist_item));
		uebi->prev = NULL;
		emperor_blacklist = uebi;
	}
	else {
		while (uebi) {
			if (!uebi->next) {
				uebi->next = uwsgi_calloc(sizeof(struct uwsgi_emperor_blacklist_item));
				uebi->next->prev = uebi;
				uebi = uebi->next;
				break;
			}
			uebi = uebi->next;
		}
	}

	strcpy(uebi->id, id);
	gettimeofday(&uebi->first_attempt, NULL);
	memcpy(&uebi->last_attempt, &uebi->first_attempt, sizeof(struct timeval));
	uebi->throttle_level = uwsgi.emperor_throttle;
	uebi->next = NULL;

}

void uwsgi_emperor_blacklist_remove(char *id) {

	struct uwsgi_emperor_blacklist_item *uebi = uwsgi_emperor_blacklist_check(id);
	if (!uebi)
		return;

	// ok let's remove the item
	//is it the first item ?
	if (uebi == emperor_blacklist) {
		emperor_blacklist = uebi->next;
	}

	struct uwsgi_emperor_blacklist_item *next = uebi->next;
	struct uwsgi_emperor_blacklist_item *prev = uebi->prev;

	if (next)
		next->prev = prev;

	if (prev)
		prev->next = next;

	free(uebi);
}


struct uwsgi_emperor_scanner *emperor_scanners;

int uwsgi_emperor_is_valid(char *name) {

	if (uwsgi_endswith(name, ".xml") || uwsgi_endswith(name, ".ini") || uwsgi_endswith(name, ".yml") || uwsgi_endswith(name, ".yaml") || uwsgi_endswith(name, ".js") || uwsgi_endswith(name, ".json")) {


		if (strlen(name) < 0xff) {
			return 1;
		}
	}

	return 0;
}

// this is the monitor for non-glob directories
void uwsgi_imperial_monitor_directory(struct uwsgi_emperor_scanner *ues) {
	struct uwsgi_instance *ui_current;
	struct dirent *de;
	struct stat st;

	if (chdir(ues->arg)) {
		uwsgi_error("chdir()");
		return;
	}

	DIR *dir = opendir(".");
	while ((de = readdir(dir)) != NULL) {

		if (!uwsgi_emperor_is_valid(de->d_name))
			continue;

		if (stat(de->d_name, &st))
			continue;

		if (!S_ISREG(st.st_mode))
			continue;

		ui_current = emperor_get(de->d_name);

		if (ui_current) {
			// check if uid or gid are changed, in such case, stop the instance
			if (uwsgi.emperor_tyrant) {
				if (st.st_uid != ui_current->uid || st.st_gid != ui_current->gid) {
					uwsgi_log("!!! permissions of file %s changed. stopping the instance... !!!\n", de->d_name);
					emperor_stop(ui_current);
					continue;
				}
			}
			// check if mtime is changed and the uWSGI instance must be reloaded
			if (st.st_mtime > ui_current->last_mod) {
				emperor_respawn(ui_current, st.st_mtime);
			}
		}
		else {
			emperor_add(ues, de->d_name, st.st_mtime, NULL, 0, st.st_uid, st.st_gid);
		}
	}
	closedir(dir);

	// now check for removed instances
	struct uwsgi_instance *c_ui = ui->ui_next;

	while (c_ui) {
		if (c_ui->scanner == ues) {
			if (stat(c_ui->name, &st)) {
				emperor_stop(c_ui);
			}
		}
		c_ui = c_ui->ui_next;
	}
}

// this is the monitor for glob patterns
void uwsgi_imperial_monitor_glob(struct uwsgi_emperor_scanner *ues) {

	glob_t g;
	int i;
	struct stat st;
	struct uwsgi_instance *ui_current;

	if (glob(ues->arg, GLOB_MARK | GLOB_NOCHECK, NULL, &g)) {
		uwsgi_error("glob()");
		return;
	}

	for (i = 0; i < (int) g.gl_pathc; i++) {

		if (!uwsgi_emperor_is_valid(g.gl_pathv[i]))
			continue;

		if (stat(g.gl_pathv[i], &st))
			continue;

		if (!S_ISREG(st.st_mode))
			continue;

		ui_current = emperor_get(g.gl_pathv[i]);

		if (ui_current) {
			// check if uid or gid are changed, in such case, stop the instance
			if (uwsgi.emperor_tyrant) {
				if (st.st_uid != ui_current->uid || st.st_gid != ui_current->gid) {
					uwsgi_log("!!! permissions of file %s changed. stopping the instance... !!!\n", g.gl_pathv[i]);
					emperor_stop(ui_current);
					continue;
				}
			}
			// check if mtime is changed and the uWSGI instance must be reloaded
			if (st.st_mtime > ui_current->last_mod) {
				emperor_respawn(ui_current, st.st_mtime);
			}
		}
		else {
			emperor_add(ues, g.gl_pathv[i], st.st_mtime, NULL, 0, st.st_uid, st.st_gid);
		}

	}
	globfree(&g);

	// now check for removed instances
	struct uwsgi_instance *c_ui = ui->ui_next;

	while (c_ui) {
		if (c_ui->scanner == ues) {
			if (stat(c_ui->name, &st)) {
				emperor_stop(c_ui);
			}
		}
		c_ui = c_ui->ui_next;
	}


}

void uwsgi_register_imperial_monitor(char *name, void (*init) (struct uwsgi_emperor_scanner *), void (*func) (struct uwsgi_emperor_scanner *)) {

	struct uwsgi_imperial_monitor *uim = uwsgi.emperor_monitors;
	if (!uim) {
		uim = uwsgi_calloc(sizeof(struct uwsgi_imperial_monitor));
		uwsgi.emperor_monitors = uim;
	}
	else {
		while (uim) {
			if (!uim->next) {
				uim->next = uwsgi_calloc(sizeof(struct uwsgi_imperial_monitor));
				uim = uim->next;
				break;
			}
			uim = uim->next;
		}
	}

	uim->scheme = name;
	uim->init = init;
	uim->func = func;
	uim->next = NULL;
}


// the sad death of an Emperor
static void royal_death(int signum) {


	struct uwsgi_instance *c_ui = ui->ui_next;

	if (uwsgi.vassals_stop_hook) {


		while (c_ui) {
			uwsgi_log("[emperor] running vassal stop-hook: %s %s\n", uwsgi.vassals_stop_hook, c_ui->name);
			if (uwsgi.emperor_absolute_dir) {
				if (setenv("UWSGI_VASSALS_DIR", uwsgi.emperor_absolute_dir, 1)) {
					uwsgi_error("setenv()");
				}
			}
			int stop_hook_ret = uwsgi_run_command_and_wait(uwsgi.vassals_stop_hook, c_ui->name);
			uwsgi_log("[emperor] %s stop-hook returned %d\n", c_ui->name, stop_hook_ret);
			c_ui = c_ui->ui_next;
		}
	}

	uwsgi_log("[emperor] *** RAGNAROK EVOKED ***\n");
	uwsgi_notify("The Emperor is buried.");
	exit(0);
}

// massive reload of vassals
static void emperor_massive_reload(int signum) {
	struct uwsgi_instance *c_ui = ui->ui_next;

	while (c_ui) {
		emperor_respawn(c_ui, uwsgi_now());
		c_ui = c_ui->ui_next;
	}
}


static void emperor_stats() {

	struct uwsgi_instance *c_ui = ui->ui_next;

	while (c_ui) {

		uwsgi_log("vassal instance %s (last modified %d) status %d loyal %d zerg %d\n", c_ui->name, c_ui->last_mod, c_ui->status, c_ui->loyal, c_ui->zerg);

		c_ui = c_ui->ui_next;
	}

}

struct uwsgi_instance *emperor_get_by_fd(int fd) {

	struct uwsgi_instance *c_ui = ui;

	while (c_ui->ui_next) {
		c_ui = c_ui->ui_next;

		if (c_ui->pipe[0] == fd) {
			return c_ui;
		}
	}
	return NULL;
}


struct uwsgi_instance *emperor_get(char *name) {

	struct uwsgi_instance *c_ui = ui;

	while (c_ui->ui_next) {
		c_ui = c_ui->ui_next;

		if (!strcmp(c_ui->name, name)) {
			return c_ui;
		}
	}
	return NULL;
}

void emperor_del(struct uwsgi_instance *c_ui) {

	struct uwsgi_instance *parent_ui = c_ui->ui_prev;
	struct uwsgi_instance *child_ui = c_ui->ui_next;

	parent_ui->ui_next = child_ui;
	if (child_ui) {
		child_ui->ui_prev = parent_ui;
	}

	// this will destroy the whole uWSGI instance (and workers)
	close(c_ui->pipe[0]);

	if (c_ui->use_config) {
		close(c_ui->pipe_config[0]);
	}

	if (uwsgi.vassals_stop_hook) {
		uwsgi_log("[emperor] running vassal stop-hook: %s %s\n", uwsgi.vassals_stop_hook, c_ui->name);
		if (uwsgi.emperor_absolute_dir) {
			if (setenv("UWSGI_VASSALS_DIR", uwsgi.emperor_absolute_dir, 1)) {
				uwsgi_error("setenv()");
			}
		}
		int stop_hook_ret = uwsgi_run_command_and_wait(uwsgi.vassals_stop_hook, c_ui->name);
		uwsgi_log("[emperor] %s stop-hook returned %d\n", c_ui->name, stop_hook_ret);
	}

	uwsgi_log("[emperor] removed uwsgi instance %s\n", c_ui->name);
	// put the instance in the blacklist (or update its throttling value)
	if (!c_ui->loyal) {
		uwsgi_emperor_blacklist_add(c_ui->name);
	}

	if (c_ui->zerg) {
		uwsgi.emperor_broodlord_count--;
	}

	free(c_ui);

}

void emperor_stop(struct uwsgi_instance *c_ui) {
	// remove uWSGI instance

	if (write(c_ui->pipe[0], "\0", 1) != 1) {
		uwsgi_error("write()");
	}

	c_ui->status = 1;

	uwsgi_log("[emperor] stop the uwsgi instance %s\n", c_ui->name);
}

void emperor_respawn(struct uwsgi_instance *c_ui, time_t mod) {

	// reload the uWSGI instance
	if (c_ui->use_config) {
		if (write(c_ui->pipe[0], "\0", 1) != 1) {
			uwsgi_error("write()");
		}
	}
	else {
		if (write(c_ui->pipe[0], "\1", 1) != 1) {
			uwsgi_error("write()");
		}
	}

	c_ui->respawns++;
	c_ui->last_mod = mod;
	c_ui->last_run = uwsgi_now();

	uwsgi_log("[emperor] reload the uwsgi instance %s\n", c_ui->name);
}

void emperor_add(struct uwsgi_emperor_scanner *ues, char *name, time_t born, char *config, uint32_t config_size, uid_t uid, gid_t gid) {

	struct uwsgi_instance *c_ui = ui;
	struct uwsgi_instance *n_ui = NULL;
	pid_t pid;
	char **vassal_argv;
	char *uef;
	char **uenvs;
	int counter;
	char *colon = NULL;
	int i;
	struct timeval tv;

#ifdef UWSGI_DEBUG
	uwsgi_log("\n\nVASSAL %s %d %.*s %d %d\n", name, born, config_size, config, uid, gid);
#endif

	if (strlen(name) > (0xff - 1)) {
		uwsgi_log("[emperor] invalid vassal name\n", name);
		return;
	}


	gettimeofday(&tv, NULL);
	int now = tv.tv_sec;
	uint64_t micros = (tv.tv_sec * 1000 * 1000) + tv.tv_usec;

	// blacklist check
	struct uwsgi_emperor_blacklist_item *uebi = uwsgi_emperor_blacklist_check(name);
	if (uebi) {
		uint64_t i_micros = (uebi->last_attempt.tv_sec * 1000 * 1000) + uebi->last_attempt.tv_usec + uebi->throttle_level;
		if (i_micros > micros) {
			return;
		}
	}

	if (now - emperor_throttle < 1) {
		emperor_throttle_level = emperor_throttle_level * 2;
	}
	else {
		if (emperor_throttle_level > uwsgi.emperor_throttle) {
			emperor_throttle_level = emperor_throttle_level / 2;
		}

		if (emperor_throttle_level < uwsgi.emperor_throttle) {
			emperor_throttle_level = uwsgi.emperor_throttle;
		}
	}

	emperor_throttle = now;
#ifdef UWSGI_DEBUG
	uwsgi_log("emperor throttle = %d\n", emperor_throttle_level);
#endif
	usleep(emperor_throttle_level);

	if (uwsgi.emperor_tyrant) {
		if (uid == 0 || gid == 0) {
			uwsgi_log("[emperor-tyrant] invalid permissions for vassal %s\n", name);
			return;
		}
	}

	while (c_ui->ui_next) {
		c_ui = c_ui->ui_next;
	}

	n_ui = uwsgi_malloc(sizeof(struct uwsgi_instance));
	memset(n_ui, 0, sizeof(struct uwsgi_instance));

	if (config) {
		n_ui->use_config = 1;
		n_ui->config = config;
		n_ui->config_len = config_size;
	}

	c_ui->ui_next = n_ui;
#ifdef UWSGI_DEBUG
	uwsgi_log("c_ui->ui_next = %p\n", c_ui->ui_next);
#endif
	n_ui->ui_prev = c_ui;

	if (strchr(name, ':')) {
		n_ui->zerg = 1;
		uwsgi.emperor_broodlord_count++;
	}

	n_ui->scanner = ues;
	memcpy(n_ui->name, name, strlen(name));
	n_ui->born = born;
	n_ui->uid = uid;
	n_ui->gid = gid;
	n_ui->last_mod = born;
	// start without loyalty
	n_ui->last_loyal = 0;
	n_ui->loyal = 0;

	n_ui->first_run = uwsgi_now();
	n_ui->last_run = n_ui->first_run;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, n_ui->pipe)) {
		uwsgi_error("socketpair()");
		goto clear;
	}

	event_queue_add_fd_read(uwsgi.emperor_queue, n_ui->pipe[0]);

	if (n_ui->use_config) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, n_ui->pipe_config)) {
			uwsgi_error("socketpair()");
			goto clear;
		}
	}

	// TODO pre-start hook

	// a new uWSGI instance will start 
	pid = fork();
	if (pid < 0) {
		uwsgi_error("fork()")
	}
	else if (pid > 0) {
		n_ui->pid = pid;
		// close the right side of the pipe
		close(n_ui->pipe[1]);
		if (n_ui->use_config) {
			close(n_ui->pipe_config[1]);
		}

		if (n_ui->use_config) {
			if (write(n_ui->pipe_config[0], n_ui->config, n_ui->config_len) <= 0) {
				uwsgi_error("write()");
			}
			close(n_ui->pipe_config[0]);
		}
		return;
	}
	else {

		if (uwsgi.emperor_tyrant) {
			uwsgi_log("[emperor-tyrant] dropping privileges to %d %d for instance %s\n", (int) uid, (int) gid, name);
			if (setgid(gid)) {
				uwsgi_error("setgid()");
				exit(1);
			}
			if (setgroups(0, NULL)) {
				uwsgi_error("setgroups()");
				exit(1);
			}

			if (setuid(uid)) {
				uwsgi_error("setuid()");
				exit(1);
			}

		}

		unsetenv("UWSGI_RELOADS");
		unsetenv("NOTIFY_SOCKET");

		uef = uwsgi_num2str(n_ui->pipe[1]);
		if (setenv("UWSGI_EMPEROR_FD", uef, 1)) {
			uwsgi_error("setenv()");
			exit(1);
		}
		free(uef);

		if (n_ui->use_config) {
			uef = uwsgi_num2str(n_ui->pipe_config[1]);
			if (setenv("UWSGI_EMPEROR_FD_CONFIG", uef, 1)) {
				uwsgi_error("setenv()");
				exit(1);
			}
			free(uef);
		}

		uenvs = environ;
		while (*uenvs) {
			if (!strncmp(*uenvs, "UWSGI_VASSAL_", 13)) {
				char *ne = uwsgi_concat2("UWSGI_", *uenvs + 13);
				char *oe = uwsgi_concat2n(*uenvs, strchr(*uenvs, '=') - *uenvs, "", 0);
				if (unsetenv(oe)) {
					uwsgi_error("unsetenv()");
					break;
				}
				free(oe);
#ifdef UWSGI_DEBUG
				uwsgi_log("putenv %s\n", ne);
#endif

				if (putenv(ne)) {
					uwsgi_error("putenv()");
				}
				// do not free ne as putenv will add it to the environ
				uenvs = environ;
				continue;
			}
			uenvs++;
		}

		// close the left side of the pipe
		close(n_ui->pipe[0]);

		if (n_ui->use_config) {
			close(n_ui->pipe_config[0]);
		}

		counter = 4;
		struct uwsgi_string_list *uct = uwsgi.vassals_templates;
		while (uct) {
			counter += 2;
			uct = uct->next;
		}

		vassal_argv = uwsgi_malloc(sizeof(char *) * counter);
		// set args
		vassal_argv[0] = uwsgi.binary_path;

		if (uwsgi.emperor_broodlord) {
			colon = strchr(name, ':');
			if (colon) {
				colon[0] = 0;
			}
		}
		// initialize to a default value
		vassal_argv[1] = "--inherit";

		if (!strcmp(name + (strlen(name) - 4), ".xml"))
			vassal_argv[1] = "--xml";
		if (!strcmp(name + (strlen(name) - 4), ".ini"))
			vassal_argv[1] = "--ini";
		if (!strcmp(name + (strlen(name) - 4), ".yml"))
			vassal_argv[1] = "--yaml";
		if (!strcmp(name + (strlen(name) - 5), ".yaml"))
			vassal_argv[1] = "--yaml";
		if (!strcmp(name + (strlen(name) - 3), ".js"))
			vassal_argv[1] = "--json";
		if (!strcmp(name + (strlen(name) - 5), ".json"))
			vassal_argv[1] = "--json";

		if (colon) {
			colon[0] = ':';
		}


		vassal_argv[2] = name;
		if (uwsgi.emperor_magic_exec) {
			if (!access(name, R_OK | X_OK)) {
				vassal_argv[2] = uwsgi_concat2("exec://", name);
			}

		}

		if (n_ui->use_config) {
			vassal_argv[2] = uwsgi_concat2("emperor://", name);
		}

		counter = 3;
		uct = uwsgi.vassals_templates;
		while (uct) {
			vassal_argv[counter] = "--inherit";
			vassal_argv[counter + 1] = uct->value;
			counter += 2;
			uct = uct->next;
		}
		vassal_argv[counter] = NULL;

		// disable stdin
		int stdin_fd = open("/dev/null", O_RDONLY);
		if (stdin_fd < 0) {
			uwsgi_error_open("/dev/null");
			exit(1);
		}
		if (stdin_fd != 0) {
			if (dup2(stdin_fd, 0)) {
				uwsgi_error("dup2()");
				exit(1);
			}
			close(stdin_fd);
		}

		// close all of the unneded fd
		for (i = 3; i < (int) uwsgi.max_fd; i++) {
			if (n_ui->use_config) {
				if (i == n_ui->pipe_config[1])
					continue;
			}
			if (i != n_ui->pipe[1]) {
				close(i);
			}
		}

		if (uwsgi.vassals_start_hook) {
			uwsgi_log("[emperor] running vassal start-hook: %s %s\n", uwsgi.vassals_start_hook, n_ui->name);
			if (uwsgi.emperor_absolute_dir) {
				if (setenv("UWSGI_VASSALS_DIR", uwsgi.emperor_absolute_dir, 1)) {
					uwsgi_error("setenv()");
				}
			}
			int start_hook_ret = uwsgi_run_command_and_wait(uwsgi.vassals_start_hook, n_ui->name);
			uwsgi_log("[emperor] %s start-hook returned %d\n", n_ui->name, start_hook_ret);
		}

		// start !!!
		if (execvp(vassal_argv[0], vassal_argv)) {
			uwsgi_error("execvp()");
		}
		uwsgi_log("[emperor] is the uwsgi binary in your system PATH ?\n");
		// never here
		exit(UWSGI_EXILE_CODE);
	}

clear:

	free(n_ui);
	c_ui->ui_next = NULL;

}

void uwsgi_imperial_monitor_glob_init(struct uwsgi_emperor_scanner *ues) {
	if (chdir(uwsgi.cwd)) {
		uwsgi_error("chdir()");
		exit(1);
	}

	uwsgi.emperor_absolute_dir = uwsgi.cwd;

	if (!uwsgi_startswith(ues->arg, "glob://", 7)) {
		ues->arg += 7;
	}
}

void uwsgi_imperial_monitor_directory_init(struct uwsgi_emperor_scanner *ues) {

	if (!uwsgi_startswith(ues->arg, "dir://", 6)) {
		ues->arg += 6;
	}

	if (chdir(ues->arg)) {
		uwsgi_error("chdir()");
		exit(1);
	}

	uwsgi.emperor_absolute_dir = uwsgi_malloc(PATH_MAX + 1);
	if (realpath(".", uwsgi.emperor_absolute_dir) == NULL) {
		uwsgi_error("realpath()");
		exit(1);
	}

}

struct uwsgi_imperial_monitor *imperial_monitor_get_by_id(char *scheme) {
	struct uwsgi_imperial_monitor *uim = uwsgi.emperor_monitors;
	while (uim) {
		if (!strcmp(uim->scheme, scheme)) {
			return uim;
		}
		uim = uim->next;
	}
	return NULL;
}

struct uwsgi_imperial_monitor *imperial_monitor_get_by_scheme(char *arg) {
	struct uwsgi_imperial_monitor *uim = uwsgi.emperor_monitors;
	while (uim) {
		char *scheme = uwsgi_concat2(uim->scheme, "://");
		if (!uwsgi_starts_with(arg, strlen(arg), scheme, strlen(scheme))) {
			free(scheme);
			return uim;
		}
		free(scheme);
		uim = uim->next;
	}
	return NULL;
}

void emperor_add_scanner(struct uwsgi_imperial_monitor *monitor, char *arg) {
	struct uwsgi_emperor_scanner *ues = emperor_scanners;
	if (!ues) {
		ues = uwsgi_calloc(sizeof(struct uwsgi_emperor_scanner));
		emperor_scanners = ues;
	}
	else {
		while (ues) {
			if (!ues->next) {
				ues->next = uwsgi_calloc(sizeof(struct uwsgi_emperor_scanner));
				ues = ues->next;
				break;
			}
			ues = ues->next;
		}
	}

	ues->arg = arg;
	ues->monitor = monitor;
	ues->next = NULL;
	ues->fd = -1;
	// run the init hook
	ues->monitor->init(ues);
}

void uwsgi_emperor_run_scanners(void) {
	struct uwsgi_emperor_scanner *ues = emperor_scanners;
	while (ues) {
		ues->monitor->func(ues);
		ues = ues->next;
	}
}

void emperor_build_scanners() {
	struct uwsgi_string_list *usl = uwsgi.emperor;
	glob_t g;
	while (usl) {
		struct uwsgi_imperial_monitor *uim = imperial_monitor_get_by_scheme(usl->value);
		if (uim) {
			emperor_add_scanner(uim, usl->value);
		}
		else {
			// check for "glob" and fallback to "dir"
			if (!glob(usl->value, GLOB_MARK | GLOB_NOCHECK, NULL, &g)) {
				if (g.gl_pathc == 1 && g.gl_pathv[0][strlen(g.gl_pathv[0]) - 1] == '/') {
					globfree(&g);
					goto dir;
				}
				globfree(&g);
				uim = imperial_monitor_get_by_id("glob");
				emperor_add_scanner(uim, usl->value);
				goto next;
			}
dir:
			uim = imperial_monitor_get_by_id("dir");
			emperor_add_scanner(uim, usl->value);
		}
next:
		usl = usl->next;
	}
}

int uwsgi_emperor_scanner_event(int fd) {

	struct uwsgi_emperor_scanner *ues = emperor_scanners;
	while (ues) {
		if (ues->fd > -1 && ues->fd == fd) {
			ues->event_func(ues);
			return 1;
		}
		ues = ues->next;
	}

	return 0;

}

void emperor_loop() {

	// monitor a directory

	struct uwsgi_instance ui_base;
	struct uwsgi_instance *ui_current;

	pid_t diedpid;
	int waitpid_status;
	int has_children = 0;
	int i_am_alone = 0;
	int i;

	void *events;
	int nevents;
	int interesting_fd;
	char notification_message[64];
	struct rlimit rl;

	uwsgi.emperor_stats_fd = -1;

	if (uwsgi.emperor_pidfile) {
		uwsgi_write_pidfile(uwsgi.emperor_pidfile);
	}

	signal(SIGPIPE, SIG_IGN);
	uwsgi_unix_signal(SIGINT, royal_death);
	uwsgi_unix_signal(SIGTERM, royal_death);
	uwsgi_unix_signal(SIGQUIT, royal_death);
	uwsgi_unix_signal(SIGUSR1, emperor_stats);
	uwsgi_unix_signal(SIGHUP, emperor_massive_reload);

	memset(&ui_base, 0, sizeof(struct uwsgi_instance));

	if (getrlimit(RLIMIT_NOFILE, &rl)) {
		uwsgi_error("getrlimit()");
		exit(1);
	}

	uwsgi.max_fd = rl.rlim_cur;

	emperor_throttle_level = uwsgi.emperor_throttle;

	// the queue must be initialized before adding scanners
	uwsgi.emperor_queue = event_queue_init();

	emperor_build_scanners();

	events = event_queue_alloc(64);

	if (uwsgi.has_emperor) {
		uwsgi_log("*** starting uWSGI sub-Emperor ***\n");
	}
	else {
		uwsgi_log("*** starting uWSGI Emperor ***\n");
	}

	if (uwsgi.emperor_stats) {
		char *tcp_port = strchr(uwsgi.emperor_stats, ':');
		if (tcp_port) {
			// disable deferred accept for this socket
			int current_defer_accept = uwsgi.no_defer_accept;
			uwsgi.no_defer_accept = 1;
			uwsgi.emperor_stats_fd = bind_to_tcp(uwsgi.emperor_stats, uwsgi.listen_queue, tcp_port);
			uwsgi.no_defer_accept = current_defer_accept;
		}
		else {
			uwsgi.emperor_stats_fd = bind_to_unix(uwsgi.emperor_stats, uwsgi.listen_queue, uwsgi.chmod_socket, uwsgi.abstract_socket);
		}

		event_queue_add_fd_read(uwsgi.emperor_queue, uwsgi.emperor_stats_fd);
		uwsgi_log("*** Emperor stats server enabled on %s fd: %d ***\n", uwsgi.emperor_stats, uwsgi.emperor_stats_fd);
	}

	ui = &ui_base;

	int freq = 0;

	for (;;) {


		if (!i_am_alone) {
			diedpid = waitpid(uwsgi.emperor_pid, &waitpid_status, WNOHANG);
			if (diedpid < 0 || diedpid > 0) {
				i_am_alone = 1;
			}
		}

		nevents = event_queue_wait_multi(uwsgi.emperor_queue, freq, events, 64);
		freq = uwsgi.emperor_freq;

		for (i = 0; i < nevents; i++) {
			interesting_fd = event_queue_interesting_fd(events, i);

			if (uwsgi.emperor_stats && uwsgi.emperor_stats_fd > -1 && interesting_fd == uwsgi.emperor_stats_fd) {
				emperor_send_stats(uwsgi.emperor_stats_fd);
				continue;
			}

			// check if a monitor is mapped to that file descriptor
			if (uwsgi_emperor_scanner_event(interesting_fd))
				continue;


			ui_current = emperor_get_by_fd(interesting_fd);
			if (ui_current) {
				char byte;
				ssize_t rlen = read(interesting_fd, &byte, 1);
				if (rlen <= 0) {
					// SAFE
					if (!ui_current->config_len) {
						emperor_del(ui_current);
					}
				}
				else {
					if (byte == 17) {
						ui_current->loyal = 1;
						ui_current->last_loyal = uwsgi_now();
						uwsgi_log("[emperor] vassal %s is now loyal\n", ui_current->name);
						// remove it from the blacklist
						uwsgi_emperor_blacklist_remove(ui_current->name);
						// TODO post-start hook
					}
					// heartbeat can be used for spotting blocked instances
					else if (byte == 26) {
						ui_current->last_heartbeat = uwsgi_now();
					}
					else if (byte == 22) {
						emperor_stop(ui_current);
					}
					else if (byte == 30 && uwsgi.emperor_broodlord > 0 && uwsgi.emperor_broodlord_count < uwsgi.emperor_broodlord) {
						uwsgi_log("[emperor] going in broodlord mode: launching zergs for %s\n", ui_current->name);
						char *zerg_name = uwsgi_concat3(ui_current->name, ":", "zerg");
						emperor_add(NULL, zerg_name, uwsgi_now(), NULL, 0, ui_current->uid, ui_current->gid);
						free(zerg_name);
					}
				}
			}
			else {
				uwsgi_log("[emperor] unrecognized vassal event on fd %d\n", interesting_fd);
				close(interesting_fd);
			}

		}

		uwsgi_emperor_run_scanners();

		// check for heartbeat (if required)
		ui_current = ui->ui_next;
		while (ui_current) {
			if (ui_current->last_heartbeat > 0) {
				if ((ui_current->last_heartbeat + uwsgi.emperor_heartbeat) < uwsgi_now()) {
					uwsgi_log("[emperor] vassal %s sent no heartbeat in last %d seconds, respawning it...\n", ui_current->name, uwsgi.emperor_heartbeat);
					// set last_heartbeat to 0 avoiding races
					ui_current->last_heartbeat = 0;
					emperor_respawn(ui_current, uwsgi_now());
				}
			}
			ui_current = ui_current->ui_next;
		}

		// check for removed instances
		ui_current = ui;
		has_children = 0;
		while (ui_current->ui_next) {
			ui_current = ui_current->ui_next;
			has_children++;
		}

		if (uwsgi.notify) {
			if (snprintf(notification_message, 64, "The Emperor is governing %d vassals", has_children) >= 34) {
				uwsgi_notify(notification_message);
			}
		}

		if (has_children) {
			diedpid = waitpid(WAIT_ANY, &waitpid_status, WNOHANG);
		}
		else {
			// vacuum
			waitpid(WAIT_ANY, &waitpid_status, WNOHANG);
			diedpid = 0;
		}
		if (diedpid < 0) {
			// it looks like it happens when OOM is triggered to Linux cgroup, but it could be a uWSGI bug :P
			// by the way, fallback to a clean situation...
			if (errno == ECHILD) {
				uwsgi_log("--- MUTINY DETECTED !!! IMPALING VASSALS... ---\n");
				ui_current = ui->ui_next;
				while (ui_current) {
					struct uwsgi_instance *rebel_vassal = ui_current;
					ui_current = ui_current->ui_next;
					emperor_del(rebel_vassal);
				}
			}
			else {
				uwsgi_error("waitpid()");
			}
		}
		ui_current = ui;
		while (ui_current->ui_next) {
			ui_current = ui_current->ui_next;
			if (ui_current->status == 1) {
				if (ui_current->config)
					free(ui_current->config);
				// SAFE
				emperor_del(ui_current);
				break;
			}
			else if (ui_current->pid == diedpid) {
				if (ui_current->status == 0) {
					// respawn an accidentally dead instance if its exit code is not UWSGI_EXILE_CODE
					if (WIFEXITED(waitpid_status) && WEXITSTATUS(waitpid_status) == UWSGI_EXILE_CODE) {
						// SAFE
						emperor_del(ui_current);
					}
					else {
						// UNSAFE
						emperor_add(ui_current->scanner, ui_current->name, ui_current->last_mod, ui_current->config, ui_current->config_len, ui_current->uid, ui_current->gid);
						emperor_del(ui_current);
					}
					break;
				}
				else if (ui_current->status == 1) {
					// remove 'marked for dead' instance
					if (ui_current->config)
						free(ui_current->config);
					// SAFE
					emperor_del(ui_current);
					break;
				}
			}
		}


	}

}

void emperor_send_stats(int fd) {

	struct sockaddr_un client_src;
	socklen_t client_src_len = 0;

	int client_fd = accept(fd, (struct sockaddr *) &client_src, &client_src_len);
	if (client_fd < 0) {
		uwsgi_error("accept()");
		return;
	}

	if (uwsgi.stats_http) {
		if (uwsgi_send_http_stats(client_fd)) {
			close(client_fd);
			return;
		}
	}

	struct uwsgi_stats *us = uwsgi_stats_new(8192);

	if (uwsgi_stats_keyval_comma(us, "version", UWSGI_VERSION))
		goto end;
	if (uwsgi_stats_keylong_comma(us, "pid", (unsigned long long) getpid()))
		goto end;
	if (uwsgi_stats_keylong_comma(us, "uid", (unsigned long long) getuid()))
		goto end;
	if (uwsgi_stats_keylong_comma(us, "gid", (unsigned long long) getgid()))
		goto end;

	char *cwd = uwsgi_get_cwd();
	if (uwsgi_stats_keyval_comma(us, "cwd", cwd))
		goto end0;

	if (uwsgi_stats_key(us, "emperor"))
		goto end0;
	if (uwsgi_stats_list_open(us))
		goto end0;
	struct uwsgi_emperor_scanner *ues = emperor_scanners;
	while (ues) {
		uwsgi_stats_str(us, ues->arg);
		ues = ues->next;
		if (ues) {
			if (uwsgi_stats_comma(us))
				goto end0;
		}
	}
	if (uwsgi_stats_list_close(us))
		goto end0;

	if (uwsgi_stats_comma(us))
		goto end0;

	if (uwsgi_stats_keylong_comma(us, "emperor_tyrant", (unsigned long long) uwsgi.emperor_tyrant))
		goto end0;

	if (uwsgi_stats_keylong_comma(us, "throttle_level", (unsigned long long) emperor_throttle_level / 1000))
		goto end0;


	if (uwsgi_stats_key(us, "vassals"))
		goto end0;
	if (uwsgi_stats_list_open(us))
		goto end0;

	struct uwsgi_instance *c_ui = ui->ui_next;

	while (c_ui) {
		if (uwsgi_stats_object_open(us))
			goto end0;

		if (uwsgi_stats_keyval_comma(us, "id", c_ui->name))
			goto end0;

		if (uwsgi_stats_keylong_comma(us, "pid", (unsigned long long) c_ui->pid))
			goto end0;
		if (uwsgi_stats_keylong_comma(us, "born", (unsigned long long) c_ui->born))
			goto end0;
		if (uwsgi_stats_keylong_comma(us, "last_mod", (unsigned long long) c_ui->last_mod))
			goto end0;
		if (uwsgi_stats_keylong_comma(us, "last_heartbeat", (unsigned long long) c_ui->last_heartbeat))
			goto end0;
		if (uwsgi_stats_keylong_comma(us, "loyal", (unsigned long long) c_ui->loyal))
			goto end0;
		if (uwsgi_stats_keylong_comma(us, "last_loyal", (unsigned long long) c_ui->last_loyal))
			goto end0;
		if (uwsgi_stats_keylong_comma(us, "first_run", (unsigned long long) c_ui->first_run))
			goto end0;
		if (uwsgi_stats_keylong_comma(us, "last_run", (unsigned long long) c_ui->last_run))
			goto end0;
		if (uwsgi_stats_keylong_comma(us, "zerg", (unsigned long long) c_ui->zerg))
			goto end0;

		if (uwsgi_stats_keylong_comma(us, "uid", (unsigned long long) c_ui->uid))
			goto end0;
		if (uwsgi_stats_keylong_comma(us, "gid", (unsigned long long) c_ui->gid))
			goto end0;

		if (uwsgi_stats_keyval_comma(us, "monitor", c_ui->scanner->arg))
			goto end0;

		if (uwsgi_stats_keylong(us, "respawns", (unsigned long long) c_ui->respawns))
			goto end0;

		if (uwsgi_stats_object_close(us))
			goto end0;

		c_ui = c_ui->ui_next;

		if (c_ui) {
			if (uwsgi_stats_comma(us))
				goto end0;
		}
	}


	if (uwsgi_stats_list_close(us))
		goto end0;

	if (uwsgi_stats_comma(us))
		goto end0;

	if (uwsgi_stats_key(us, "blacklist"))
		goto end0;
	if (uwsgi_stats_list_open(us))
		goto end0;

	struct uwsgi_emperor_blacklist_item *uebi = emperor_blacklist;
	while (uebi) {

		if (uwsgi_stats_object_open(us))
			goto end0;

		if (uwsgi_stats_keyval_comma(us, "id", uebi->id))
			goto end0;


		if (uwsgi_stats_keylong_comma(us, "throttle_level", uebi->throttle_level / 1000))
			goto end0;

		if (uwsgi_stats_keylong_comma(us, "attempt", (unsigned long long) uebi->attempt))
			goto end0;

		if (uwsgi_stats_keylong_comma(us, "first_attempt", (unsigned long long) uebi->first_attempt.tv_sec))
			goto end0;

		if (uwsgi_stats_keylong(us, "last_attempt", (unsigned long long) uebi->last_attempt.tv_sec))
			goto end0;

		if (uwsgi_stats_object_close(us))
			goto end0;


		uebi = uebi->next;
		if (uebi) {
			if (uwsgi_stats_comma(us))
				goto end0;
		}
	}


	if (uwsgi_stats_list_close(us))
		goto end0;

	if (uwsgi_stats_object_close(us))
		goto end0;

	size_t remains = us->pos;
	off_t pos = 0;
	while (remains > 0) {
		int ret = uwsgi_waitfd_write(client_fd, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
		if (ret <= 0) {
			goto end0;
		}
		ssize_t res = write(client_fd, us->base + pos, remains);
		if (res <= 0) {
			if (res < 0) {
				uwsgi_error("write()");
			}
			goto end0;
		}
		pos += res;
		remains -= res;
	}

end0:
	free(cwd);
end:
	free(us->base);
	free(us);
	close(client_fd);
}

void uwsgi_emperor_start() {

	if (!uwsgi.sockets && !ushared->gateways_cnt && !uwsgi.master_process) {
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

void uwsgi_check_emperor() {
	char *emperor_env = getenv("UWSGI_EMPEROR_FD");
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

}

void uwsgi_emperor_simple_do(struct uwsgi_emperor_scanner *ues, char *name, char *config, time_t ts, uid_t uid, gid_t gid) {

	if (!uwsgi_emperor_is_valid(name))
		return;

	struct uwsgi_instance *ui_current = emperor_get(name);

	if (ui_current) {
		// check if uid or gid are changed, in such case, stop the instance
		if (uwsgi.emperor_tyrant) {
			if (uid != ui_current->uid || gid != ui_current->gid) {
				uwsgi_log("[emperor-tyrant] !!! permissions of vassal %s changed. stopping the instance... !!!\n", name);
				emperor_stop(ui_current);
				return;
			}
		}
		// check if mtime is changed and the uWSGI instance must be reloaded
		if (ts > ui_current->last_mod) {
			// make a new config (free the old one)
			free(ui_current->config);
			ui_current->config = config;
			ui_current->config_len = strlen(config);
			// always respawn (no need for amqp-style rules)
			emperor_respawn(ui_current, ts);
		}
	}
	else {
		// make a copy of the config as it will be freed
		emperor_add(ues, name, ts, uwsgi_str(config), strlen((const char *) config), uid, gid);
	}
}
