#include "uwsgi.h"
#include <glob.h>


extern struct uwsgi_server uwsgi;
extern char **environ;

struct uwsgi_instance {
	struct uwsgi_instance *ui_prev;
	struct uwsgi_instance *ui_next;

	char name[0xff];
	pid_t pid;

	int status;
	time_t born;
	time_t last_mod;

	uint64_t respawns;
	int use_config;

	int pipe[2];
	int pipe_config[2];

	char *config;
	uint32_t config_len;
};

struct uwsgi_instance *ui;

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

	uwsgi_log("removed uwsgi instance %s\n", c_ui->name);

	free(c_ui);

}

void emperor_stop(struct uwsgi_instance *c_ui) {
	// remove uWSGI instance

	if (write(c_ui->pipe[0], "\0", 1) != 1) {
		uwsgi_error("write()");
	}

	c_ui->status = 1;

	uwsgi_log("stop the uwsgi instance %s\n", c_ui->name);
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

	uwsgi_log("reload the uwsgi instance %s\n", c_ui->name);
}

void emperor_add(char *name, time_t born, char *config, uint32_t config_size) {

	struct uwsgi_instance *c_ui = ui;
	struct uwsgi_instance *n_ui = NULL;
	pid_t pid;
	char *argv[4];
	char *uef;
	char **uenvs;

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
	uwsgi_log("c_ui->ui_next = %p\n", c_ui->ui_next);
	n_ui->ui_prev = c_ui;
	memcpy(n_ui->name, name, strlen(name));
	n_ui->born = born;
	n_ui->last_mod = born;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, n_ui->pipe)) {
		uwsgi_error("socketpair()");
		goto clear;
	}

	if (n_ui->use_config) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, n_ui->pipe_config)) {
			uwsgi_error("socketpair()");
			goto clear;
		}
	}

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

		unsetenv("UWSGI_RELOADS");

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
				uwsgi_log("putenv %s\n", ne);

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


		// set args
		argv[0] = uwsgi.binary_path;
		if (!strcmp(name + (strlen(name) - 4), ".xml"))
			argv[1] = "--xml";
		if (!strcmp(name + (strlen(name) - 4), ".ini"))
			argv[1] = "--ini";
		if (!strcmp(name + (strlen(name) - 4), ".yml"))
			argv[1] = "--yaml";
		if (!strcmp(name + (strlen(name) - 5), ".yaml"))
			argv[1] = "--yaml";
		argv[2] = name;
		argv[3] = NULL;
		// start !!!
		if (execvp(argv[0], argv)) {
			uwsgi_error("execvp()");
		}
		// never here
		exit(1);
	}

      clear:

	free(n_ui);
	c_ui->ui_next = NULL;

}

void emperor_loop() {

	// monitor a directory

	struct uwsgi_instance ui_base;
	struct uwsgi_instance *ui_current;
	struct stat st;

	pid_t diedpid;
	int waitpid_status;
	int has_children = 0;
	int i_am_alone = 0;
	int simple_mode = 0;
	glob_t g;
	int i;
	struct dirent *de;
	char *amqp_port;
	int amqp_fd = -1;
	char *amqp_routing_key;

	signal(SIGPIPE, SIG_IGN);

	memset(&ui_base, 0, sizeof(struct uwsgi_instance));

	uwsgi_log("*** starting uWSGI Emperor ***\n");

	amqp_port = strchr(uwsgi.emperor_dir, ':');

	if (amqp_port) {
reconnect:
		while(amqp_fd == -1) {	
			uwsgi_log("connecting to AMQP server...\n");
			amqp_fd = uwsgi_connect(uwsgi.emperor_dir, -1, 0);
			if (amqp_fd < 0) {
				sleep(1);
			}
		}

		uwsgi_log("subscribing to queue...\n");
		if (uwsgi_amqp_consume_queue(amqp_fd, "/", "", "uwsgi.emperor", "fanout") < 0) {
			close(amqp_fd);
			amqp_fd = -1;
			goto reconnect;
		}
	}
	else {
		if (!glob(uwsgi.emperor_dir, GLOB_MARK, NULL, &g)) {
			if (g.gl_pathc == 1 && g.gl_pathv[0][strlen(g.gl_pathv[0]) - 1] == '/') {
				simple_mode = 1;
				if (chdir(uwsgi.emperor_dir)) {
					uwsgi_error("chdir()");
					exit(1);
				}
			}
		}
		else {
			uwsgi_error("glob()");
			exit(1);
		}
	}

	ui = &ui_base;

	for (;;) {


		if (!i_am_alone) {
			diedpid = waitpid(uwsgi.emperor_pid, &waitpid_status, WNOHANG);
			if (diedpid < 0 || diedpid > 0) {
				i_am_alone = 1;
			}
		}

		if (amqp_fd > -1) {
			uint64_t msgsize;
			if (uwsgi_waitfd(amqp_fd, 3)) {
				char *config = uwsgi_amqp_consume(amqp_fd, &msgsize, &amqp_routing_key);
				
				if (!config) {
					uwsgi_log("problem with RabbitMQ server, trying reconnection...\n");
					close(amqp_fd);
					amqp_fd = -1;
					goto reconnect;
				}

				if (amqp_routing_key) {
					uwsgi_log("AMQP routing_key = %s\n", amqp_routing_key);
					char *config_file = uwsgi_concat2("emperor://", amqp_routing_key);
					free(amqp_routing_key);

					ui_current = emperor_get(config_file);

                                        if (ui_current) {
						free(ui_current->config);
						ui_current->config = config;
						ui_current->config_len = msgsize;
						if (!msgsize) {
							emperor_del(ui_current);
						}
						else {
                                                	emperor_respawn(ui_current, time(NULL));
						}
                                        }
                                        else {
						if (msgsize > 0) {
                                                	emperor_add(config_file, time(NULL), config, msgsize);
						}
                                        }

					
                                        free(config_file);
				}
				else {
				if (msgsize) {
					if (msgsize >= 0xff) { free(config); continue; }

					uwsgi_log("%.*s\n", (int)msgsize, config);
					char *config_file = uwsgi_concat2n(config, msgsize, "", 0);
					free(config);

					if (strncmp(config_file, "http://", 7)) {
						if (stat(config_file, &st)) {
							free(config_file);
							continue;
						}

						if (!S_ISREG(st.st_mode)) {
							free(config_file);
							continue;
						}
					}

					ui_current = emperor_get(config_file);

					if (ui_current) {
						emperor_respawn(ui_current, time(NULL));
					}
					else {
						emperor_add(config_file, time(NULL), NULL, 0);
					}

					free(config_file);
				}
				}
			}
		}
		else if (simple_mode) {
			DIR *dir = opendir(".");
			while ((de = readdir(dir)) != NULL) {
				if (!strcmp(de->d_name + (strlen(de->d_name) - 4), ".xml") || !strcmp(de->d_name + (strlen(de->d_name) - 4), ".ini") || !strcmp(de->d_name + (strlen(de->d_name) - 4), ".yml") || !strcmp(de->d_name + (strlen(de->d_name) - 5), ".yaml")
					) {


					if (strlen(de->d_name) >= 0xff)
						continue;

					if (stat(de->d_name, &st))
						continue;

					if (!S_ISREG(st.st_mode))
						continue;

					ui_current = emperor_get(de->d_name);

					if (ui_current) {
						// check if mtime is changed and the uWSGI instance must be reloaded
						if (st.st_mtime > ui_current->last_mod) {
							emperor_respawn(ui_current, st.st_mtime);
						}
					}
					else {
						emperor_add(de->d_name, st.st_mtime, NULL, 0);
					}
				}
			}
			closedir(dir);
		}
		else {
			if (glob(uwsgi.emperor_dir, GLOB_MARK, NULL, &g)) {
				uwsgi_error("glob()");
				continue;
			}

			for (i = 0; i < (int) g.gl_pathc; i++) {
				if (!strcmp(g.gl_pathv[i] + (strlen(g.gl_pathv[i]) - 4), ".xml") ||
					!strcmp(g.gl_pathv[i] + (strlen(g.gl_pathv[i]) - 4), ".ini") ||
					!strcmp(g.gl_pathv[i] + (strlen(g.gl_pathv[i]) - 4), ".yml") ||
					!strcmp(g.gl_pathv[i] + (strlen(g.gl_pathv[i]) - 5), ".yaml")
					) {


					if (strlen(g.gl_pathv[i]) >= 0xff)
						continue;

					if (stat(g.gl_pathv[i], &st))
						continue;

					if (!S_ISREG(st.st_mode))
						continue;

					ui_current = emperor_get(g.gl_pathv[i]);

					if (ui_current) {
						// check if mtime is changed and the uWSGI instance must be reloaded
						if (st.st_mtime > ui_current->last_mod) {
							emperor_respawn(ui_current, st.st_mtime);
						}
					}
					else {
						emperor_add(g.gl_pathv[i], st.st_mtime, NULL, 0);
					}
				}

			}
		}

		// check for removed instances

		ui_current = ui;
		has_children = 0;
		while (ui_current->ui_next) {
			ui_current = ui_current->ui_next;
			has_children++;
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
			uwsgi_error("waitpid()");
		}
		ui_current = ui;
		while (ui_current->ui_next) {
			ui_current = ui_current->ui_next;
			if (ui_current->status == 1) {
				if (ui_current->config) free(ui_current->config);
				emperor_del(ui_current);
				break;
			}
			else if (!ui_current->use_config && strncmp(ui_current->name, "http://",7) && stat(ui_current->name, &st)) {
				emperor_stop(ui_current);
			}
			else if (ui_current->pid == diedpid) {
				if (ui_current->status == 0) {
					// respawn an accidentally dead instance if its exit code is not UWSGI_EXILE_CODE
					if (WIFEXITED(waitpid_status) && WEXITSTATUS(waitpid_status) == UWSGI_EXILE_CODE) {
						emperor_del(ui_current);
					}
					else {
						emperor_add(ui_current->name, ui_current->last_mod, ui_current->config, ui_current->config_len);
						emperor_del(ui_current);
					}
					break;
				}
				else if (ui_current->status == 1) {
					// remove 'marked for dead' instance
					if (ui_current->config) free(ui_current->config);
					emperor_del(ui_current);
					break;
				}
			}
		}

		if (amqp_fd < 0)
		sleep(3);

	}

}
