#include "uwsgi.h"
#include <glob.h>


extern struct uwsgi_server uwsgi;
extern char **environ;

struct uwsgi_instance {
	struct uwsgi_instance *ui_prev;
	struct uwsgi_instance *ui_next;

	char name[0xff];
	pid_t pid ;

	int status;
	time_t born;
	time_t last_mod;

	uint64_t respawns;

	int pipe[2];
};

struct uwsgi_instance *ui;

struct uwsgi_instance *emperor_get(char *name) {
	
	struct uwsgi_instance *c_ui = ui;
	
	while(c_ui->ui_next) {
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
	if (write(c_ui->pipe[0], "\1", 1) != 1) {
                uwsgi_error("write()");
        }

        c_ui->respawns++;
	c_ui->last_mod = mod;

        uwsgi_log("reload the uwsgi instance %s\n", c_ui->name);
}

void emperor_add(char *name, time_t born) {

	struct uwsgi_instance *c_ui = ui;
	struct uwsgi_instance *n_ui = NULL;
	pid_t pid ;
	char *argv[4];
	char *uef ;
	char **uenvs;

        while(c_ui->ui_next) {
                c_ui = c_ui->ui_next;
        }

	n_ui = uwsgi_malloc(sizeof(struct uwsgi_instance));
	memset(n_ui, 0, sizeof(struct uwsgi_instance));

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

	// a new uWSGI instance will start 
	pid = fork();
	if (pid < 0) {
		uwsgi_error("fork()")
	}
	else if (pid > 0) {
		n_ui->pid = pid;
		// close the right side of the pipe
		close(n_ui->pipe[1]);
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

		uenvs = environ;
		while(*uenvs) {
			if (!strncmp(*uenvs, "UWSGI_VASSAL_", 13)) {
				char *ne = uwsgi_concat2("UWSGI_", *uenvs+13);
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


		// set args
		argv[0] = uwsgi.binary_path;
		if (!strcmp(name+(strlen(name)-4), ".xml")) argv[1] = "--xml";
		if (!strcmp(name+(strlen(name)-4), ".ini")) argv[1] = "--ini";
		if (!strcmp(name+(strlen(name)-4), ".yml")) argv[1] = "--yaml";
		if (!strcmp(name+(strlen(name)-5), ".yaml")) argv[1] = "--yaml";
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

	memset(&ui_base, 0, sizeof(struct uwsgi_instance));

	uwsgi_log("*** starting uWSGI Emperor ***\n");

	if (!glob(uwsgi.emperor_dir, GLOB_MARK, NULL, &g)) {
		if (g.gl_pathc == 1 && g.gl_pathv[0][strlen(g.gl_pathv[0])-1] == '/' ) {
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

	ui = &ui_base;

	for(;;) {


		if (!i_am_alone) {
			diedpid = waitpid(uwsgi.emperor_pid, &waitpid_status, WNOHANG);
			if (diedpid < 0) {
				uwsgi_error("waitpid()");
			}
			else if (diedpid > 0) {
				i_am_alone = 1;
			}
		}

		if (simple_mode) {
			DIR *dir = opendir(".");
			while((de = readdir(dir)) != NULL) {
				if (!strcmp(de->d_name+(strlen(de->d_name)-4), ".xml") ||
					!strcmp(de->d_name+(strlen(de->d_name)-4), ".ini") ||
					!strcmp(de->d_name+(strlen(de->d_name)-4), ".yml") ||
					!strcmp(de->d_name+(strlen(de->d_name)-5), ".yaml")
					) {

				
					if (strlen(de->d_name) >= 0xff) continue;

					if (stat(de->d_name, &st)) continue;

					if (!S_ISREG(st.st_mode)) continue;
		
					ui_current = emperor_get(de->d_name);

					if (ui_current) {
						// check if mtime is changed and the uWSGI instance must be reloaded
						if (st.st_mtime > ui_current->last_mod) {
							emperor_respawn(ui_current, st.st_mtime);
						}
					}
					else {
						emperor_add(de->d_name, st.st_mtime);
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

			for(i=0;i<(int)g.gl_pathc;i++) {
				if (!strcmp(g.gl_pathv[i]+(strlen(g.gl_pathv[i])-4), ".xml") ||
                                        !strcmp(g.gl_pathv[i]+(strlen(g.gl_pathv[i])-4), ".ini") ||
                                        !strcmp(g.gl_pathv[i]+(strlen(g.gl_pathv[i])-4), ".yml") ||
                                        !strcmp(g.gl_pathv[i]+(strlen(g.gl_pathv[i])-5), ".yaml")
                                        ) {


                                        if (strlen(g.gl_pathv[i]) >= 0xff) continue;

                                        if (stat(g.gl_pathv[i], &st)) continue;

                                        if (!S_ISREG(st.st_mode)) continue;

                                        ui_current = emperor_get(g.gl_pathv[i]);

                                        if (ui_current) {
                                                // check if mtime is changed and the uWSGI instance must be reloaded
                                                if (st.st_mtime > ui_current->last_mod) {
                                                        emperor_respawn(ui_current, st.st_mtime);
                                                }
                                        }
                                        else {
                                                emperor_add(g.gl_pathv[i], st.st_mtime);
                                        }
                                }
	
			}
		}

		// check for removed instances

		ui_current = ui;
		has_children = 0;
                while(ui_current->ui_next) {
                	ui_current = ui_current->ui_next;
			has_children++;
		}

		if (has_children) {
			diedpid = waitpid(WAIT_ANY, &waitpid_status, WNOHANG);
		}
		else {
			diedpid = 0;
		}
		if (diedpid < 0) {
			uwsgi_error("waitpid()");
		}
		ui_current = ui;
        	while(ui_current->ui_next) {
                	ui_current = ui_current->ui_next;
			if (ui_current->pid == diedpid) {
				if (ui_current->status == 0) {
					// respawn an accidentally dead instance
					emperor_add(ui_current->name, ui_current->last_mod);
					emperor_del(ui_current);
					break;
				}
				else if (ui_current->status == 1) {
					// remove 'marked for dead' instance
					emperor_del(ui_current);
					break;
				}
			}
			else if (ui_current->status == 1) {
				emperor_del(ui_current);
				break;
			}
			else if (stat(ui_current->name, &st)) {
				emperor_stop(ui_current);
			}
        	}

		sleep(3);
		
	}
	
}




