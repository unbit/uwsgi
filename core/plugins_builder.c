#include <uwsgi.h>

#define UWSGI_BUILD_DIR ".uwsgi_plugins_builder"

/*

	steps:

		mkdir(.uwsgi_plugin_builder)
		generate .uwsgi_plugin_builder/uwsgi.h
		setenv(CFLAGS=uwsgi_cflags)
		pipe uwsgiconfig.py to python passing args

*/

int uwsgi_build_plugin(char *directory) {
	uwsgi_log("building uWSGI plugin %s...\n", directory);

	if (!uwsgi_file_exists(UWSGI_BUILD_DIR)) {
		if (mkdir(UWSGI_BUILD_DIR, S_IRWXU) < 0) {
        		uwsgi_error("uwsgi_build_plugin()/mkdir() " UWSGI_BUILD_DIR "/");
			return 1;
		}
	}

	char *dot_h = uwsgi_get_dot_h();
	if (!dot_h) {
		uwsgi_log("unable to generate uwsgi.h");
		return 1;
	}

	if (strlen(dot_h) == 0) {
		free(dot_h);
		uwsgi_log("invalid uwsgi.h");
		return 1;
	}

	int dot_h_fd = open(UWSGI_BUILD_DIR "/uwsgi.h", O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
	if (dot_h_fd < 0) {
		uwsgi_error_open(UWSGI_BUILD_DIR "/uwsgi.h");
		free(dot_h);
		return 1;
	}

	ssize_t dot_h_len = (ssize_t) strlen(dot_h);
	if (write(dot_h_fd, dot_h, dot_h_len) != dot_h_len) {
		uwsgi_error("uwsgi_build_plugin()/write()");
		close(dot_h_fd);
		free(dot_h);
		return 1;
	}
	
	free(dot_h);
	close(dot_h_fd);

	// now extract the python build script from the process
	// and pipe it to python

	char *argv[4];

	argv[0] = getenv("PYTHON");
	if (!argv[0]) argv[0] = "python";

	argv[1] = "-";
	argv[2] = "--extra-plugin";
	argv[3] = directory;

	execvp(argv[0], argv);
	// never here...	
	return 1;
}
