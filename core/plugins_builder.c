#include <uwsgi.h>

/*

	steps:

		mkdir(.uwsgi_plugin_builder)
		generate .uwsgi_plugin_builder/uwsgi.h
		setenv(CFLAGS=uwsgi_cflags)
		pipe uwsgiconfig.py to python passing args

*/

int uwsgi_build_plugin(char *directory) {
	return 0;
}
