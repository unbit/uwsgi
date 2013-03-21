#include <uwsgi.h>

/*

a fake plugin used for preloading mongodb library when only available as static.

*/

int uwsgi_mongodb_version(void);

struct uwsgi_plugin mongodb_plugin = {
	.name = "mongodb",
	.init = uwsgi_mongodb_version,
};
