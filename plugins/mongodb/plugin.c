#include <uwsgi.h>

/*

a fake plugin used for preloading mongodb library when only available as static.

*/

struct uwsgi_plugin mongodb_plugin = {
	.name = "mongodb",
};
