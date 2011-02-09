#include <ei.h>

#define LONG_ARGS_ERLANG                17012
#define LONG_ARGS_ERLANG_COOKIE         17013


struct uwsgi_erlang {

        ei_cnode cnode;
        char *name;
        char *cookie;

        int fd;

	void *lock;
};


