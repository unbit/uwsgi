#include <ei.h>

struct uwsgi_erlang_process {
	
	char name[0xff];
	void (*plugin)(void *, ei_x_buff *);
	void *func;

	struct uwsgi_erlang_process *next;
};

struct uwsgi_erlang {

        ei_cnode cnode;
        char *name;
        char *cookie;

        int fd;

	void *lock;

	struct uwsgi_erlang_process *uep;
};

