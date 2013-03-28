#include <uwsgi.h>

/*

	pluggable configuration system

*/

extern struct uwsgi_server uwsgi;

struct uwsgi_configurator *uwsgi_register_configurator(char *name, void (*func)(char *, char **)) {
	struct uwsgi_configurator *old_uc = NULL,*uc = uwsgi.configurators;
        while(uc) {
                if (!strcmp(uc->name, name)) {
                        return uc;
                }
                old_uc = uc;
                uc = uc->next;
        }

        uc = uwsgi_calloc(sizeof(struct uwsgi_configurator));
        uc->name = name;
        uc->func = func;

        if (old_uc) {
                old_uc->next = uc;
        }
        else {
                uwsgi.configurators = uc;
        }

        return uc;
}
