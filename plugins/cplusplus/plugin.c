#include <uwsgi.h>


int uwsgi_cplusplus_init(void);
int uwsgi_cplusplus_request(struct wsgi_request *);
void uwsgi_cplusplus_after_request(struct wsgi_request *);

struct uwsgi_plugin cplusplus_plugin = {

        .name = "cplusplus",
        .modifier1 = 250,
        .init = uwsgi_cplusplus_init,
        .request = uwsgi_cplusplus_request,
        .after_request = uwsgi_cplusplus_after_request,

};

