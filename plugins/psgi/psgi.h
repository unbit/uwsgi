#undef __USE_GNU
#include "../../uwsgi.h"

#ifdef __APPLE__
#define HAS_BOOL 1
#endif
#include <EXTERN.h>
#include <perl.h>
#include "XSUB.h"


struct uwsgi_perl {

        int fd;
        char *psgibuffer;
        char *psgi;
	char *locallib;
	char *embedding[3];
        PerlInterpreter *main;
        pthread_key_t u_interpreter;
        PerlInterpreter **interp;
        SV *psgi_main;
        SV **psgi_func;
        CV *stream_responder;
	HV *streaming_stash;
	HV *input_stash;
	HV *error_stash;

};

#define LONG_ARGS_PERL_BASE      	17000 + ((5 + 1) * 1000)
#define LONG_ARGS_PSGI           	LONG_ARGS_PERL_BASE + 1
#define LONG_ARGS_PERL_LOCAL_LIB	LONG_ARGS_PERL_BASE + 2

void init_perl_embedded_module(void);
void uwsgi_psgi_app(void);
int psgi_response(struct wsgi_request *, AV*);

#define psgi_xs(func) newXS("uwsgi::" #func, XS_##func, "uwsgi")
#define psgi_check_args(x) if (items < x) Perl_croak(aTHX_ "Usage: uwsgi::%s takes %d arguments", __FUNCTION__ + 3, x)

SV *uwsgi_perl_obj_call(SV *, char *);
int uwsgi_perl_obj_can(SV *, char *, size_t);
