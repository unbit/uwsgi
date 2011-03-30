#undef __USE_GNU
#include "../../uwsgi.h"

#define HAS_BOOL 1
#include <EXTERN.h>
#include <perl.h>
#include "XSUB.h"


struct uwsgi_perl {

        int fd;
        char *psgibuffer;
        char *psgi;
        PerlInterpreter *main;
        pthread_key_t u_interpreter;
        PerlInterpreter **interp;
        SV *psgi_main;
        SV **psgi_func;
        CV *stream_responder;

};

#define LONG_ARGS_PERL_BASE      17000 + ((5 + 1) * 100)
#define LONG_ARGS_PSGI           LONG_ARGS_PERL_BASE + 1

void init_perl_embedded_module(void);
int psgi_response(struct wsgi_request *, PerlInterpreter *, AV*);
