#include "../../uwsgi.h"

#include <EXTERN.h>
#include "XSUB.h"
#include <perl.h>


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

#define LONG_ARGS_PERL_BASE      17000 + (5 * 100)
#define LONG_ARGS_PSGI           LONG_ARGS_PERL_BASE + 1

int psgi_response(struct wsgi_request *, PerlInterpreter *, AV*);
