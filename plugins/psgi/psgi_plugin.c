#include "psgi.h"

extern char **environ;
extern struct uwsgi_server uwsgi;

struct uwsgi_perl uperl;

struct option uwsgi_perl_options[] = {

        {"psgi", required_argument, 0, LONG_ARGS_PSGI},
        {0, 0, 0, 0},

};

extern struct http_status_codes hsc[];

XS(XS_streaming_close) {

	dXSARGS;
	psgi_check_args(0);
	XSRETURN(0);
}

XS(XS_streaming_write) {

	dXSARGS;
	struct wsgi_request *wsgi_req = current_wsgi_req();
	STRLEN blen;
	char *body;

	psgi_check_args(2);

	body = SvPV(ST(1), blen);

	wsgi_req->response_size += wsgi_req->socket->proto_write(wsgi_req, body, blen);	

	XSRETURN(0);
}

XS(XS_stream)
{
    dXSARGS;
    struct wsgi_request *wsgi_req = current_wsgi_req();
    SV *stack;
    AV *response;

    psgi_check_args(1);
    stack = ST(0);

	if (items == 2) {
		response = (AV* ) SvRV(stack) ;

#ifdef my_perl
		psgi_response(wsgi_req, my_perl, response);
#else
		psgi_response(wsgi_req, uperl.main, response);
#endif
	}
 	else if (items == 1) {
		response = (AV* ) SvRV(stack) ;

#ifdef my_perl
		psgi_response(wsgi_req, my_perl, response);
#else
		psgi_response(wsgi_req, uperl.main, response);
#endif
		ST(0) = sv_bless(newRV(sv_newmortal()), uperl.streaming_stash);
		XSRETURN(1);
		
	}
	else {
    		uwsgi_log("invalid PSGI response: array size %d\n", items+1);
	}

    //mXPUSHp("x", 1);
    XSRETURN(0);

}

/* automatically generated */

EXTERN_C void xs_init (pTHX);

EXTERN_C void boot_DynaLoader (pTHX_ CV* cv);

	EXTERN_C void
xs_init(pTHX)
{
	char *file = __FILE__;
	dXSUB_SYS;

	/* DynaLoader is a special case */
	newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);

	uperl.stream_responder = newXS("uwsgi::stream", XS_stream, "uwsgi");

#ifdef UWSGI_EMBEDDED
	init_perl_embedded_module();
#endif

	newXS("uwsgi::streaming::write", XS_streaming_write, "uwsgi::streaming");
	newXS("uwsgi::streaming::close", XS_streaming_close, "uwsgi::streaming");

	uperl.streaming_stash = gv_stashpv("uwsgi::streaming", 0);
}

/* end of automagically generated part */


int uwsgi_perl_init(){


	struct http_status_codes *http_sc;

	int argc = 4;
	char *embedding[] = { "", "-e", "-e", "0" };

	if (setenv("PLACK_ENV", "uwsgi", 0)) {
		uwsgi_error("setenv()");
	}

	uwsgi_log("initializing Perl %s environment\n", PERL_VERSION_STRING);
	PERL_SYS_INIT3(&argc, (char ***) &embedding, &environ);
	uperl.main = perl_alloc();
	if (!uperl.main) {
		uwsgi_log("unable to allocate perl interpreter\n");
		return -1;
	}

	dTHXa(uperl.main);
	PERL_SET_CONTEXT(uperl.main);

	PL_perl_destruct_level = 2;
	PL_origalen = 1;
	perl_construct(uperl.main);

	// filling http status codes
	for (http_sc = hsc; http_sc->message != NULL; http_sc++) {
		http_sc->message_size = strlen(http_sc->message);
	}

	PL_origalen = 1;
	perl_parse(uperl.main, xs_init, 4, embedding, NULL);

	perl_eval_pv("use IO::Handle;", 0);
	perl_eval_pv("use IO::File;", 0);

	return 1;

}

void uwsgi_psgi_app() {

	struct stat stat_psgi;

	if (uperl.psgi) {
		
		SV *dollar_zero = get_sv("0", GV_ADD);
		sv_setpv(dollar_zero, uperl.psgi);

		uperl.fd = open(uperl.psgi, O_RDONLY);
		if (uperl.fd < 0) {
			uwsgi_error_open(uperl.psgi);
			exit(1);
		}

		if (fstat(uperl.fd, &stat_psgi)) {
			uwsgi_error("fstat()");
			exit(1);
		}

		uperl.psgibuffer = malloc(stat_psgi.st_size + 1);
		if (!uperl.psgibuffer) {
			uwsgi_error("malloc()");
			exit(1);
		}

		if (read(uperl.fd, uperl.psgibuffer, stat_psgi.st_size) != stat_psgi.st_size) {
			uwsgi_error("read()");
			exit(1);
		}

		uperl.psgibuffer[stat_psgi.st_size] = 0;

		if (uwsgi.threads < 2) {
			uperl.psgi_main = perl_eval_pv(uperl.psgibuffer, 0);
			if (!uperl.psgi_main) {
				uwsgi_log("unable to find PSGI function entry point.\n");
				exit(1);
			}

			if(SvTRUE(ERRSV)) {
				uwsgi_log("%s\n", SvPV_nolen(ERRSV));
				exit(1);
			}

			free(uperl.psgibuffer);
			close(uperl.fd);
		}

		uwsgi_log("PSGI app (%s) loaded at %p\n", uperl.psgi, uperl.psgi_main);
	}


}

#ifdef my_perl
void uwsgi_perl_enable_threads() {
	
	int i;

	if (pthread_key_create(&uperl.u_interpreter, NULL)) {
        	uwsgi_error("pthread_key_create()");
                exit(1);
	}

	uperl.interp = malloc( sizeof(PerlInterpreter*) * uwsgi.threads );
	if (!uperl.interp) {
		uwsgi_error("malloc()");
		exit(1);
	}

	for(i=1;i<uwsgi.threads;i++) {
		uperl.interp[i] = perl_clone(uperl.main, CLONEf_KEEP_PTR_TABLE);
		if (!uperl.interp[i]) {
			uwsgi_log("unable to create new perl interpreter\n");
			exit(1);
		}
	}

	uperl.psgi_func = malloc( sizeof(SV*) * uwsgi.threads );
	if (!uperl.psgi_func) {
		uwsgi_error("malloc()");
		exit(1);
	}
	

	dTHXa(uperl.main);
	PERL_SET_CONTEXT(uperl.main);

	uperl.psgi_main = perl_eval_pv(uperl.psgibuffer, 0);
	if (!uperl.psgi_main) {
		uwsgi_log("unable to find PSGI function entry point.\n");
		exit(1);
	}

	if(SvTRUE(ERRSV)) {
		uwsgi_log("%s\n", SvPV_nolen(ERRSV));
		exit(1);
	}
	

}
#endif



int uwsgi_perl_request(struct wsgi_request *wsgi_req) {

	HV *env;

	AV *response;

	SV *io_new, *io_err;
	int i;

	SV *psgi_func = uperl.psgi_main;
	// ugly hack
	register PerlInterpreter *my_perl = uperl.main;
	dSP;

#ifdef UWSGI_ASYNC
	if (wsgi_req->async_status == UWSGI_AGAIN) {
		return psgi_response(wsgi_req, my_perl, wsgi_req->async_placeholder);	
	}
#endif



	/* Standard PSGI request */
	if (!wsgi_req->uh.pktsize) {
		uwsgi_log("Invalid PSGI request. skip.\n");
		return -1;
	}


	if (uwsgi_parse_vars(wsgi_req)) {
		uwsgi_log("Invalid PSGI request. skip.\n");
		return -1;
	}


#ifdef UWSGI_THREADING
	if (uwsgi.threads > 1 && wsgi_req->async_id > 0) {
		psgi_func = uperl.psgi_func[wsgi_req->async_id];
		my_perl = pthread_getspecific(uperl.u_interpreter);
	}
#endif


	ENTER;
	SAVETMPS;


	env = (HV*) sv_2mortal((SV*)newHV());


	// fill perl hash
	for(i=0;i<wsgi_req->var_cnt;i++) {
		if (wsgi_req->hvec[i+1].iov_len > 0) {

			// check for multiline header
			if (hv_exists(env, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len)) {
				SV **already_avalable_header = hv_fetch(env, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len, 0);
				STRLEN hlen;
				char *old_value = SvPV(*already_avalable_header, hlen );
				char *multiline_header = uwsgi_concat3n(old_value, hlen, ", ", 2, wsgi_req->hvec[i+1].iov_base, wsgi_req->hvec[i+1].iov_len);
				if (!hv_store(env, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len,
					newSVpv(multiline_header, hlen+wsgi_req->hvec[i+1].iov_len+2), 0))  { free(multiline_header); goto clear;}
				free(multiline_header);
				
				
			}
			else {
				if (!hv_store(env, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len,
					newSVpv(wsgi_req->hvec[i+1].iov_base, wsgi_req->hvec[i+1].iov_len), 0)) goto clear;
			}
		}
		else {
			if (!hv_store(env, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len, newSVpv("", 0), 0)) goto clear;
		}
		//uwsgi_log("%.*s = %.*s\n", wsgi_req->hvec[i].iov_len, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i+1].iov_len, wsgi_req->hvec[i+1].iov_base);
		i++;
	}

	// psgi.version
	AV *av = newAV();
	av_store( av, 0, newSViv(1));
	av_store( av, 1, newSViv(1));
	if (!hv_store(env, "psgi.version", 12, newRV((SV *)av ), 0)) goto clear;
	
	if (uwsgi.numproc > 1) {
		if (!hv_store(env, "psgi.multiprocess", 17, newSViv(1), 0)) goto clear;
	}
	else {
		if (!hv_store(env, "psgi.multiprocess", 17, newSViv(0), 0)) goto clear;
	}

	if (uwsgi.threads > 1) {
		if (!hv_store(env, "psgi.multithread", 16, newSViv(1), 0)) goto clear;
	}
	else {
		if (!hv_store(env, "psgi.multithread", 16, newSViv(0), 0)) goto clear;
	}

	if (!hv_store(env, "psgi.run_once", 13, newSViv(0), 0)) goto clear;

#ifdef UWSGI_ASYNC
	if (uwsgi.async > 1) {
		if (!hv_store(env, "psgi.nonblocking", 16, newSViv(1), 0)) goto clear;
	}
	else {
#else
		if (!hv_store(env, "psgi.nonblocking", 16, newSViv(0), 0)) goto clear;
#endif

#ifdef UWSGI_ASYNC
	}
#endif

	if (!hv_store(env, "psgi.streaming", 14, newSViv(1), 0)) goto clear;

	SV *us;
	// psgi.url_scheme, honour HTTPS var or UWSGI_SCHEME
	if (wsgi_req->scheme_len > 0) {
		us = newSVpv(wsgi_req->scheme, wsgi_req->scheme_len);
	}
	else if (wsgi_req->https_len > 0) {
		if (!strncasecmp(wsgi_req->https, "on", 2) || wsgi_req->https[0] == '1') {
			us = newSVpv("https", 5);
		}
		else {
			us = newSVpv("http", 4);
		}
	}
	else {
		us = newSVpv("http", 4);
	}

	if (!hv_store(env, "psgi.url_scheme", 15, us, 0)) goto clear;


	SV* iohandle = newSVpv( "IO::File", 8 );


	PUSHMARK(SP);
	XPUSHs( sv_2mortal(iohandle));
	PUTBACK;
	perl_call_method( "new", G_SCALAR);
	SPAGAIN;
	io_new = POPs;

	PUSHMARK(SP);
	XPUSHs( io_new );
	XPUSHs( sv_2mortal(newSViv( wsgi_req->poll.fd)));
	XPUSHs( sv_2mortal(newSVpv( "r", 1)));
	PUTBACK;
	perl_call_method( "fdopen", G_SCALAR);
	SPAGAIN;




	SV *pi = SvREFCNT_inc(POPs);
	if (!hv_store(env, "psgi.input", 10, pi, 0)) goto clear;
	if (!hv_store(env, "psgix.io", 8, SvREFCNT_inc(pi), 0)) goto clear;

	if (!hv_store(env, "psgix.input.buffered", 20, newSViv(1), 0)) goto clear;


	PUSHMARK(SP);
	XPUSHs( newSVpv( "IO::Handle", 10 ));
	PUTBACK;
	perl_call_method( "new", G_SCALAR);
	SPAGAIN;
	io_err = POPs;

	PUSHMARK(SP);
	XPUSHs( io_err );
	XPUSHs( sv_2mortal( newSViv( 2 )));
	XPUSHs( sv_2mortal( newSVpv( "w", 1)));
	PUTBACK;
	perl_call_method( "fdopen", G_SCALAR);
	SPAGAIN;

	SV *pe = SvREFCNT_inc(POPs);
	if (!hv_store(env, "psgi.errors", 11, pe, 0)) goto clear;

	


	PUSHMARK(SP);
	XPUSHs( sv_2mortal(newRV((SV *)env )) );
	PUTBACK;


	perl_call_sv(psgi_func, G_SCALAR | G_EVAL);

	
	if(SvTRUE(ERRSV)) {
		internal_server_error(wsgi_req, "exception raised");
		uwsgi_log("%s\n", SvPV_nolen(ERRSV));
		goto clear;
	}
	SPAGAIN;
	// no leaks to here

	// dereference output
	response = (AV *) SvRV( POPs );

	//uwsgi_log("response: %p %d\n", response, SvTYPE(response));

	if (SvTYPE(response) == SVt_PVCV) {
			
		PUSHMARK(SP);
        	XPUSHs( newRV((SV*) uperl.stream_responder));
        	PUTBACK;

        	perl_call_sv( (SV*)response, G_SCALAR | G_EVAL);

		if(SvTRUE(ERRSV)) {
			internal_server_error(wsgi_req, "exception raised");
			uwsgi_log("%s\n", SvPV_nolen(ERRSV));
		}

		goto clear;
	}

	while (psgi_response(wsgi_req, my_perl, response) != UWSGI_OK) {
#ifdef UWSGI_ASYNC
		if (uwsgi.async > 1) {
			FREETMPS;
			LEAVE;
			return UWSGI_AGAIN;
		}
		else {
#endif
			wsgi_req->switches++;
#ifdef UWSGI_ASYNC
		}
#endif
	}

clear:

	FREETMPS;
	LEAVE;

	return UWSGI_OK;
}


void uwsgi_perl_after_request(struct wsgi_request *wsgi_req) {

	if (uwsgi.shared->options[UWSGI_OPTION_LOGGING])
		log_request(wsgi_req);
}

void uwsgi_perl_init_thread(int core_id) {


	pthread_setspecific(uperl.u_interpreter, uperl.interp[core_id]);
	dTHXa(uperl.interp[core_id]);
	PERL_SET_CONTEXT(uperl.interp[core_id]);

	uperl.psgi_func[core_id] = perl_eval_pv(uperl.psgibuffer, 0);
        if (!uperl.psgi_func[core_id]) {
        	uwsgi_log("unable to find PSGI function entry point.\n");
		exit(1);
        }

        if(SvTRUE(ERRSV)) {
        	uwsgi_log("%s\n", SvPV_nolen(ERRSV));
		exit(1);
        }


}

int uwsgi_perl_manage_options(int i, char *optarg) {

        switch(i) {
                case LONG_ARGS_PSGI:
                        uperl.psgi = optarg;
                        return 1;
        }

        return 0;
}

int uwsgi_perl_magic(char *mountpoint, char *lazy) {

        if (!strcmp(lazy+strlen(lazy)-5, ".psgi")) {
                uperl.psgi = lazy;
                return 1;
        }
        else if (!strcmp(lazy+strlen(lazy)-3, ".pl")) {
                uperl.psgi = lazy;
                return 1;
        }

        return 0;

}


struct uwsgi_plugin psgi_plugin = {

	.name = "psgi",
	.modifier1 = 5,
	.init = uwsgi_perl_init,
	.options = uwsgi_perl_options,
	.init_apps = uwsgi_psgi_app,
	//.magic = uwsgi_perl_magic,
	//.help = uwsgi_perl_help,
#ifdef my_perl
	.enable_threads = uwsgi_perl_enable_threads,
#endif
	.manage_opt = uwsgi_perl_manage_options,
	.init_thread = uwsgi_perl_init_thread,
	.request = uwsgi_perl_request,
	.after_request = uwsgi_perl_after_request,

	.magic = uwsgi_perl_magic,
};
