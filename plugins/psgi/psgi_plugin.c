#include "psgi.h"

extern char **environ;
extern struct uwsgi_server uwsgi;

#ifdef __APPLE__
extern struct uwsgi_perl uperl;
#else
struct uwsgi_perl uperl;
#endif

struct option uwsgi_perl_options[] = {

        {"psgi", required_argument, 0, LONG_ARGS_PSGI},
        {"perl-local-lib", required_argument, 0, LONG_ARGS_PERL_LOCAL_LIB},
        {0, 0, 0, 0},

};

extern struct http_status_codes hsc[];

SV *uwsgi_perl_obj_new(char *class, size_t class_len) {

	SV *newobj;
	// set current context ?
	dTHX;
	dSP;

	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv( class, class_len)));
	PUTBACK;

	call_method( "new", G_SCALAR);

	SPAGAIN;

	newobj = POPs;	
	PUTBACK;
	FREETMPS;
	LEAVE;

	return newobj;
	
}

SV *uwsgi_perl_call_stream(SV *func) {

	SV *ret = NULL;
        // set current context ?
        dTHX;
        dSP;

        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        XPUSHs( sv_2mortal(newRV((SV*) uperl.stream_responder)));
        PUTBACK;

	call_sv( func, G_SCALAR | G_EVAL);

	SPAGAIN;
        if(SvTRUE(ERRSV)) {
                uwsgi_log("%s\n", SvPV_nolen(ERRSV));
        }
        else {
                ret = SvREFCNT_inc(POPs);
        }

        PUTBACK;
        FREETMPS;
        LEAVE;

        return ret;
}

int uwsgi_perl_obj_can(SV *obj, char *method, size_t len) {

	int ret;
        // set current context ? needed for threading
        dTHX;
        dSP;

        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        XPUSHs(obj);
        XPUSHs(sv_2mortal(newSVpv(method, len)));
        PUTBACK;

        call_method( "can", G_SCALAR);

        SPAGAIN;

        ret = SvROK(POPs);
        PUTBACK;
        FREETMPS;
        LEAVE;

        return ret;

}


SV *uwsgi_perl_obj_call(SV *obj, char *method) {

        SV *ret = NULL;

	dTHX;
        dSP;

        ENTER;
        SAVETMPS;
        PUSHMARK(SP);

        XPUSHs(obj);

        PUTBACK;

        call_method( method, G_SCALAR | G_EVAL);

        SPAGAIN;
	if(SvTRUE(ERRSV)) {
        	uwsgi_log("%s\n", SvPV_nolen(ERRSV));
        }
	else {
        	ret = SvREFCNT_inc(POPs);
	}

        PUTBACK;
        FREETMPS;
        LEAVE;

        return ret;

}


AV *psgi_call(struct wsgi_request *wsgi_req, SV *psgi_func, SV *env) {

	AV *ret = NULL;

	dTHX;
        dSP;

        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        XPUSHs(env);
	PUTBACK;

	call_sv(psgi_func, G_SCALAR | G_EVAL);

	SPAGAIN;

        if(SvTRUE(ERRSV)) {
                internal_server_error(wsgi_req, "exception raised");
                uwsgi_log("%s\n", SvPV_nolen(ERRSV));
        }
	else {
		ret = (AV *) SvREFCNT_inc(SvRV(POPs));
	}

	PUTBACK;
        FREETMPS;
        LEAVE;

        return (AV *)ret;
	
}

SV *build_psgi_env(struct wsgi_request *wsgi_req) {
	int i;
	HV *env = newHV();

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
        if (!hv_store(env, "psgi.version", 12, newRV_noinc((SV *)av ), 0)) goto clear;

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


	SV *pi = uwsgi_perl_obj_new("uwsgi::input", 12);
        if (!hv_store(env, "psgi.input", 10, pi, 0)) goto clear;
	
	if (!hv_store(env, "psgix.input.buffered", 20, newSViv(wsgi_req->body_as_file), 0)) goto clear;

	if (uwsgi.master_process) {
		if (!hv_store(env, "psgix.harakiri", 14, newSViv(1), 0)) goto clear;
	}

	SV *pe = uwsgi_perl_obj_new("uwsgi::error", 12);
        if (!hv_store(env, "psgi.errors", 11, pe, 0)) goto clear;

	return newRV_noinc((SV *)env);

clear:
	SvREFCNT_dec((SV *)env);
	return NULL;
}

int uwsgi_perl_init(){


	struct http_status_codes *http_sc;

	int argc;
	uperl.embedding[0] = "";
	uperl.embedding[1] = "-e";
	uperl.embedding[2] = "0";

	if (setenv("PLACK_ENV", "uwsgi", 0)) {
		uwsgi_error("setenv()");
	}

	if (setenv("PLACK_SERVER", "uwsgi", 0)) {
		uwsgi_error("setenv()");
	}

#ifdef PERL_VERSION_STRING
	uwsgi_log("initializing Perl %s environment\n", PERL_VERSION_STRING);
#else
	uwsgi_log("initializing Perl environment\n");
#endif

	argc = 3;

	PERL_SYS_INIT3(&argc, (char ***) &uperl.embedding, &environ);
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

	return 1;

}

#ifdef USE_ITHREADS
void uwsgi_perl_enable_threads() {
	
	if (pthread_key_create(&uperl.u_interpreter, NULL)) {
        	uwsgi_error("pthread_key_create()");
                exit(1);
	}

	uperl.interp = uwsgi_malloc( sizeof(PerlInterpreter*) * uwsgi.threads );
	uperl.interp[0] = uperl.main;

	uperl.psgi_func = uwsgi_malloc( sizeof(SV*) * uwsgi.threads );


}
#endif



int uwsgi_perl_request(struct wsgi_request *wsgi_req) {

	SV **harakiri;
	SV *psgi_func = uperl.psgi_main;

#ifdef UWSGI_ASYNC
	if (wsgi_req->async_status == UWSGI_AGAIN) {
		return psgi_response(wsgi_req, wsgi_req->async_placeholder);	
	}
#endif

	/* Standard PSGI request */
	if (!wsgi_req->uh.pktsize) {
		uwsgi_log("Invalid PSGI request. skip.\n");
		return -1;
	}


	if (uwsgi_parse_vars(wsgi_req)) {
		return -1;
	}

	if (uwsgi.threads > 1) {
		psgi_func = uperl.psgi_func[wsgi_req->async_id];
	}

	
	ENTER;
	SAVETMPS;

	wsgi_req->async_environ = build_psgi_env(wsgi_req);
	if (!wsgi_req->async_environ) goto clear;

	wsgi_req->async_result = psgi_call(wsgi_req, psgi_func, wsgi_req->async_environ);
	if (!wsgi_req->async_result) goto clear;

	if (SvTYPE((AV *)wsgi_req->async_result) == SVt_PVCV) {
		SV *stream_result = uwsgi_perl_call_stream((SV*)wsgi_req->async_result);		
		if (!stream_result) {
			internal_server_error(wsgi_req, "exception raised");
		}
		else {
			SvREFCNT_dec(stream_result);
		}
		goto clear2;
	}

	while (psgi_response(wsgi_req, wsgi_req->async_result) != UWSGI_OK) {
#ifdef UWSGI_ASYNC
		if (uwsgi.async > 1) {
			FREETMPS;
			LEAVE;
			return UWSGI_AGAIN;
		}
#endif
	}

clear2:
	// check for psgix.harakiri
        harakiri = hv_fetch((HV*)SvRV( (SV*)wsgi_req->async_environ), "psgix.harakiri.commit", 21, 0);
        if (harakiri) {
                if (SvTRUE(*harakiri)) wsgi_req->async_plagued = 1;
        }

	SvREFCNT_dec(wsgi_req->async_environ);
	SvREFCNT_dec(wsgi_req->async_result);
clear:

	FREETMPS;
	LEAVE;

	return UWSGI_OK;
}


void uwsgi_perl_after_request(struct wsgi_request *wsgi_req) {

	if (uwsgi.shared->options[UWSGI_OPTION_LOGGING])
		log_request(wsgi_req);

	if (wsgi_req->async_plagued) {
		uwsgi_log("*** psgix.harakiri.commit requested ***\n");
		goodbye_cruel_world();
	}

}

#ifdef USE_ITHREADS
void uwsgi_perl_init_thread(int core_id) {



	if (core_id > 0) {
		uperl.interp[core_id] = perl_clone(uperl.main, CLONEf_KEEP_PTR_TABLE);
                if (!uperl.interp[core_id]) {
                        uwsgi_log("unable to create new perl interpreter\n");
                        exit(1);
                }
	}

	dTHXa(uperl.interp[core_id]);
	PERL_SET_CONTEXT(uperl.interp[core_id]);

	pthread_setspecific(uperl.u_interpreter, uperl.interp[core_id]);

	uperl.psgi_func[0] = uperl.psgi_main;
	if (core_id > 0) {
		uperl.psgi_func[core_id] = perl_eval_pv(uwsgi_concat4("#line 1 ", uperl.psgi, "\n", uperl.psgibuffer), 0);

        	if (!uperl.psgi_func[core_id]) {
        		uwsgi_log("unable to find PSGI function entry point.\n");
                	exit(1);
        	}

        	if(SvTRUE(ERRSV)) {
        		uwsgi_log("%s\n", SvPV_nolen(ERRSV));
                	exit(1);
        	}
	}

}
#endif

int uwsgi_perl_manage_options(int i, char *optarg) {

        switch(i) {
                case LONG_ARGS_PSGI:
                        uperl.psgi = optarg;
                        return 1;
                case LONG_ARGS_PERL_LOCAL_LIB:
                        uperl.locallib = optarg;
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
#ifdef USE_ITHREADS
	.enable_threads = uwsgi_perl_enable_threads,
	.init_thread = uwsgi_perl_init_thread,
#endif
	.manage_opt = uwsgi_perl_manage_options,
	.request = uwsgi_perl_request,
	.after_request = uwsgi_perl_after_request,

	.magic = uwsgi_perl_magic,
};
