#include "psgi.h"

extern char **environ;
extern struct uwsgi_server uwsgi;

#ifdef __APPLE__
extern struct uwsgi_perl uperl;
#else
struct uwsgi_perl uperl;
#endif

struct uwsgi_plugin psgi_plugin;

struct uwsgi_option uwsgi_perl_options[] = {

        {"psgi", required_argument, 0, "load a psgi app", uwsgi_opt_set_str, &uperl.psgi, 0},
        {"perl-no-die-catch", no_argument, 0, "do not catch $SIG{__DIE__}", uwsgi_opt_true, &uperl.no_die_catch, 0},
        {"perl-local-lib", required_argument, 0, "set perl locallib path", uwsgi_opt_set_str, &uperl.locallib, 0},
        {0, 0, 0, 0, 0, 0, 0},

};

extern struct http_status_codes hsc[];

SV *uwsgi_perl_obj_new(char *class, size_t class_len) {

	SV *newobj;

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
	struct wsgi_request *wsgi_req = current_wsgi_req();
	struct uwsgi_app *wi = &uwsgi_apps[wsgi_req->app_id];

        dSP;
        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        XPUSHs( sv_2mortal(newRV((SV*) ((SV **)wi->responder0)[wsgi_req->async_id])));
        PUTBACK;

	call_sv( func, G_SCALAR | G_EVAL);

	SPAGAIN;
        if(SvTRUE(ERRSV)) {
                uwsgi_log("[uwsgi-perl error] %s\n", SvPV_nolen(ERRSV));
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

int uwsgi_perl_obj_isa(SV *obj, char *class) {

	int ret = 0;

        dSP;

        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        XPUSHs(obj);
        PUTBACK;

        call_pv( "Scalar::Util::reftype", G_SCALAR|G_EVAL);

        SPAGAIN;
        char *reftype = POPp;
	if (reftype && !strcmp(reftype, class)) {
		ret = 1;
	}
        PUTBACK;
        FREETMPS;
        LEAVE;

        return ret;

}


SV *uwsgi_perl_obj_call(SV *obj, char *method) {

        SV *ret = NULL;

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
                uwsgi_log("[uwsgi-perl error] %s\n", SvPV_nolen(ERRSV));
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
	struct uwsgi_app *wi = &uwsgi_apps[wsgi_req->app_id];
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

	if (!hv_store(env, "psgix.logger", 12,newRV((SV*) ((SV **)wi->responder1)[wsgi_req->async_id]) ,0)) goto clear;

	if (uwsgi.master_process) {
		if (!hv_store(env, "psgix.harakiri", 14, newSViv(1), 0)) goto clear;
	}

	if (!hv_store(env, "psgix.cleanup", 13, newSViv(1), 0)) goto clear;
	// cleanup handlers array
	av = newAV();
	if (!hv_store(env, "psgix.cleanup.handlers", 22, newRV_noinc((SV *)av ), 0)) goto clear;
	

	SV *pe = uwsgi_perl_obj_new("uwsgi::error", 12);
        if (!hv_store(env, "psgi.errors", 11, pe, 0)) goto clear;

	(void) hv_delete(env, "HTTP_CONTENT_LENGTH", 19, G_DISCARD);
	(void) hv_delete(env, "HTTP_CONTENT_TYPE", 17, G_DISCARD);

	return newRV_noinc((SV *)env);

clear:
	SvREFCNT_dec((SV *)env);
	return NULL;
}

int uwsgi_perl_init(){


	struct http_status_codes *http_sc;

	int argc;
	int i;

	uperl.embedding[0] = "";
	uperl.embedding[1] = "-e";
	uperl.embedding[2] = "0";

#ifndef USE_ITHREADS
	if (uwsgi.threads > 1) {
		uwsgi_log("your Perl environment does not support threads\n");
		exit(1);
	} 
#endif

	if (setenv("PLACK_ENV", "uwsgi", 0)) {
		uwsgi_error("setenv()");
	}

	if (setenv("PLACK_SERVER", "uwsgi", 0)) {
		uwsgi_error("setenv()");
	}

	argc = 3;

	PERL_SYS_INIT3(&argc, (char ***) &uperl.embedding, &environ);

	uperl.main = uwsgi_calloc(sizeof(PerlInterpreter *) * uwsgi.threads);

	uperl.main[0] = uwsgi_perl_new_interpreter();
	if (!uperl.main[0]) {
		return -1;
	}

	for(i=1;i<uwsgi.threads;i++) {
		uperl.main[i] = uwsgi_perl_new_interpreter();
                if (!uperl.main[i]) {
                	uwsgi_log("unable to create new perl interpreter for thread %d\n", i+1);
                        exit(1);
                }
	}

	PERL_SET_CONTEXT(uperl.main[0]);

	// filling http status codes
	for (http_sc = hsc; http_sc->message != NULL; http_sc++) {
		http_sc->message_size = strlen(http_sc->message);
	}

#ifdef PERL_VERSION_STRING
	uwsgi_log_initial("initialized Perl %s main interpreter at %p\n", PERL_VERSION_STRING, uperl.main[0]);
#else
	uwsgi_log_initial("initialized Perl main interpreter at %p\n", uperl.main[0]);
#endif

	return 1;

}

int uwsgi_perl_request(struct wsgi_request *wsgi_req) {

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

	wsgi_req->app_id = uwsgi_get_app_id(wsgi_req->appid, wsgi_req->appid_len, psgi_plugin.modifier1);
	// if it is -1, try to load a dynamic app
	if (wsgi_req->app_id == -1) {
		if (wsgi_req->dynamic) {
			if (uwsgi.threads > 1) {
                                pthread_mutex_lock(&uperl.lock_loader);
                        }

			if (wsgi_req->script_len > 0) {
				wsgi_req->app_id = init_psgi_app(wsgi_req, wsgi_req->script, wsgi_req->script_len, NULL);	
			}
			else if (wsgi_req->file_len > 0) {
				wsgi_req->app_id = init_psgi_app(wsgi_req, wsgi_req->file, wsgi_req->file_len, NULL);	
			}

			if (uwsgi.threads > 1) {
                                pthread_mutex_unlock(&uperl.lock_loader);
                        }
		}

		if (wsgi_req->app_id == -1) {
			internal_server_error(wsgi_req, "Perl application not found");	
			// nothing to clear/free
			return UWSGI_OK;
		}
	}

	struct uwsgi_app *wi = &uwsgi_apps[wsgi_req->app_id];
	wi->requests++;

	if (((PerlInterpreter **)wi->interpreter)[wsgi_req->async_id] != uperl.main[wsgi_req->async_id]) {
		PERL_SET_CONTEXT(((PerlInterpreter **)wi->interpreter)[wsgi_req->async_id]);
	}

	ENTER;
	SAVETMPS;

	wsgi_req->async_environ = build_psgi_env(wsgi_req);
	if (!wsgi_req->async_environ) goto clear;

	wsgi_req->async_result = psgi_call(wsgi_req, ((SV **)wi->callable)[wsgi_req->async_id], wsgi_req->async_environ);
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
	// clear response
	SvREFCNT_dec(wsgi_req->async_result);
clear:

	FREETMPS;
	LEAVE;

	// restore main interpreter if needed
	if (((PerlInterpreter **)wi->interpreter)[wsgi_req->async_id] != uperl.main[wsgi_req->async_id]) {
		PERL_SET_CONTEXT(uperl.main[wsgi_req->async_id]);
	}

	return UWSGI_OK;
}

static void psgi_call_cleanup_hook(SV *hook, SV *env) {
	dSP;
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs(env);
	PUTBACK;
	call_sv(hook, G_DISCARD);
	if(SvTRUE(ERRSV)) {
                uwsgi_log("[uwsgi-perl error] %s\n", SvPV_nolen(ERRSV));
        }
	FREETMPS;
	LEAVE;
}

void uwsgi_perl_after_request(struct wsgi_request *wsgi_req) {

	log_request(wsgi_req);

	// dereference %env
	SV *env = SvRV((SV *) wsgi_req->async_environ);

	// check for cleanup handlers
	if (hv_exists((HV *)env, "psgix.cleanup.handlers", 22)) {
		SV **cleanup_handlers = hv_fetch((HV *)env, "psgix.cleanup.handlers", 22, 0);
		if (SvROK(*cleanup_handlers)) {
			if (SvTYPE(SvRV(*cleanup_handlers)) == SVt_PVAV) {
				I32 n = av_len((AV *)SvRV(*cleanup_handlers));
				I32 i;
				for(i=0;i<=n;i++) {
					SV **hook = av_fetch((AV *)SvRV(*cleanup_handlers), i, 0);
					psgi_call_cleanup_hook(*hook, (SV *) wsgi_req->async_environ);
				}
			}
		}
	}

	// check for psgix.harakiri
	if (hv_exists((HV *)env, "psgix.harakiri.commit", 21)) {
		SV **harakiri = hv_fetch((HV *)env, "psgix.harakiri.commit", 21, 0);
		if (SvTRUE(*harakiri)) wsgi_req->async_plagued = 1;
	}

	// async plagued could be defined in other areas...
	if (wsgi_req->async_plagued) {
		uwsgi_log("*** psgix.harakiri.commit requested ***\n");
		goodbye_cruel_world();
	}

	// clear the env
	SvREFCNT_dec(wsgi_req->async_environ);

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

// taken from Torsten Foertsch AfterFork.xs
void uwsgi_perl_post_fork() {

	GV *tmpgv = gv_fetchpv("$", TRUE, SVt_PV);
	if (tmpgv) {
		SvREADONLY_off(GvSV(tmpgv));
		sv_setiv(GvSV(tmpgv), (IV)getpid());
		SvREADONLY_on(GvSV(tmpgv));
	}
}

int uwsgi_perl_mount_app(char *mountpoint, char *app) {

	if (uwsgi_endswith(app, ".pl") || uwsgi_endswith(app, ".psgi")) {
        	uwsgi.wsgi_req->appid = mountpoint;
        	uwsgi.wsgi_req->appid_len = strlen(mountpoint);

        	return init_psgi_app(uwsgi.wsgi_req, app, strlen(app), NULL);
	}
	return -1;

}

void uwsgi_perl_init_thread(int core_id) {

#ifdef USE_ITHREADS
        PERL_SET_CONTEXT(uperl.main[core_id]);
#endif
}

void uwsgi_perl_pthread_prepare(void) {
        pthread_mutex_lock(&uperl.lock_loader);
}

void uwsgi_perl_pthread_parent(void) {
        pthread_mutex_unlock(&uperl.lock_loader);
}

void uwsgi_perl_pthread_child(void) {
        pthread_mutex_init(&uperl.lock_loader, NULL);
}


void uwsgi_perl_enable_threads(void) {
#ifdef USE_ITHREADS
	pthread_mutex_init(&uperl.lock_loader, NULL);
	pthread_atfork(uwsgi_perl_pthread_prepare, uwsgi_perl_pthread_parent, uwsgi_perl_pthread_child);
#endif
}

int uwsgi_perl_signal_handler(uint8_t sig, void *handler) {

	int ret = 0;

	dSP;
        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        XPUSHs( sv_2mortal(newSViv(sig)));
        PUTBACK;

        call_sv( SvRV((SV*)handler), G_DISCARD);

	if(SvTRUE(ERRSV)) {
                uwsgi_log("[uwsgi-perl error] %s\n", SvPV_nolen(ERRSV));
		ret = -1;
        }

        SPAGAIN;
        PUTBACK;
        FREETMPS;
        LEAVE;

	return ret;
}

struct uwsgi_plugin psgi_plugin = {

	.name = "psgi",
	.modifier1 = 5,
	.init = uwsgi_perl_init,
	.options = uwsgi_perl_options,

	.init_apps = uwsgi_psgi_app,
	.mount_app = uwsgi_perl_mount_app,

	.init_thread = uwsgi_perl_init_thread,
	.signal_handler = uwsgi_perl_signal_handler,

	.mule = uwsgi_perl_mule,

	.post_fork = uwsgi_perl_post_fork,
	.request = uwsgi_perl_request,
	.after_request = uwsgi_perl_after_request,
	.enable_threads = uwsgi_perl_enable_threads,

	.magic = uwsgi_perl_magic,
};
