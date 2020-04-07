#include "psgi.h"

extern char **environ;
extern struct uwsgi_server uwsgi;

struct uwsgi_perl uperl;

struct uwsgi_plugin psgi_plugin;

static void uwsgi_opt_plshell(char *opt, char *value, void *foobar) {

        uwsgi.honour_stdin = 1;
        if (value) {
                uperl.shell = value;
        }
        else {
                uperl.shell = "";
        }

        if (!strcmp("plshell-oneshot", opt)) {
                uperl.shell_oneshot = 1;
        }
}

struct uwsgi_option uwsgi_perl_options[] = {

        {"psgi", required_argument, 0, "load a psgi app", uwsgi_opt_set_str, &uperl.psgi, 0},
        {"psgi-enable-psgix-io", no_argument, 0, "enable psgix.io support", uwsgi_opt_true, &uperl.enable_psgix_io, 0},
        {"perl-no-die-catch", no_argument, 0, "do not catch $SIG{__DIE__}", uwsgi_opt_true, &uperl.no_die_catch, 0},
        {"perl-local-lib", required_argument, 0, "set perl locallib path", uwsgi_opt_set_str, &uperl.locallib, 0},
#ifdef PERL_VERSION_STRING
        {"perl-version", no_argument, 0, "print perl version", uwsgi_opt_print, PERL_VERSION_STRING, UWSGI_OPT_IMMEDIATE},
#endif
        {"perl-args", required_argument, 0, "add items (space separated) to @ARGV", uwsgi_opt_set_str, &uperl.argv_items, 0},
        {"perl-arg", required_argument, 0, "add an item to @ARGV", uwsgi_opt_add_string_list, &uperl.argv_item, 0},
        {"perl-exec", required_argument, 0, "exec the specified perl file before fork()", uwsgi_opt_add_string_list, &uperl.exec, 0},
        {"perl-exec-post-fork", required_argument, 0, "exec the specified perl file after fork()", uwsgi_opt_add_string_list, &uperl.exec_post_fork, 0},
        {"perl-auto-reload", required_argument, 0, "enable perl auto-reloader with the specified frequency", uwsgi_opt_set_int, &uperl.auto_reload, UWSGI_OPT_MASTER},
        {"perl-auto-reload-ignore", required_argument, 0, "ignore the specified files when auto-reload is enabled", uwsgi_opt_add_string_list, &uperl.auto_reload_ignore, UWSGI_OPT_MASTER},

	{"plshell", optional_argument, 0, "run a perl interactive shell", uwsgi_opt_plshell, NULL, 0},
        {"plshell-oneshot", no_argument, 0, "run a perl interactive shell (one shot)", uwsgi_opt_plshell, NULL, 0},

        {"perl-no-plack", no_argument, 0, "force the use of do instead of Plack::Util::load_psgi", uwsgi_opt_true, &uperl.no_plack, 0},
        {0, 0, 0, 0, 0, 0, 0},

};

int uwsgi_perl_check_mtime(time_t now, HV *list, SV *key) {
	// insert item with the current time
	if (!hv_exists_ent(list, key, 0)) {
		// useless if...
		if (hv_store_ent(list, key, newSViv(now), 0)) return 0;
	}
	else {
		// compare mtime
		struct stat st;
		if (stat(SvPV_nolen(key), &st)) return 0;
		HE *mtime = hv_fetch_ent(list, key, 0, 0);
		if (!mtime) return 0;
		if (st.st_mtime > SvIV(HeVAL(mtime))) {
			uwsgi_log_verbose("[perl-auto-reloader] %s has been modified !!!\n", SvPV_nolen(key));
			kill(uwsgi.workers[0].pid, SIGHUP);
			return 1;
		}
	}

	return 0;
}

void uwsgi_perl_check_auto_reload() {
	time_t now = uwsgi_now();
	HE *he;
	if (!uperl.auto_reload_hash) {
		uperl.auto_reload_hash = newHV();
		// useless return value
		if (!SvREFCNT_inc(uperl.auto_reload_hash)) return;
	}
	GV *gv_inc = gv_fetchpv("INC", TRUE, SVt_PV);
	if (!gv_inc) return;
	HV *inc = GvHV(gv_inc);
	hv_iterinit(inc);
	while((he = hv_iternext(inc))) {
		SV *filename = hv_iterval(inc, he);
		struct uwsgi_string_list *usl;
		int found = 0;
		uwsgi_foreach(usl, uperl.auto_reload_ignore) {
			if (!strcmp(usl->value, SvPV_nolen(filename))) {
				found = 1; break;
			}
		}	
		if (found) continue;
		if (uwsgi_perl_check_mtime(now, uperl.auto_reload_hash, filename)) return;
	}
}

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

	newobj = SvREFCNT_inc(POPs);
	PUTBACK;
	FREETMPS;
	LEAVE;

	return newobj;
	
}

SV *uwsgi_perl_obj_new_from_fd(char *class, size_t class_len, int fd) {
	SV *newobj;

        dSP;

        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv( class, class_len)));
        XPUSHs(sv_2mortal(newSViv( fd )));
        XPUSHs(sv_2mortal(newSVpv( "w", 1 )));
        PUTBACK;

        call_method( "new_from_fd", G_SCALAR);

        SPAGAIN;

        newobj = SvREFCNT_inc(POPs);
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
	if (uwsgi.threads > 1) {
        	XPUSHs( sv_2mortal(newRV((SV*) ((SV **)wi->responder0)[wsgi_req->async_id])));
	}
	else {
        	XPUSHs( sv_2mortal(newRV((SV*) ((SV **)wi->responder0)[0])));
	}
        PUTBACK;

	call_sv( func, G_SCALAR | G_EVAL);

	SPAGAIN;
        if(SvTRUE(ERRSV)) {
                uwsgi_log("[uwsgi-perl error] %s", SvPV_nolen(ERRSV));
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

        call_method( "can", G_SCALAR|G_EVAL);

        SPAGAIN;
	if(SvTRUE(ERRSV)) {
		uwsgi_log("%s", SvPV_nolen(ERRSV));
	}

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
        	uwsgi_log("%s", SvPV_nolen(ERRSV));
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
                uwsgi_500(wsgi_req);
                uwsgi_log("[uwsgi-perl error] %s", SvPV_nolen(ERRSV));
        }
	else {
		SV *r = POPs;
		if (SvROK(r)) {
			ret = (AV *) SvREFCNT_inc(SvRV(r));
		}
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

        if (uwsgi.async > 1) {
                if (!hv_store(env, "psgi.nonblocking", 16, newSViv(1), 0)) goto clear;
        }
        else {
                if (!hv_store(env, "psgi.nonblocking", 16, newSViv(0), 0)) goto clear;
        }

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
	
	if (!hv_store(env, "psgix.input.buffered", 20, newSViv(uwsgi.post_buffering), 0)) goto clear;

	if (uwsgi.threads > 1) {
		if (!hv_store(env, "psgix.logger", 12,newRV((SV*) ((SV **)wi->responder1)[wsgi_req->async_id]) ,0)) goto clear;
	}
	else {
		if (!hv_store(env, "psgix.logger", 12,newRV((SV*) ((SV **)wi->responder1)[0]) ,0)) goto clear;
	}

	if (uwsgi.master_process) {
		if (!hv_store(env, "psgix.harakiri", 14, newSViv(1), 0)) goto clear;
	}

	if (!hv_store(env, "psgix.cleanup", 13, newSViv(1), 0)) goto clear;
	// cleanup handlers array
	av = newAV();
	if (!hv_store(env, "psgix.cleanup.handlers", 22, newRV_noinc((SV *)av ), 0)) goto clear;

	// this call requires a bunch of syscalls, so it hurts performance
	if (uperl.enable_psgix_io) {
		SV *io = uwsgi_perl_obj_new_from_fd("IO::Socket", 10, wsgi_req->fd);
		if (!hv_store(env, "psgix.io", 8, io, 0)) goto clear;
	}

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

#ifdef PERL_VERSION_STRING
	uwsgi_log_initial("initialized Perl %s main interpreter at %p\n", PERL_VERSION_STRING, uperl.main[0]);
#else
	uwsgi_log_initial("initialized Perl main interpreter at %p\n", uperl.main[0]);
#endif

	return 1;

}

int uwsgi_perl_request(struct wsgi_request *wsgi_req) {

	if (wsgi_req->async_status == UWSGI_AGAIN) {
		return psgi_response(wsgi_req, wsgi_req->async_placeholder);	
	}

	/* Standard PSGI request */
	if (!wsgi_req->uh->pktsize) {
		uwsgi_log("Empty PSGI request. skip.\n");
		return -1;
	}

	if (uwsgi_parse_vars(wsgi_req)) {
		return -1;
	}

	if (wsgi_req->dynamic) {
		if (uwsgi.threads > 1) {
                	pthread_mutex_lock(&uperl.lock_loader);
                }
	}

	wsgi_req->app_id = uwsgi_get_app_id(wsgi_req, wsgi_req->appid, wsgi_req->appid_len, psgi_plugin.modifier1);
	// if it is -1, try to load a dynamic app
	if (wsgi_req->app_id == -1) {
		if (wsgi_req->dynamic) {
			if (wsgi_req->script_len > 0) {
				wsgi_req->app_id = init_psgi_app(wsgi_req, wsgi_req->script, wsgi_req->script_len, NULL);	
			}
			else if (wsgi_req->file_len > 0) {
				wsgi_req->app_id = init_psgi_app(wsgi_req, wsgi_req->file, wsgi_req->file_len, NULL);	
			}
		}

			if (wsgi_req->app_id == -1 && !uwsgi.no_default_app && uwsgi.default_app > -1) {
				if (uwsgi_apps[uwsgi.default_app].modifier1 == psgi_plugin.modifier1) {
					wsgi_req->app_id = uwsgi.default_app;
				}
			}

	}
	
	if (wsgi_req->dynamic) {
                if (uwsgi.threads > 1) {
                        pthread_mutex_unlock(&uperl.lock_loader);
                }
        }

		if (wsgi_req->app_id == -1) {
			uwsgi_500(wsgi_req);	
			uwsgi_log("--- unable to find perl application ---\n");
			// nothing to clear/free
			return UWSGI_OK;
		}

	struct uwsgi_app *wi = &uwsgi_apps[wsgi_req->app_id];
	wi->requests++;


	if (uwsgi.threads < 2) {
		if (((PerlInterpreter **)wi->interpreter)[0] != uperl.main[0]) {
			PERL_SET_CONTEXT(((PerlInterpreter **)wi->interpreter)[0]);
		}
	}
	else {
		if (((PerlInterpreter **)wi->interpreter)[wsgi_req->async_id] != uperl.main[wsgi_req->async_id]) {
			PERL_SET_CONTEXT(((PerlInterpreter **)wi->interpreter)[wsgi_req->async_id]);
		}
	}

	ENTER;
	SAVETMPS;

	wsgi_req->async_environ = build_psgi_env(wsgi_req);
	if (!wsgi_req->async_environ) goto clear;


	if (uwsgi.threads > 1) {
		wsgi_req->async_result = psgi_call(wsgi_req, ((SV **)wi->callable)[wsgi_req->async_id], wsgi_req->async_environ);
	}
	else {
		wsgi_req->async_result = psgi_call(wsgi_req, ((SV **)wi->callable)[0], wsgi_req->async_environ);
	}
	if (!wsgi_req->async_result) goto clear;

	if (SvTYPE((AV *)wsgi_req->async_result) == SVt_PVCV) {
		SV *stream_result = uwsgi_perl_call_stream((SV*)wsgi_req->async_result);		
		if (!stream_result) {
			uwsgi_500(wsgi_req);
		}
		else {
			SvREFCNT_dec(stream_result);
		}
		goto clear2;
	}

	while (psgi_response(wsgi_req, wsgi_req->async_result) != UWSGI_OK) {
		if (uwsgi.async > 1) {
			FREETMPS;
			LEAVE;
			return UWSGI_AGAIN;
		}
	}

clear2:
	// clear response
	SvREFCNT_dec(wsgi_req->async_result);
clear:

	FREETMPS;
	LEAVE;

	// restore main interpreter if needed
	if (uwsgi.threads > 1) {
		if (((PerlInterpreter **)wi->interpreter)[wsgi_req->async_id] != uperl.main[wsgi_req->async_id]) {
			PERL_SET_CONTEXT(uperl.main[wsgi_req->async_id]);
		}
	}
	else {
		if (((PerlInterpreter **)wi->interpreter)[0] != uperl.main[0]) {
			PERL_SET_CONTEXT(uperl.main[0]);
		}
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
                uwsgi_log("[uwsgi-perl error] %s", SvPV_nolen(ERRSV));
        }
	FREETMPS;
	LEAVE;
}

void uwsgi_perl_after_request(struct wsgi_request *wsgi_req) {

	log_request(wsgi_req);

	// We may be called after an early exit in XS_coroae_accept_request, 
	// before the environ is set up.
	if (!wsgi_req->async_environ) return;

	// we need to restore the context in case of multiple interpreters
	struct uwsgi_app *wi = &uwsgi_apps[wsgi_req->app_id];
	if (uwsgi.threads < 2) {
                if (((PerlInterpreter **)wi->interpreter)[0] != uperl.main[0]) {
                        PERL_SET_CONTEXT(((PerlInterpreter **)wi->interpreter)[0]);
                }
        }
        else {
                if (((PerlInterpreter **)wi->interpreter)[wsgi_req->async_id] != uperl.main[wsgi_req->async_id]) {
                        PERL_SET_CONTEXT(((PerlInterpreter **)wi->interpreter)[wsgi_req->async_id]);
                }
        }

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

	// Free the $env hash
	SvREFCNT_dec(wsgi_req->async_environ);

	// async plagued could be defined in other areas...
	if (wsgi_req->async_plagued) {
		uwsgi_log("*** psgix.harakiri.commit requested ***\n");
		// Before we call exit(0) we'll run the
		// uwsgi_perl_atexit() hook which'll properly tear
		// down the interpreter.

		// mark the request as ended (otherwise the atexit hook will be skipped)
		uwsgi.workers[uwsgi.mywid].cores[wsgi_req->async_id].in_request = 0;
		goodbye_cruel_world();
	}

	// now we can check for changed files
        if (uperl.auto_reload) {
                time_t now = uwsgi_now();
                if (now - uperl.last_auto_reload > uperl.auto_reload) {
                        uwsgi_perl_check_auto_reload();
                }
        }

	// restore main interpreter if needed
        if (uwsgi.threads > 1) {
                if (((PerlInterpreter **)wi->interpreter)[wsgi_req->async_id] != uperl.main[wsgi_req->async_id]) {
                        PERL_SET_CONTEXT(uperl.main[wsgi_req->async_id]);
                }
        }
        else {
                if (((PerlInterpreter **)wi->interpreter)[0] != uperl.main[0]) {
                        PERL_SET_CONTEXT(uperl.main[0]);
                }
        }


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

	struct uwsgi_string_list *usl;
	uwsgi_foreach(usl, uperl.exec_post_fork) {
		SV *dollar_zero = get_sv("0", GV_ADD);
                sv_setsv(dollar_zero, newSVpv(usl->value, usl->len));
		uwsgi_perl_exec(usl->value);
	}

	if (uperl.postfork) {
		uwsgi_perl_run_hook(uperl.postfork);
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

static int uwsgi_perl_signal_handler(uint8_t sig, void *handler) {

	int ret = 0;

	dSP;
        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        XPUSHs( sv_2mortal(newSViv(sig)));
        PUTBACK;

        call_sv( SvRV((SV*)handler), G_DISCARD);

        SPAGAIN;
	if(SvTRUE(ERRSV)) {
                uwsgi_log("[uwsgi-perl error] %s", SvPV_nolen(ERRSV));
		ret = -1;
        }

        PUTBACK;
        FREETMPS;
        LEAVE;

	return ret;
}

void uwsgi_perl_run_hook(SV *hook) {
	dSP;
        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        PUTBACK;

        call_sv( SvRV(hook), G_DISCARD);

        SPAGAIN;
        if(SvTRUE(ERRSV)) {
                uwsgi_log("[uwsgi-perl error] %s", SvPV_nolen(ERRSV));
		return;
        }

        PUTBACK;
        FREETMPS;
        LEAVE;
}

static void uwsgi_perl_atexit() {
	int i;

	if (uwsgi.mywid == 0) goto realstuff;

        // if hijacked do not run atexit hooks -- TODO: explain why
        // not.
        if (uwsgi.workers[uwsgi.mywid].hijacked)
                goto destroyperl;

	// if busy do not run atexit hooks (as this part could be called in a signal handler
	// while a subroutine is running)
        if (uwsgi_worker_is_busy(uwsgi.mywid))
                return;

realstuff:

	if (uperl.atexit) {
		uwsgi_perl_run_hook(uperl.atexit);
	}

	// For the reasons explained in
	// https://github.com/unbit/uwsgi/issues/1384, tearing down
	// the interpreter can be very expensive.
	if (uwsgi.skip_atexit_teardown)
		return;

destroyperl:

        // We must free our perl context(s) so any DESTROY hooks
        // etc. will run.
        for(i=0;i<uwsgi.threads;i++) {
            PERL_SET_CONTEXT(uperl.main[i]);

            // Destroy the PerlInterpreter, see "perldoc perlembed"
            perl_destruct(uperl.main[i]);
            perl_free(uperl.main[i]);
        }
        PERL_SYS_TERM();
        free(uperl.main);
}

static uint64_t uwsgi_perl_rpc(void *func, uint8_t argc, char **argv, uint16_t argvs[], char **buffer) {

	int i;
	uint64_t ret = 0;

        dSP;
        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
	for(i=0;i<argc;i++) {
        	XPUSHs( sv_2mortal(newSVpv(argv[i], argvs[i])));
	}
        PUTBACK;

        call_sv( SvRV((SV*)func), G_SCALAR | G_EVAL);

        SPAGAIN;
        if(SvTRUE(ERRSV)) {
                uwsgi_log("[uwsgi-perl error] %s", SvPV_nolen(ERRSV));
        }
	else {
		STRLEN rlen;
		SV *response = POPs;
                char *value = SvPV(response, rlen );
		if (rlen > 0) {
			*buffer = uwsgi_malloc(rlen);
			memcpy(*buffer, value, rlen);
			ret = rlen;
		}	
	}

        PUTBACK;
        FREETMPS;
        LEAVE;

        return ret;
}

static void uwsgi_perl_hijack(void) {
        if (uperl.shell_oneshot && uwsgi.workers[uwsgi.mywid].hijacked_count > 0) {
                uwsgi.workers[uwsgi.mywid].hijacked = 0;
                return;
        }
        if (uperl.shell && uwsgi.mywid == 1) {
                uwsgi.workers[uwsgi.mywid].hijacked = 1;
                uwsgi.workers[uwsgi.mywid].hijacked_count++;
                // re-map stdin to stdout and stderr if we are logging to a file
                if (uwsgi.logfile) {
                        if (dup2(0, 1) < 0) {
                                uwsgi_error("dup2()");
                        }
                        if (dup2(0, 2) < 0) {
                                uwsgi_error("dup2()");
                        }
                }

                if (uperl.shell[0] != 0) {
			perl_eval_pv(uperl.shell, 0);
                }
                else {
			perl_eval_pv("use Devel::REPL;my $repl = Devel::REPL->new;$repl->run;", 0);
                }
                if (uperl.shell_oneshot) {
                        exit(UWSGI_DE_HIJACKED_CODE);
                }
                exit(0);
        }

}

static void uwsgi_perl_add_item(char *key, uint16_t keylen, char *val, uint16_t vallen, void *data) {

        HV *spool_dict = (HV*) data;

	(void)hv_store(spool_dict, key, keylen, newSVpv(val, vallen), 0);
}


static int uwsgi_perl_spooler(char *filename, char *buf, uint16_t len, char *body, size_t body_len) {

        int ret = -1;

	if (!uperl.spooler) return 0;

	dSP;
        ENTER;
        SAVETMPS;
        PUSHMARK(SP);

	HV *spool_dict = newHV();	

	if (uwsgi_hooked_parse(buf, len, uwsgi_perl_add_item, (void *) spool_dict)) {
                return 0;
        }

        (void) hv_store(spool_dict, "spooler_task_name", 18, newSVpv(filename, 0), 0);

        if (body && body_len > 0) {
                (void) hv_store(spool_dict, "body", 4, newSVpv(body, body_len), 0);
        }

        XPUSHs( sv_2mortal((SV*)newRV_noinc((SV*)spool_dict)) );
        PUTBACK;

        call_sv( SvRV((SV*)uperl.spooler), G_SCALAR|G_EVAL);

        SPAGAIN;
        if(SvTRUE(ERRSV)) {
                uwsgi_log("[uwsgi-spooler-perl error] %s", SvPV_nolen(ERRSV));
		ret = -1;
        }
	else {
		ret = POPi;
	}

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

	.preinit_apps = uwsgi_psgi_preinit_apps,
	.init_apps = uwsgi_psgi_app,
	.mount_app = uwsgi_perl_mount_app,

	.init_thread = uwsgi_perl_init_thread,
	.signal_handler = uwsgi_perl_signal_handler,
	.rpc = uwsgi_perl_rpc,

	.mule = uwsgi_perl_mule,

	.hijack_worker = uwsgi_perl_hijack,

	.post_fork = uwsgi_perl_post_fork,
	.request = uwsgi_perl_request,
	.after_request = uwsgi_perl_after_request,
	.enable_threads = uwsgi_perl_enable_threads,

	.atexit = uwsgi_perl_atexit,

	.magic = uwsgi_perl_magic,

	.spooler = uwsgi_perl_spooler,
};
