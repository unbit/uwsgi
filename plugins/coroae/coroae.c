#include "../psgi/psgi.h"
#include "CoroAPI.h"

struct uwsgi_coroae {
	SV *condvar;
	AV *watchers;
	int destroy;
};

extern struct uwsgi_server uwsgi;
extern struct uwsgi_perl uperl;
struct uwsgi_coroae ucoroae;

MGVTBL uwsgi_coroae_vtbl = { 0,  0,  0,  0, 0 };

#define free_req_queue uwsgi.async_queue_unused_ptr++; uwsgi.async_queue_unused[uwsgi.async_queue_unused_ptr] = wsgi_req

static void uwsgi_opt_setup_coroae(char *opt, char *value, void *null) {

        // set async mode
        uwsgi_opt_set_int(opt, value, &uwsgi.async);
        if (uwsgi.socket_timeout < 30) {
                uwsgi.socket_timeout = 30;
        }
        // set loop engine
        uwsgi.loop = "coroae";

}


static struct uwsgi_option coroae_options[] = {
        {"coroae", required_argument, 0, "a shortcut enabling Coro::AnyEvent loop engine with the specified number of async cores and optimal parameters", uwsgi_opt_setup_coroae, NULL, 0},
        {0, 0, 0, 0, 0, 0, 0},

};

static struct wsgi_request *coroae_current_wsgi_req(void) {
	MAGIC *mg;
	SV *current = CORO_CURRENT;
	for (mg = SvMAGIC (current); mg; mg = mg->mg_moremagic) {
		if (mg->mg_type == PERL_MAGIC_ext + 1 && mg->mg_virtual == &uwsgi_coroae_vtbl) {
        		return (struct wsgi_request *) mg->mg_ptr;
		}
	}	
	uwsgi_log("[BUG] current_wsgi_req NOT FOUND !!!\n");
	// TODO allow to survive api call error as in the python plugin
	exit(1);
}   


// create a new coro
SV * coroae_coro_new(CV *block) {
	SV *newobj = NULL;
	dSP;
        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        mXPUSHs(newSVpvs("Coro"));
        mXPUSHs(newRV_noinc((SV *)block));
        PUTBACK;
        call_method("new", G_SCALAR|G_EVAL);
        SPAGAIN;
        if(SvTRUE(ERRSV)) {
                uwsgi_log("[uwsgi-perl error] %s", SvPV_nolen(ERRSV));
                (void)POPs; // we must pop undef from the stack in G_SCALAR context
        }
        else {
                newobj = SvREFCNT_inc(POPs);
        }
	PUTBACK;
        FREETMPS;
        LEAVE;
	return newobj;
}

static int coroae_wait_milliseconds(int timeout) {
	char buf[256];
	double d = ((double)timeout)/1000.0;
	int ret = snprintf(buf, 256, "Coro::AnyEvent::sleep %f", d);
	if (ret <= 0 || ret > 256) return -1;
	perl_eval_pv(buf, 0);
	return 0;
}

static int coroae_wait_fd_read(int fd, int timeout) {
	int ret = 0;
	dSP;
        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        mXPUSHs(newSViv(fd));
        mXPUSHs(newSViv(timeout));
        PUTBACK;
        call_pv("Coro::AnyEvent::readable", G_SCALAR|G_EVAL);
        SPAGAIN;
        if(SvTRUE(ERRSV)) {
                uwsgi_log("[uwsgi-perl error] %s", SvPV_nolen(ERRSV));
                (void)POPs; // we must pop undef from the stack in G_SCALAR context
        }
	else {
		SV *p_ret = POPs;
		if (SvTRUE(p_ret)) {
			ret = 1;
		}
	}
        PUTBACK;
        FREETMPS;
        LEAVE;

	return ret;
}

static int coroae_wait_fd_write(int fd, int timeout) {
	int ret = 0;
        dSP;
        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        XPUSHs(sv_2mortal(newSViv(fd)));
        XPUSHs(sv_2mortal(newSViv(timeout)));
        PUTBACK;
        call_pv("Coro::AnyEvent::writable", G_SCALAR|G_EVAL);
        SPAGAIN;
        if(SvTRUE(ERRSV)) {
                uwsgi_log("[uwsgi-perl error] %s", SvPV_nolen(ERRSV));
                (void)POPs; // we must pop undef from the stack in G_SCALAR context
        }
	else {
		SV *p_ret = POPs;	
		if (SvTRUE(p_ret)) {
			ret = 1;
		}
	}
        FREETMPS;
        LEAVE;

	return ret;
}


// this runs in another Coro object
XS(XS_coroae_accept_request) {

	dXSARGS;
        psgi_check_args(0);

	struct wsgi_request *wsgi_req = (struct wsgi_request *) XSANY.any_ptr;

	// if in edge-triggered mode read from socket now !!!
        if (wsgi_req->socket->edge_trigger) {
                int status = wsgi_req->socket->proto(wsgi_req);
                if (status < 0) {
                        goto end;
                }
                goto request;
        }

	for(;;) {
		int ret = uwsgi.wait_read_hook(wsgi_req->fd, uwsgi.socket_timeout);
		wsgi_req->switches++;
	
		if (ret <= 0) {
			goto end;
		}
	
		int status = wsgi_req->socket->proto(wsgi_req);
                if (status < 0) {
                	goto end;
                }
                else if (status == 0) {
                	break;
                }
	}

request:

#ifdef UWSGI_ROUTING
        if (uwsgi_apply_routes(wsgi_req) == UWSGI_ROUTE_BREAK) {
                goto end;
        }
#endif

        for(;;) {
                if (uwsgi.p[wsgi_req->uh->modifier1]->request(wsgi_req) <= UWSGI_OK) {
                        goto end;
                }
                wsgi_req->switches++;
                // switch after each yield
		CORO_CEDE;
        }

end:
	uwsgi_close_request(wsgi_req);
        free_req_queue;
	XSRETURN(0);
}

XS(XS_coroae_sighandler) {
	int sigfd = (long) XSANY.any_ptr;
	uwsgi_receive_signal(sigfd, "worker", uwsgi.mywid);
}

XS(XS_coroae_acceptor) {
        dXSARGS;
	psgi_check_args(0);

	struct uwsgi_socket *uwsgi_sock = (struct uwsgi_socket *) XSANY.any_ptr;

	struct wsgi_request *wsgi_req = NULL;
edge:
        wsgi_req = find_first_available_wsgi_req();

        if (wsgi_req == NULL) {
		uwsgi_async_queue_is_full(uwsgi_now());
                goto clear;
        }

        // fill wsgi_request structure
        wsgi_req_setup(wsgi_req, wsgi_req->async_id, uwsgi_sock );

        // mark core as used
        uwsgi.workers[uwsgi.mywid].cores[wsgi_req->async_id].in_request = 1;

	// accept the connection
        if (wsgi_req_simple_accept(wsgi_req, uwsgi_sock->fd)) {
                free_req_queue;
                if (uwsgi_sock->retry && uwsgi_sock->retry[wsgi_req->async_id]) {
                        goto edge;
                }
		// in case of errors (or thundering herd, just rest it)
                uwsgi.workers[uwsgi.mywid].cores[wsgi_req->async_id].in_request = 0;
                goto clear;
        }

	wsgi_req->start_of_request = uwsgi_micros();
        wsgi_req->start_of_request_in_sec = wsgi_req->start_of_request/1000000;

        // enter harakiri mode
        if (uwsgi.harakiri_options.workers > 0) {
                set_harakiri(uwsgi.harakiri_options.workers);
        }


	// here we spawn an async {} block
	CV *async_xs_call = newXS(NULL, XS_coroae_accept_request, "uwsgi::coroae");
	CvXSUBANY(async_xs_call).any_ptr = wsgi_req;
	SV *coro_req = coroae_coro_new(async_xs_call);
	sv_magicext(SvRV(coro_req), 0, PERL_MAGIC_ext + 1, &uwsgi_coroae_vtbl, (const char *)wsgi_req, 0);
	CORO_READY(coro_req);
	SvREFCNT_dec(coro_req);

	if (uwsgi_sock->edge_trigger) {
#ifdef UWSGI_DEBUG
                uwsgi_log("i am an edge triggered socket !!!\n");
#endif
                goto edge;
	}


clear:
        XSRETURN(0);
}


static CV *coroae_closure_acceptor(struct uwsgi_socket *uwsgi_sock) {

	CV *xsub = newXS(NULL, XS_coroae_acceptor, "uwsgi::coroae");
	CvXSUBANY(xsub).any_ptr = uwsgi_sock;
	return xsub;
}

static CV *coroae_closure_sighandler(int sigfd) {

        CV *xsub = newXS(NULL, XS_coroae_sighandler, "uwsgi::coroae");
        CvXSUBANY(xsub).any_ptr = (void *) sigfd;
        return xsub;
}



static SV *coroae_add_watcher(int fd, CV *cb) {

        SV *newobj;

        dSP;

        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        mXPUSHs(newSVpvs("AnyEvent"));
        mXPUSHs(newSVpvs("fh"));
        mXPUSHs(newSViv(fd));
        mXPUSHs(newSVpvs("poll"));
        mXPUSHs(newSVpvs("r"));
        mXPUSHs(newSVpvs("cb"));
        mXPUSHs(newRV_noinc((SV *)cb));
        PUTBACK;

        call_method( "io", G_SCALAR|G_EVAL);

        SPAGAIN;
	if(SvTRUE(ERRSV)) {
		// no need to continue...
                uwsgi_log("[uwsgi-perl error] %s", SvPV_nolen(ERRSV));
		exit(1);
        }
	else {
        	newobj = SvREFCNT_inc(POPs);
	}
        PUTBACK;
        FREETMPS;
        LEAVE;

        return newobj;


}

static SV *coroae_add_signal_watcher(const char *signame, CV *cb) {

	SV *newobj;

	dSP;

	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	mXPUSHs(newSVpvs("AnyEvent"));
	mXPUSHs(newSVpvs("signal"));
	mXPUSHs(newSVpv(signame, 0));
	mXPUSHs(newSVpvs("cb"));
	mXPUSHs(newRV_noinc((SV *)cb));
	PUTBACK;

	call_method("signal", G_SCALAR|G_EVAL);

	SPAGAIN;
	if(SvTRUE(ERRSV)) {
		// no need to continue...
		uwsgi_log("[uwsgi-perl error] %s", SvPV_nolen(ERRSV));
		exit(1);
	}
	else {
		newobj = SvREFCNT_inc(POPs);
	}
	PUTBACK;
	FREETMPS;
	LEAVE;

	return newobj;

}

static SV *coroae_condvar_new() {
	
	SV *newobj;

        dSP;

        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        XPUSHs(sv_2mortal(newSVpv( "AnyEvent", 8)));
        PUTBACK;

        call_method( "condvar", G_SCALAR|G_EVAL);

        SPAGAIN;
        if(SvTRUE(ERRSV)) {
                uwsgi_log("[uwsgi-perl error] %s", SvPV_nolen(ERRSV));
                (void)POPs; // we must pop undef from the stack in G_SCALAR context
                newobj = NULL;
        }
        else {
                newobj = SvREFCNT_inc(POPs);
        }
        PUTBACK;
        FREETMPS;
        LEAVE;

        return newobj;
}

static void coroae_condvar_call(SV *cv, const char *method) {
	dSP;

        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        XPUSHs(cv);
        PUTBACK;

        call_method(method, G_DISCARD|G_EVAL);

        SPAGAIN;
        if(SvTRUE(ERRSV)) {
                uwsgi_log("[uwsgi-perl error] %s", SvPV_nolen(ERRSV));
        }
        PUTBACK;
        FREETMPS;
        LEAVE;
}


XS(XS_coroae_graceful) {
	int i;
	int rounds;
	int running_cores;
	for (rounds = 0; ; rounds++) {
		running_cores = 0;
		for (i = 0; i < uwsgi.async; i++) {
			if (uwsgi.workers[uwsgi.mywid].cores[i].in_request) {
				struct wsgi_request *wsgi_req = &uwsgi.workers[uwsgi.mywid].cores[i].req;
				if (!rounds) {
					uwsgi_log_verbose("worker %d (pid: %d) core %d is managing \"%.*s %.*s\" for %.*s\n", uwsgi.mywid, uwsgi.mypid, i, 
						wsgi_req->method_len, wsgi_req->method, wsgi_req->uri_len, wsgi_req->uri,
						wsgi_req->remote_addr_len, wsgi_req->remote_addr);
				}
				running_cores++;
			}
		}

		if (running_cores == 0) {
			break;
		}

		uwsgi_log_verbose("waiting for %d running requests on worker %d (pid: %d)...\n", running_cores, uwsgi.mywid, uwsgi.mypid);
		coroae_wait_milliseconds(100);
	}

	coroae_condvar_call(ucoroae.condvar, "send");
}

static void coroae_graceful(void) {
	uwsgi_log("Gracefully killing worker %d (pid: %d)...\n", uwsgi.mywid, uwsgi.mypid);
	uwsgi.workers[uwsgi.mywid].manage_next_request = 0;
	SvREFCNT_dec(ucoroae.watchers);

	SV *coro_sv = coroae_coro_new(newXS(NULL, XS_coroae_graceful, "uwsgi::coroae"));
	CORO_READY(coro_sv);
	SvREFCNT_dec(coro_sv);
}

static void coroae_int(void) {
	uwsgi_log("Brutally killing worker %d (pid: %d)...\n", uwsgi.mywid, uwsgi.mypid);
	uwsgi.workers[uwsgi.mywid].manage_next_request = 0;
	SvREFCNT_dec(ucoroae.watchers);

	coroae_condvar_call(ucoroae.condvar, "send");
}

XS(XS_coroae_hup_sighandler) {
	coroae_graceful();
}

XS(XS_coroae_int_sighandler) {
	coroae_int();
}

static void coroae_gbcw(void) {
	if (ucoroae.destroy) return;
	ucoroae.destroy = 1;

	uwsgi_log("...The work of process %d is done. Seeya!\n", getpid());

	uwsgi_time_bomb(uwsgi.worker_reload_mercy, 0);
	
	coroae_graceful();
}

static void coroae_loop() {

	if (uwsgi.async < 2) {
		if (uwsgi.mywid == 1) {
			uwsgi_log("the Coro::AnyEvent loop engine requires async mode (--async <n>)\n");
		}
                exit(1);
	}

	if (!uperl.loaded) {
		uwsgi_log("no perl/PSGI code loaded (with --psgi), unable to initialize Coro::AnyEvent\n");
		exit(1);
	}

	perl_eval_pv("use Coro;", 1);
	perl_eval_pv("use AnyEvent;", 1);
	perl_eval_pv("use Coro::AnyEvent;", 1);
	
	uwsgi.current_wsgi_req = coroae_current_wsgi_req;
	uwsgi.wait_write_hook = coroae_wait_fd_write;
        uwsgi.wait_read_hook = coroae_wait_fd_read;
        uwsgi.wait_milliseconds_hook = coroae_wait_milliseconds;

	I_CORO_API("uwsgi::coroae");

	// patch goodbye_cruel_world
	uwsgi.gbcw_hook = coroae_gbcw;
	ucoroae.watchers = newAV();

	av_push(ucoroae.watchers, coroae_add_signal_watcher("HUP", newXS(NULL, XS_coroae_hup_sighandler, "uwsgi::coroae")));
	av_push(ucoroae.watchers, coroae_add_signal_watcher("INT", newXS(NULL, XS_coroae_int_sighandler, "uwsgi::coroae")));
	av_push(ucoroae.watchers, coroae_add_signal_watcher("TERM", newXS(NULL, XS_coroae_int_sighandler, "uwsgi::coroae")));

	// create signal watchers
	if (uwsgi.signal_socket > -1) {
		av_push(ucoroae.watchers, coroae_add_watcher(uwsgi.signal_socket, coroae_closure_sighandler(uwsgi.signal_socket)));
		av_push(ucoroae.watchers, coroae_add_watcher(uwsgi.my_signal_socket, coroae_closure_sighandler(uwsgi.my_signal_socket)));
	}

	struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;
	while(uwsgi_sock) {
		// check return value here
		av_push(ucoroae.watchers, coroae_add_watcher(uwsgi_sock->fd, coroae_closure_acceptor(uwsgi_sock)));
		uwsgi_sock = uwsgi_sock->next;
	};

	ucoroae.condvar = coroae_condvar_new();
	coroae_condvar_call(ucoroae.condvar, "recv");
	SvREFCNT_dec(ucoroae.condvar);

	if (uwsgi.workers[uwsgi.mywid].manage_next_request == 0) {
                uwsgi_log("goodbye to the Coro::AnyEvent loop on worker %d (pid: %d)\n", uwsgi.mywid, uwsgi.mypid);
                exit(UWSGI_RELOAD_CODE);
        }

	uwsgi_log("the Coro::AnyEvent loop is no more :(\n");
}

static void coroae_init() {
	uwsgi_register_loop( (char *) "coroae", coroae_loop);
}

struct uwsgi_plugin coroae_plugin = {
	.name = "coroae",
	.options = coroae_options,
	.on_load = coroae_init,
};
