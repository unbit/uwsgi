#include "../psgi/psgi.h"

extern struct uwsgi_server uwsgi;

#define free_req_queue uwsgi.async_queue_unused_ptr++; uwsgi.async_queue_unused[uwsgi.async_queue_unused_ptr] = wsgi_req

static void coro_ready(SV *coro) {
        dSP;
        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        XPUSHs(coro);
        PUTBACK;
        call_method("ready", G_DISCARD);
        uwsgi_log(" R e A D Y \n");
        SPAGAIN;
        if(SvTRUE(ERRSV)) {
                uwsgi_log("[uwsgi-perl error] %s\n", SvPV_nolen(ERRSV));
        }
        PUTBACK;
        FREETMPS;
        LEAVE;
}

static SV * coroae_coro_new(CV *block) {
	SV *newobj = NULL;
	dSP;
        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        XPUSHs(sv_2mortal(newSVpv( "Coro", 4)));
        XPUSHs(newRV_inc((SV *)block));
        PUTBACK;
        call_method("new", G_SCALAR);
	uwsgi_log("C a L L e D\n");
        SPAGAIN;
        if(SvTRUE(ERRSV)) {
                uwsgi_log("[uwsgi-perl error] %s\n", SvPV_nolen(ERRSV));
        }
        else {
                newobj = SvREFCNT_inc(POPs);
        }
	PUTBACK;
        FREETMPS;
        LEAVE;
	return newobj;
}

static int coroae_wait_fd_read(int fd, int timeout) {
	int ret = 0;
	dSP;
        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        XPUSHs(newSViv(fd));
        XPUSHs(newSViv(timeout));
        PUTBACK;
	uwsgi_log("waiting for %d\n", fd);
        call_pv("Coro::AnyEvent::readable", G_SCALAR);
        SPAGAIN;
	uwsgi_log("ok\n");
        if(SvTRUE(ERRSV)) {
                uwsgi_log("[uwsgi-perl error] %s\n", SvPV_nolen(ERRSV));
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

int coroae_wait_fd_write(int fd, int timeout) {
	int ret = 0;
        dSP;
        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        XPUSHs(sv_2mortal(newSViv(fd)));
        XPUSHs(sv_2mortal(newSViv(timeout)));
        PUTBACK;
        call_pv("Coro::AnyEvent::writable", G_SCALAR);
        SPAGAIN;
        if(SvTRUE(ERRSV)) {
                uwsgi_log("[uwsgi-perl error] %s\n", SvPV_nolen(ERRSV));
        }
	else {
		if (SvTRUE(POPs)) {
			ret = 1;
		}
	}
        FREETMPS;
        LEAVE;

	return ret;
}


static void coroae_cede() {
	dSP;
        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        PUTBACK;
        call_pv("cede", G_DISCARD);
	SPAGAIN;
        if(SvTRUE(ERRSV)) {
                uwsgi_log("[uwsgi-perl error] %s\n", SvPV_nolen(ERRSV));
        }
        FREETMPS;
        LEAVE;
}

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
		uwsgi_log("W a I t I n G\n");
		int ret = coroae_wait_fd_read(wsgi_req->poll.fd, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
		uwsgi_log("done\n");
		wsgi_req->switches++;
	
		if (!ret) {
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
	uwsgi_log("ready !!!\n");
	//coroae_cede();
	uwsgi_log("ready (cede) !!!\n");
	
        for(;;) {
		uwsgi_log("run code [0]\n");
                wsgi_req->async_status = uwsgi.p[wsgi_req->uh.modifier1]->request(wsgi_req);
		uwsgi_log("run code [1]\n");
                if (wsgi_req->async_status <= UWSGI_OK) {
                        goto end;
                }
                wsgi_req->switches++;
                // switch after each yield
		coroae_cede();
        }

end:
	uwsgi_close_request(wsgi_req);
        free_req_queue;
        XSRETURN(0);
}

XS(XS_coroae_acceptor) {
        dXSARGS;
	psgi_check_args(0);

	struct uwsgi_socket *uwsgi_sock = (struct uwsgi_socket *) XSANY.any_ptr;

	struct wsgi_request *wsgi_req = NULL;
edge:
        wsgi_req = find_first_available_wsgi_req();

        if (wsgi_req == NULL) {
                uwsgi_log("async queue is full !!!\n");
                goto clear;
        }

        // fill wsgi_request structure
        wsgi_req_setup(wsgi_req, wsgi_req->async_id, uwsgi_sock );

        // mark core as used
        uwsgi.workers[uwsgi.mywid].cores[wsgi_req->async_id].in_request = 1;

        wsgi_req->start_of_request = uwsgi_micros();
        wsgi_req->start_of_request_in_sec = wsgi_req->start_of_request/1000000;

        // enter harakiri mode
        if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0) {
                set_harakiri(uwsgi.shared->options[UWSGI_OPTION_HARAKIRI]);
        }

	// accept the connection
        if (wsgi_req_simple_accept(wsgi_req, uwsgi_sock->fd)) {
                free_req_queue;
                if (uwsgi_sock->retry && uwsgi_sock->retry[wsgi_req->async_id]) {
                        goto edge;
                }
                goto clear;
        }

// on linux we need to set the socket in non-blocking as it is not inherited
#ifdef __linux__
        uwsgi_socket_nb(wsgi_req->poll.fd);
#endif

	// here we spawn an async {} block
	CV *async_xs_call = newXS(NULL, XS_coroae_accept_request, "uwsgi::coroae");
	CvXSUBANY(async_xs_call).any_ptr = wsgi_req;
	SV *coro_req = coroae_coro_new(async_xs_call);
	coro_ready(coro_req);

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


static SV *coroae_add_watcher(int fd, SV *cb) {

        SV *newobj;

        dSP;

        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        XPUSHs(sv_2mortal(newSVpv( "AnyEvent", 8)));
        XPUSHs(sv_2mortal(newSVpv( "fh", 2)));
        XPUSHs(sv_2mortal(newSViv(fd)));
        XPUSHs(sv_2mortal(newSVpv( "poll", 4)));
        XPUSHs(sv_2mortal(newSVpv( "r", 1)));
        XPUSHs(sv_2mortal(newSVpv( "cb", 2)));
        XPUSHs(newRV_inc(cb));
        PUTBACK;

        call_method( "io", G_SCALAR);

        SPAGAIN;
	if(SvTRUE(ERRSV)) {
                uwsgi_log("[uwsgi-perl error] %s\n", SvPV_nolen(ERRSV));
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

static SV *coroae_condvar_new() {
	
	SV *newobj;

        dSP;

        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        XPUSHs(sv_2mortal(newSVpv( "AnyEvent", 8)));
        PUTBACK;

        call_method( "condvar", G_SCALAR);

        SPAGAIN;
        if(SvTRUE(ERRSV)) {
                uwsgi_log("[uwsgi-perl error] %s\n", SvPV_nolen(ERRSV));
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

static void coroae_wait_condvar(SV *cv) {
	dSP;

        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        XPUSHs(cv);
        PUTBACK;

        call_method( "recv", G_DISCARD);

        SPAGAIN;
        if(SvTRUE(ERRSV)) {
                uwsgi_log("[uwsgi-perl error] %s\n", SvPV_nolen(ERRSV));
        }
        PUTBACK;
        FREETMPS;
        LEAVE;
}


static void coroae_loop() {

	if (uwsgi.async < 2) {
		if (uwsgi.mywid == 1) {
			uwsgi_log("the Coro::AnyEvent loop engine requires async mode (--async <n>)\n");
		}
                exit(1);
	}

	perl_eval_pv("use Coro;", 0);
        if (SvTRUE(ERRSV)) {
		uwsgi_log("unable to load Coro module\n");
		exit(1);
	}
	perl_eval_pv("use AnyEvent;", 0);
        if (SvTRUE(ERRSV)) {
		uwsgi_log("unable to load AnyEvent module\n");
		exit(1);
	}
	perl_eval_pv("use Coro::AnyEvent;", 0);
        if (SvTRUE(ERRSV)) {
		uwsgi_log("unable to load Coro::AnyEvent module\n");
		exit(1);
	}

	struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;
	while(uwsgi_sock) {
		uwsgi_log("sock = %p\n", uwsgi_sock);
		// check return value here
		coroae_add_watcher(uwsgi_sock->fd, (SV *) coroae_closure_acceptor(uwsgi_sock));
		uwsgi_sock = uwsgi_sock->next;
	};

	SV *condvar = coroae_condvar_new();
	uwsgi_log("condvar = %p\n", condvar);
	coroae_wait_condvar(condvar);

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
	//.options = coroae_options,
	.on_load = coroae_init,
};
