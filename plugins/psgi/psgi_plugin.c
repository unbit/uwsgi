#include <uwsgi.h>

#include <EXTERN.h>
#include <perl.h>

static PerlInterpreter *my_perl;
static SV *psgi_func;

#ifdef UWSGI_THREADING
pthread_key_t uwsgi_perl_interpreter;
#endif

extern char **environ;
extern struct uwsgi_server uwsgi;

struct uwsgi_perl {

	char *psgi;

} uperl;

#define LONG_ARGS_PERL_BASE      17000 + (5 * 100)
#define LONG_ARGS_PSGI           LONG_ARGS_PERL_BASE + 1

struct option uwsgi_perl_options[] = {

        {"psgi", required_argument, 0, LONG_ARGS_PSGI},
        {0, 0, 0, 0},

};


/* statistically ordered */
static struct http_status_codes hsc[] = {
	{"200", "OK"},
	{"302", "Found"},
	{"404", "Not Found"},
	{"500", "Internal Server Error"},
	{"301", "Moved Permanently"},
	{"304", "Not Modified"},
	{"303", "See Other"},
	{"403", "Forbidden"},
	{"307", "Temporary Redirect"},
	{"401", "Unauthorized"},
	{"400", "Bad Request"},
	{"405", "Method Not Allowed"},
	{"408", "Request Timeout"},

	{"100", "Continue"},
	{"101", "Switching Protocols"},
	{"201", "Created"},
	{"202", "Accepted"},
	{"203", "Non-Authoritative Information"},
	{"204", "No Content"},
	{"205", "Reset Content"},
	{"206", "Partial Content"},
	{"300", "Multiple Choices"},
	{"305", "Use Proxy"},
	{"402", "Payment Required"},
	{"406", "Not Acceptable"},
	{"407", "Proxy Authentication Required"},
	{"409", "Conflict"},
	{"410", "Gone"},
	{"411", "Length Required"},
	{"412", "Precondition Failed"},
	{"413", "Request Entity Too Large"},
	{"414", "Request-URI Too Long"},
	{"415", "Unsupported Media Type"},
	{"416", "Requested Range Not Satisfiable"},
	{"417", "Expectation Failed"},
	{"501", "Not Implemented"},
	{"502", "Bad Gateway"},
	{"503", "Service Unavailable"},
	{"504", "Gateway Timeout"},
	{"505", "HTTP Version Not Supported"},
	{ "", NULL },
};

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
}

/* end of automagically generated part */


int uwsgi_perl_init(){

	char *psgibuffer;
	int fd;

	struct stat stat_psgi;

	struct http_status_codes *http_sc;

	int argc = 4;
	char *embedding[] = { "", "-e", "-e", "0" };

	uwsgi_log("initializing Perl environment\n");
	PERL_SYS_INIT3(&argc, (char ***) &embedding, &environ);
	my_perl = perl_alloc();
	if (!my_perl) {
		uwsgi_log("unable to allocate perl interpreter\n");
		return -1;
	}

	PL_perl_destruct_level = 1;
	perl_construct(my_perl);

	// filling http status codes
	for (http_sc = hsc; http_sc->message != NULL; http_sc++) {
		http_sc->message_size = strlen(http_sc->message);
	}

#ifdef UWSGI_THREADING
	if (uwsgi.threads > 1) {
		if (pthread_key_create(&uwsgi_perl_interpreter, NULL)) {
			uwsgi_error("pthread_key_create()");
			exit(1);
		}
	}
#endif

	PL_origalen = 1;
	perl_parse(my_perl, xs_init, 4, embedding, NULL);

	perl_eval_pv("use IO::Handle;", 0);

	fd = open(uperl.psgi, O_RDONLY);
	if (fd < 0) {
		uwsgi_error("open()");
		goto clear;
	}

	if (fstat(fd, &stat_psgi)) {
		uwsgi_error("fstat()");
		close(fd);
		goto clear;
	}

	psgibuffer = malloc(stat_psgi.st_size + 1);
	if (!psgibuffer) {
		uwsgi_error("malloc()");
		close(fd);
		goto clear;
	}

	if (read(fd, psgibuffer, stat_psgi.st_size) != stat_psgi.st_size) {
		uwsgi_error("read()");
		close(fd);
		free(psgibuffer);
		goto clear;
	}

	psgibuffer[stat_psgi.st_size] = 0;

	psgi_func = perl_eval_pv(psgibuffer, 0);

	if (!psgi_func) {
		uwsgi_log("unable to find PSGI function entry point.\n");
		close(fd);
		free(psgibuffer);
		goto clear;
	}

	if(SvTRUE(ERRSV)) {
		uwsgi_log("%s\n", SvPV_nolen(ERRSV));
		goto clear;
	}

	uwsgi_log("PSGI_FUNC %p\n", psgi_func);

	free(psgibuffer);
	close(fd);

	return 0;

clear:
	uwsgi_log("error initializing the perl engine\n");
	perl_destruct(my_perl);
	perl_free(my_perl);
	return -1;

}

int uwsgi_perl_request(struct wsgi_request *wsgi_req) {

	HV *env;
	SV **item;

	AV *response, *headers, *body;

	SV **status_code, **hitem, *io_new, *io_err;
	char *chitem;
	STRLEN hlen;

	struct http_status_codes *http_sc;

	int i,vi, base;

	/* Standard PSGI request */
	if (!wsgi_req->uh.pktsize) {
		uwsgi_log("Invalid PSGI request. skip.\n");
		return -1;
	}


	if (uwsgi_parse_vars(wsgi_req)) {
		uwsgi_log("Invalid PSGI request. skip.\n");
		return -1;
	}


	dSP;

	ENTER;
	SAVETMPS;


	env = (HV*) sv_2mortal((SV*)newHV());


	// fill perl hash
	for(i=0;i<wsgi_req->var_cnt;i++) {
		if (wsgi_req->hvec[i+1].iov_len > 0) {

			item = hv_store(env, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len,
					newSVpv(wsgi_req->hvec[i+1].iov_base, wsgi_req->hvec[i+1].iov_len), 0);
		}
		else {
			item = hv_store(env, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len, newSVpv("", 0), 0);
		}
		//uwsgi_log("%.*s = %.*s\n", wsgi_req->hvec[i].iov_len, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i+1].iov_len, wsgi_req->hvec[i+1].iov_base);
		i++;
	}


	SV *us = newSVpv("http", 4);

	item = hv_store(env, "psgi.url_scheme", 15, us, 0);



	SV* iohandle = newSVpv( "IO::Handle", 10 );


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
	item = hv_store(env, "psgi.input", 10, pi, 0);




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

	item = hv_store(env, "psgi.errors", 11, pe, 0);


	PUSHMARK(SP);
	XPUSHs( sv_2mortal(newRV((SV *)env )) );
	PUTBACK;



	perl_call_sv(psgi_func, G_SCALAR);
	SPAGAIN;

	// no leaks to here

	// dereference output
	response = (AV *) SvRV( POPs );

	status_code = av_fetch(response, 0, 0);

	wsgi_req->hvec[0].iov_base = "HTTP/1.1 ";
	wsgi_req->hvec[0].iov_len = 9;

	wsgi_req->hvec[1].iov_base = SvPV(*status_code, hlen);
	wsgi_req->hvec[1].iov_len = 3;

	wsgi_req->status = atoi(wsgi_req->hvec[1].iov_base);

	wsgi_req->hvec[2].iov_base = " ";
	wsgi_req->hvec[2].iov_len = 1;

	wsgi_req->hvec[3].iov_len = 0;

	// get the status code
	for (http_sc = hsc; http_sc->message != NULL; http_sc++) {
		if (!strncmp(http_sc->key, wsgi_req->hvec[1].iov_base, 3)) {
			wsgi_req->hvec[3].iov_base = (char *) http_sc->message;
			wsgi_req->hvec[3].iov_len = http_sc->message_size;
			break;
		}
	}

	if (wsgi_req->hvec[3].iov_len == 0) {
		wsgi_req->hvec[3].iov_base = "Unknown";
		wsgi_req->hvec[3].iov_len =  7;
	}

	wsgi_req->hvec[4].iov_base = "\r\n";
	wsgi_req->hvec[4].iov_len = 2;

	hitem = av_fetch(response, 1, 0);

	headers = (AV *) SvRV(*hitem);

	base = 5;


	// put them in hvec
	for(i=0; i<=av_len(headers); i++) {

		vi = (i*2)+base;
		hitem = av_fetch(headers,i,0);
		chitem = SvPV(*hitem, hlen);
		wsgi_req->hvec[vi].iov_base = chitem; wsgi_req->hvec[vi].iov_len = hlen;

		wsgi_req->hvec[vi+1].iov_base = ": "; wsgi_req->hvec[vi+1].iov_len = 2;

		hitem = av_fetch(headers,i+1,0);
		chitem = SvPV(*hitem, hlen);
		wsgi_req->hvec[vi+2].iov_base = chitem; wsgi_req->hvec[vi+2].iov_len = hlen;

		wsgi_req->hvec[vi+3].iov_base = "\r\n"; wsgi_req->hvec[vi+3].iov_len = 2;

		wsgi_req->header_cnt++;

		i++;
	}


	vi = (i*2)+base;
	wsgi_req->hvec[vi].iov_base = "\r\n"; wsgi_req->hvec[vi].iov_len = 2;

	if ( !(wsgi_req->headers_size = writev(wsgi_req->poll.fd, wsgi_req->hvec, vi+1)) ) {
		uwsgi_error("writev()");
	}



	hitem = av_fetch(response, 2, 0);


	if (SvTYPE(SvRV(*hitem)) == SVt_PVGV || SvTYPE(SvRV(*hitem)) == SVt_PVHV) {

		for(;;) {
			PUSHMARK(SP);
			XPUSHs(*hitem);
			PUTBACK;
			perl_call_method("getline", G_SCALAR);
			SPAGAIN;

			if(SvTRUE(ERRSV)) {
				uwsgi_log("%s\n", SvPV_nolen(ERRSV));
				break;
			}

			SV *chunk = POPs;
			chitem = SvPV( chunk, hlen);
			if (hlen <= 0) {
				break;
			}
			wsgi_req->response_size = write(wsgi_req->poll.fd, chitem, hlen);
		}


	}
	else if (SvTYPE(SvRV(*hitem)) == SVt_PVAV)  {

		body = (AV *) SvRV(*hitem);

		for(i=0; i<=av_len(body); i++) {
			hitem = av_fetch(body,i,0);
			chitem = SvPV(*hitem, hlen);
			wsgi_req->response_size = write(wsgi_req->poll.fd, chitem, hlen);
		}

	}
	else {
		uwsgi_log("unsupported response body type: %d\n", SvTYPE(SvRV(*hitem)));
	}


	FREETMPS;
	LEAVE;

	return 0;
}


void uwsgi_perl_after_request(struct wsgi_request *wsgi_req) {

	if (uwsgi.shared->options[UWSGI_OPTION_LOGGING])
		log_request(wsgi_req);
}

void uwsgi_perl_init_thread() {
}

int uwsgi_perl_manage_options(int i, char *optarg) {

        switch(i) {
                case LONG_ARGS_PSGI:
                        uperl.psgi = optarg;
                        return 1;
        }

        return 0;
}


struct uwsgi_plugin psgi_plugin = {

	.name = "psgi",
	.modifier1 = 5,
	.init = uwsgi_perl_init,
	.options = uwsgi_perl_options,
	//.magic = uwsgi_perl_magic,
	//.help = uwsgi_perl_help,
	.manage_opt = uwsgi_perl_manage_options,
	.init_thread = uwsgi_perl_init_thread,
	.request = uwsgi_perl_request,
	.after_request = uwsgi_perl_after_request,
};
