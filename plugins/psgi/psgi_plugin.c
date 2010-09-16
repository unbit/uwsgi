#include <uwsgi.h>

#include <EXTERN.h>
#include <perl.h>

static PerlInterpreter *my_perl;
static SV *psgi_func ;

extern char **environ;

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


int uwsgi_init(struct uwsgi_server *uwsgi, char *args){

	char *psgibuffer ;
	int fd ;

	struct stat stat_psgi;

	struct http_status_codes *http_sc ;

	int argc = 4 ;
	char *embedding[] = { "", args,  "-e", "0" };
	char **argv = embedding ;

	uwsgi_log("initializing Perl environment: %s\n", args);

	PERL_SYS_INIT3(&argc, &argv, &environ);
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


	PL_origalen = 1;
	perl_parse(my_perl, xs_init, 4, embedding, NULL);

	perl_eval_pv("use IO::Handle;", 0);

	fd = open(args, O_RDONLY);
	if (fd < 0) {
		uwsgi_error("open()");
		goto clear ;
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

	psgibuffer[stat_psgi.st_size] = 0 ;

	psgi_func = perl_eval_pv(psgibuffer, 0);

	if (!psgi_func) {
		uwsgi_log("unable to find PSGI function entry point.\n");
		close(fd);
		free(psgibuffer);
		goto clear;
	}

	free(psgibuffer);
	close(fd);

	return 0;

clear:
	perl_destruct(my_perl);
        perl_free(my_perl);
	return -1;

}

int uwsgi_request(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {
	
	HV *env ;
	SV **item ;
	
	AV *response, *headers, *body ;

	SV **status_code, **hitem, *io_new, *io_err, *io, *chunk;
	char *chitem ;
	STRLEN hlen ;

	struct http_status_codes *http_sc;

	int i,vi, base ;

	/* Standard PSGI request */
        if (!wsgi_req->uh.pktsize) {
                uwsgi_log("Invalid PSGI request. skip.\n");
                return -1;
        }


	if (uwsgi_parse_vars(uwsgi, wsgi_req)) {
		uwsgi_log("Invalid PSGI request. skip.\n");
		return -1;
	}


	dSP;

	ENTER;
	SAVETMPS;


	env = (HV*)sv_2mortal((SV*)newHV());

	// fill perl hash
	for(i=0;i<wsgi_req->var_cnt;i++) {
		if (wsgi_req->hvec[i+1].iov_len > 0) {
		
		item = hv_store(env, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len, 
			newSVpv(wsgi_req->hvec[i+1].iov_base, wsgi_req->hvec[i+1].iov_len), 0);
		}
		else {
			item = hv_store(env, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len, newSVpv("", 0), 0);
		}
		i++;
	}

	item = hv_store(env, "psgi.url_scheme", 15, newSVpv("http", 4), 0);


	PUSHMARK(SP);
	XPUSHs( sv_2mortal( newSVpv( "IO::Handle", 10 )));
	PUTBACK;
	perl_call_method( "new", G_SCALAR);
	SPAGAIN;
	io_new = newSVsv(POPs);


	PUSHMARK(SP);
	XPUSHs( sv_2mortal(io_new) );
	XPUSHs( sv_2mortal( newSViv( wsgi_req->poll.fd)));
	XPUSHs( sv_2mortal( newSVpv( "r", 1)));
	PUTBACK;
	perl_call_method( "fdopen", G_SCALAR);
	SPAGAIN;


	item = hv_store(env, "psgi.input", 10, newSVsv(POPs), 0);

	PUSHMARK(SP);
	XPUSHs( sv_2mortal( newSVpv( "IO::Handle", 10 )));
	PUTBACK;
	perl_call_method( "new", G_SCALAR);
	SPAGAIN;
	io_err = newSVsv(POPs);

	PUSHMARK(SP);
	XPUSHs( sv_2mortal(io_err) );
	XPUSHs( sv_2mortal( newSViv( 2 )));
	XPUSHs( sv_2mortal( newSVpv( "w", 1)));
	PUTBACK;
	perl_call_method( "fdopen", G_SCALAR);
	SPAGAIN;


	item = hv_store(env, "psgi.errors", 11, newSVsv(POPs), 0);


	PUSHMARK(SP);
	XPUSHs( sv_2mortal(newRV((SV *)env )) );
	PUTBACK;


	perl_call_sv(psgi_func, G_SCALAR);
	SPAGAIN;

	// dereference output
	response = (AV *) SvRV( sv_2mortal(newSVsv(POPs)) ) ;

	status_code = av_fetch(response, 0, 0);

	wsgi_req->hvec[0].iov_base = "HTTP/1.1 ";
	wsgi_req->hvec[0].iov_len = 9 ;

	wsgi_req->hvec[1].iov_base = SvPV(*status_code, hlen);
	wsgi_req->hvec[1].iov_len = 3 ;

	wsgi_req->hvec[2].iov_base = " ";
	wsgi_req->hvec[2].iov_len = 1 ;

	wsgi_req->hvec[3].iov_len = 0 ;

	// get the status code
	for (http_sc = hsc; http_sc->message != NULL; http_sc++) {
		if (!strncmp(http_sc->key, wsgi_req->hvec[1].iov_base, 3)) {
			wsgi_req->hvec[3].iov_base = http_sc->message ;
			wsgi_req->hvec[3].iov_len = http_sc->message_size ;
			break;
		}
        }

	if (wsgi_req->hvec[3].iov_len == 0) {
		wsgi_req->hvec[3].iov_base = "Unknown" ;
		wsgi_req->hvec[3].iov_len =  7;
	}

	wsgi_req->hvec[4].iov_base = "\r\n";
	wsgi_req->hvec[4].iov_len = 2 ;
	
	hitem = av_fetch(response, 1, 0) ;

	headers = (AV *) SvRV(*hitem);

	base = 5 ;

	// put them in hvec
	for(i=0; i<=av_len(headers); i++) {

		vi = (i*2)+base ;
		hitem = av_fetch(headers,i,0);
		chitem = SvPV(*hitem, hlen);
		wsgi_req->hvec[vi].iov_base = chitem ; wsgi_req->hvec[vi].iov_len = hlen ;

		wsgi_req->hvec[vi+1].iov_base = ": " ; wsgi_req->hvec[vi+1].iov_len = 2 ;

		hitem = av_fetch(headers,i+1,0);
		chitem = SvPV(*hitem, hlen);
		wsgi_req->hvec[vi+2].iov_base = chitem ; wsgi_req->hvec[vi+2].iov_len = hlen ;

		wsgi_req->hvec[vi+3].iov_base = "\r\n" ; wsgi_req->hvec[vi+3].iov_len = 2 ;

		i++;
	}

	vi = (i*2)+base ;
	wsgi_req->hvec[vi].iov_base = "\r\n" ; wsgi_req->hvec[vi].iov_len = 2 ;


	if ( !(wsgi_req->response_size = writev(wsgi_req->poll.fd, wsgi_req->hvec, vi+1)) ) {
		uwsgi_error("writev()");
	}


	hitem = av_fetch(response, 2, 0) ;

	io = *hitem;
	
	if (SvTYPE(SvRV(io)) == SVt_PVGV || SvTYPE(SvRV(io)) == SVt_PVHV) {

		for(;;) {

			PUSHMARK(SP);
			XPUSHs(io) ;
			PUTBACK;
			perl_call_method("getline", G_SCALAR);	
			SPAGAIN;
			chunk = sv_2mortal(newSVsv(POPs));

			chitem = SvPV(chunk, hlen);
			if (hlen <= 0) {
				break;
			}
			wsgi_req->response_size += write(wsgi_req->poll.fd, chitem, hlen);
		}


	}
	else if (SvTYPE(SvRV(io)) == SVt_PVAV)  {

		body = (AV *) SvRV(io);

		for(i=0; i<=av_len(body); i++) {
			hitem = av_fetch(body,i,0);
			chitem = SvPV(*hitem, hlen);
			wsgi_req->response_size += write(wsgi_req->poll.fd, chitem, hlen);
		}

	}
	else {
		uwsgi_log("unsupported response body type: %d\n", SvTYPE(SvRV(io)));
	}
	
	FREETMPS;
	LEAVE;

	return 0;
}


void uwsgi_after_request(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {

	if (uwsgi->shared->options[UWSGI_OPTION_LOGGING])
                log_request(wsgi_req);
}
