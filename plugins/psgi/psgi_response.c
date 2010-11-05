#include "psgi.h"

/* statistically ordered */
struct http_status_codes hsc[] = {
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


int psgi_response(struct wsgi_request *wsgi_req, PerlInterpreter *my_perl, AV *response) {

	SV **status_code, **hitem ;
	AV *headers, *body =NULL;
	STRLEN hlen;
	struct http_status_codes *http_sc;
	int i,vi, base;
	char *chitem;
	dSP;

	status_code = av_fetch(response, 0, 0);

        wsgi_req->hvec[0].iov_base = "HTTP/1.1 ";
        wsgi_req->hvec[0].iov_len = 9;

        //uwsgi_log("setting status %d %d\n", SvTYPE(*status_code), SvIV(*status_code));

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
	
	return 1;

}
