#include "psgi.h"

extern struct uwsgi_server uwsgi;

int psgi_response(struct wsgi_request *wsgi_req, AV *response) {

	SV **status_code, **hitem ;
	AV *headers, *body =NULL;
	STRLEN hlen, hlen2;
	int i;
	char *chitem, *chitem2;
	SV **harakiri;

	if (wsgi_req->async_force_again) {

		wsgi_req->async_force_again = 0;

		wsgi_req->switches++;
                SV *chunk = uwsgi_perl_obj_call(wsgi_req->async_placeholder, "getline");
		if (!chunk) {
			uwsgi_500(wsgi_req);
			return UWSGI_OK;
		}

                chitem = SvPV( chunk, hlen);

                if (hlen <= 0) {
			SvREFCNT_dec(chunk);
			if (wsgi_req->async_force_again) {
				return UWSGI_AGAIN;
			}
			SV *closed = uwsgi_perl_obj_call(wsgi_req->async_placeholder, "close");
                	if (closed) {
                        	SvREFCNT_dec(closed);
                	}

			// check for psgix.harakiri
        		harakiri = hv_fetch((HV*)SvRV( (SV*)wsgi_req->async_environ), "psgix.harakiri.commit", 21, 0);
        		if (harakiri) {
                		if (SvTRUE(*harakiri)) wsgi_req->async_plagued = 1;
        		}

        		SvREFCNT_dec(wsgi_req->async_result);

			return UWSGI_OK;
                }

		uwsgi_response_write_body_do(wsgi_req, chitem, hlen);
		uwsgi_pl_check_write_errors {
			SvREFCNT_dec(chunk);
			return UWSGI_OK;
		}
		SvREFCNT_dec(chunk);
		wsgi_req->async_force_again = 1;
		return UWSGI_AGAIN;
	}

	if (SvTYPE(response) != SVt_PVAV) {
		uwsgi_log("invalid PSGI response type\n");
		return UWSGI_OK;
	}

	if (av_len(response) == -1) {
		// deliberately empty response
		wsgi_req->status = 101;
		// don't actually close socket, it must be closed by application itself
		wsgi_req->fd_closed = 1;
		return UWSGI_OK;
	}

	status_code = av_fetch(response, 0, 0);
	if (!status_code) { uwsgi_log("invalid PSGI status code\n"); return UWSGI_OK;}

	char *status_str = SvPV(*status_code, hlen);
	if (uwsgi_response_prepare_headers(wsgi_req, status_str, hlen)) return UWSGI_OK;


        hitem = av_fetch(response, 1, 0);
	if (!hitem || !SvRV(*hitem) || SvTYPE(SvRV(*hitem)) != SVt_PVAV) { uwsgi_log("invalid PSGI headers\n"); return UWSGI_OK;}

        headers = (AV *) SvRV(*hitem);
	if (!headers) { uwsgi_log("invalid PSGI headers\n"); return UWSGI_OK;}

        // generate headers
	int headers_len = (int) av_len(headers);
        for(i=0; i<=headers_len; i++) {
                hitem = av_fetch(headers,i,0);
		if (!*hitem) {
			uwsgi_log("invalid PSGI headers\n"); return UWSGI_OK;
		}
                chitem = SvPV(*hitem, hlen);
		if (i+1 > headers_len) {
			uwsgi_log("invalid PSGI headers\n"); return UWSGI_OK;
		}
                hitem = av_fetch(headers,i+1,0);
		if (!*hitem) {
			uwsgi_log("invalid PSGI headers\n"); return UWSGI_OK;
		}
                chitem2 = SvPV(*hitem, hlen2);
		if (uwsgi_response_add_header(wsgi_req, chitem, hlen, chitem2, hlen2)) return UWSGI_OK;
		i++;
        }

        hitem = av_fetch(response, 2, 0);

	if (!hitem) {
		return UWSGI_OK;
	}

	if (!SvRV(*hitem)) { uwsgi_log("invalid PSGI response body\n") ; return UWSGI_OK; }

	if (!SvROK(*hitem)) goto unsupported;
	
        if (SvTYPE(SvRV(*hitem)) == SVt_PVGV || SvTYPE(SvRV(*hitem)) == SVt_PVHV || SvTYPE(SvRV(*hitem)) == SVt_PVMG) {

		// check for fileno() method, IO class or GvIO
		if (uwsgi_perl_obj_can(*hitem, "fileno", 6) || uwsgi_perl_obj_isa(*hitem, "IO") || (uwsgi_perl_obj_isa(*hitem, "GLOB") && GvIO(SvRV(*hitem)))  ) {
			SV *fn = uwsgi_perl_obj_call(*hitem, "fileno");
			if (fn) {
				if (SvTYPE(fn) == SVt_IV && SvIV(fn) >= 0) {
					wsgi_req->sendfile_fd = SvIV(fn);
					SvREFCNT_dec(fn);	
					uwsgi_response_sendfile_do(wsgi_req, wsgi_req->sendfile_fd, 0, 0);
					// no need to close here as perl GC will do the close()
					uwsgi_pl_check_write_errors {
						// noop
					}
					return UWSGI_OK;
				}
				SvREFCNT_dec(fn);	
			}
		}
			
		// check for path method
		if (uwsgi_perl_obj_can(*hitem, "path", 4)) {
			SV *p = uwsgi_perl_obj_call(*hitem, "path");
			int fd = open(SvPV_nolen(p), O_RDONLY);
			SvREFCNT_dec(p);	
			// the following function will close fd
			uwsgi_response_sendfile_do(wsgi_req, fd, 0, 0);
			uwsgi_pl_check_write_errors {
				// noop
			}
			return UWSGI_OK;
		}

                for(;;) {

			wsgi_req->switches++;
                        SV *chunk = uwsgi_perl_obj_call(*hitem, "getline");
			if (!chunk) {
				uwsgi_500(wsgi_req);
				break;
			}

                        chitem = SvPV( chunk, hlen);
                        if (hlen <= 0) {
				SvREFCNT_dec(chunk);
				if (uwsgi.async > 1 && wsgi_req->async_force_again) {
					wsgi_req->async_placeholder = (SV *) *hitem;
					return UWSGI_AGAIN;
				}
                                break;
                        }

			uwsgi_response_write_body_do(wsgi_req, chitem, hlen);
			uwsgi_pl_check_write_errors {
				SvREFCNT_dec(chunk);
                                break;
			}
			SvREFCNT_dec(chunk);
			if (uwsgi.async > 1) {
				wsgi_req->async_placeholder = (SV *) *hitem;
				wsgi_req->async_force_again = 1;
				return UWSGI_AGAIN;
			}
                }


		SV *closed = uwsgi_perl_obj_call(*hitem, "close");
		if (closed) {
			SvREFCNT_dec(closed);
		}

        }
        else if (SvTYPE(SvRV(*hitem)) == SVt_PVAV)  {

                body = (AV *) SvRV(*hitem);

                for(i=0; i<=av_len(body); i++) {
                        hitem = av_fetch(body,i,0);
                        chitem = SvPV(*hitem, hlen);
			uwsgi_response_write_body_do(wsgi_req, chitem, hlen);
			uwsgi_pl_check_write_errors {
				break;
			}
                }

        }
        else {
unsupported:
                uwsgi_log("unsupported response body type: %d\n", SvTYPE(SvRV(*hitem)));
        }
	
	return UWSGI_OK;

}
