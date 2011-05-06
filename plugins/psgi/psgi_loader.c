#include "psgi.h" 

extern struct uwsgi_server uwsgi;
struct uwsgi_perl uperl;



XS(XS_input_seek) {

        dXSARGS;

        psgi_check_args(1);
        XSRETURN(0);
}

XS(XS_error) {
	dXSARGS;

        psgi_check_args(0);

        ST(0) = sv_bless(newRV(sv_newmortal()), uperl.error_stash);
        XSRETURN(1);
}

XS(XS_input) {

        dXSARGS;
        psgi_check_args(0);

        ST(0) = sv_bless(newRV(sv_newmortal()), uperl.input_stash);
        XSRETURN(1);
}

XS(XS_stream)
{
    dXSARGS;
    struct wsgi_request *wsgi_req = current_wsgi_req();

    psgi_check_args(1);

    AV *response = (AV* ) SvREFCNT_inc(SvRV(ST(0))) ;

	if (av_len(response) == 2) {

#ifdef my_perl
		while (psgi_response(wsgi_req, my_perl, response) != UWSGI_OK);
#else
		while (psgi_response(wsgi_req, uperl.main, response) != UWSGI_OK);
#endif
	}
	else if (av_len(response) == 1) {
#ifdef my_perl
		while (psgi_response(wsgi_req, my_perl, response) != UWSGI_OK);
#else
		while (psgi_response(wsgi_req, uperl.main, response) != UWSGI_OK);
#endif
		SvREFCNT_dec(response);
                ST(0) = sv_bless(newRV(sv_newmortal()), uperl.streaming_stash);
                XSRETURN(1);
	}
	else {
		uwsgi_log("invalid PSGI response: array size %d\n", av_len(response));
	}

	SvREFCNT_dec(response);
	XSRETURN(0);

}


XS(XS_input_read) {

        dXSARGS;
        struct wsgi_request *wsgi_req = current_wsgi_req();
        int fd = -1;
        char *tmp_buf;
        ssize_t bytes = 0, len;
        size_t remains;
        SV *read_buf;

        psgi_check_args(3);


        read_buf = ST(1);
        len = SvIV(ST(2));

        // return empty string if no post_cl or pos >= post_cl
        if (!wsgi_req->post_cl || (size_t) wsgi_req->post_pos >= wsgi_req->post_cl) {
                sv_setpvn(read_buf, "", 0);
                goto ret;
        }

        if (wsgi_req->body_as_file) {
                fd = fileno((FILE *)wsgi_req->async_post);
        }
        else if (uwsgi.post_buffering > 0) {
                fd = -1;
                if (wsgi_req->post_cl <= (size_t) uwsgi.post_buffering) {
                        fd = fileno((FILE *)wsgi_req->async_post);
                }
        }
        else {
                fd = wsgi_req->poll.fd;
        }
        // return the whole input
        if (len <= 0) {
                remains = wsgi_req->post_cl;
        }
        else {
                remains = len ;
        }

        if (remains + wsgi_req->post_pos > wsgi_req->post_cl) {
                remains = wsgi_req->post_cl - wsgi_req->post_pos;
        }

        if (remains <= 0) {
                sv_setpvn(read_buf, "", 0);
                goto ret;
        }

        // data in memory ?
        if (fd == -1) {
                sv_setpvn(read_buf, wsgi_req->post_buffering_buf, remains);
                bytes = remains;
                wsgi_req->post_pos += remains;

        }

        tmp_buf = uwsgi_malloc(remains);

        if (uwsgi_waitfd(fd, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]) <= 0) {
                free(tmp_buf);
                croak("error waiting for wsgi.input data");
                goto ret;
        }

        bytes = read(fd, tmp_buf, remains);
        if (bytes < 0) {
                free(tmp_buf);
                croak("error reading wsgi.input data");
                goto ret;
        }

        wsgi_req->post_pos += bytes;
        sv_setpvn(read_buf, tmp_buf, bytes);

        free(tmp_buf);

ret:
        XSRETURN_IV(bytes);
}


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

XS(XS_error_print) {

	dXSARGS;
        STRLEN blen;
        char *body;

        psgi_check_args(1);

	if (items > 1) {
        	body = SvPV(ST(1), blen);
		uwsgi_log("%.*s", blen, body);
	}

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

        newXS("uwsgi::input::new", XS_input, "uwsgi::input");
        newXS("uwsgi::input::read", XS_input_read, "uwsgi::input");
        newXS("uwsgi::input::seek", XS_input_seek, "uwsgi::input");

        uperl.input_stash = gv_stashpv("uwsgi::input", 0);

        newXS("uwsgi::error::new", XS_error, "uwsgi::error");
        newXS("uwsgi::error::print", XS_error_print, "uwsgi::print");
        uperl.error_stash = gv_stashpv("uwsgi::error", 0);

        uperl.stream_responder = newXS("uwsgi::stream", XS_stream, "uwsgi");

        newXS("uwsgi::streaming::write", XS_streaming_write, "uwsgi::streaming");
        newXS("uwsgi::streaming::close", XS_streaming_close, "uwsgi::streaming");

        uperl.streaming_stash = gv_stashpv("uwsgi::streaming", 0);

#ifdef UWSGI_EMBEDDED
        init_perl_embedded_module();
#endif

}

/* end of automagically generated part */


void uwsgi_psgi_app() {

        struct stat stat_psgi;

        if (uperl.psgi) {

                // two-pass loading: parse the script -> eval the script



                if (uperl.locallib) {
                        uwsgi_log("using %s as local::lib directory\n", uperl.locallib);
                        uperl.embedding[1] = uwsgi_concat2("-Mlocal::lib=", uperl.locallib);
                        uperl.embedding[2] = uperl.psgi;
                        if (perl_parse(uperl.main, xs_init, 3, uperl.embedding, NULL)) {
                                exit(1);
                        }
                }
                else {
                        uperl.embedding[1] = uperl.psgi;
                        if (perl_parse(uperl.main, xs_init, 2, uperl.embedding, NULL)) {
                                exit(1);
                        }
                }

                perl_eval_pv("use IO::Handle;", 0);
                perl_eval_pv("use IO::File;", 0);

                SV *dollar_zero = get_sv("0", GV_ADD);
                sv_setsv(dollar_zero, newSVpv(uperl.psgi, 0));

                SV *dollar_slash = get_sv("/", GV_ADD);
                sv_setsv(dollar_slash, newRV_inc(newSViv(uwsgi.buffer_size)));

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
                        uperl.psgi_main = perl_eval_pv(uwsgi_concat4("#line 1 ", uperl.psgi, "\n", uperl.psgibuffer), 0);
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

