#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

/*

	Exceptions management

	generally exceptions are printed in the logs, but if you enable
	an exception manager they will be stored in a (relatively big) uwsgi packet
	with the following structure.

	"vars" -> keyval of request vars
	"backtrace" -> list of backtrace lines. Each line is a list of 5 elements filename,line,function,text,custom
	"unix" -> seconds since the epoch
	"class" -> the exception class
	"msg" -> a text message mapped to the extension
	"wid" -> worker id
	"core" -> the core generating the exception
	"pid" -> pid of the worker
	"node" -> hostname

	Other vars can be added, but you cannot be sure they will be used by exceptions handler.

	The exception-uwsgi packet is passed "as is" to the exception handler

	Exceptions hooks:
	
		a request plugin can export that hooks:
	
		struct uwsgi_buffer *backtrace(struct wsgi_request *);
		struct uwsgi_buffer *exception_class(struct wsgi_request *);
		struct uwsgi_buffer *exception_msg(struct wsgi_request *);
		struct uwsgi_buffer *exception_repr(struct wsgi_request *);
		void exception_log(struct wsgi_request *);

		Remember to reset the exception status (if possibile) after each call

	Exceptions catcher:

		This is a special development-mode in which exceptions are printed
		to the HTTP client.

*/

static void append_vars_to_ubuf(char *key, uint16_t keylen, char *val, uint16_t vallen, void *data) {
	struct uwsgi_buffer *ub = (struct uwsgi_buffer *) data;

	if (uwsgi_buffer_append(ub, key, keylen)) return;
	if (uwsgi_buffer_append(ub, " = ", 3)) return;
	if (uwsgi_buffer_append(ub, val, vallen)) return;
	if (uwsgi_buffer_append(ub, "\n", 1)) return;
}

int uwsgi_exceptions_catch(struct wsgi_request *wsgi_req) {

	if (uwsgi_response_prepare_headers(wsgi_req, "500 Internal Server Error", 25)) {
		return -1;
	}

	if (uwsgi_response_add_content_type(wsgi_req, "text/plain", 10)) {
		return -1;
	}

	struct uwsgi_buffer *ub = uwsgi_buffer_new(4096);
	if (uwsgi_buffer_append(ub, "uWSGI exceptions catcher for \"", 30)) goto error;
	if (uwsgi_buffer_append(ub, wsgi_req->method, wsgi_req->method_len)) goto error;
	if (uwsgi_buffer_append(ub, " ", 1)) goto error;
	if (uwsgi_buffer_append(ub, wsgi_req->uri, wsgi_req->uri_len)) goto error;
	if (uwsgi_buffer_append(ub, "\"\n\n", 3)) goto error;

	if (uwsgi_buffer_append(ub, "Exception: ", 11)) goto error;
                
        if (uwsgi.p[wsgi_req->uh->modifier1]->exception_repr) {
                struct uwsgi_buffer *ub_exc_repr = uwsgi.p[wsgi_req->uh->modifier1]->exception_repr(wsgi_req);
                if (ub_exc_repr) {
                        if (uwsgi_buffer_append(ub, ub_exc_repr->buf, ub_exc_repr->pos)) {
                                uwsgi_buffer_destroy(ub_exc_repr);
                                goto error;
                        }
                        uwsgi_buffer_destroy(ub_exc_repr);
                }
                else {
                        goto notavail3;
                }
        }
        else {
notavail3:
                if (uwsgi_buffer_append(ub, "-Not available-", 15)) goto error;
        }

        if (uwsgi_buffer_append(ub, "\n\n", 2)) goto error;

	if (uwsgi_buffer_append(ub, "Exception class: ", 17)) goto error;

	if (uwsgi.p[wsgi_req->uh->modifier1]->exception_class) {
		struct uwsgi_buffer *ub_exc_class = uwsgi.p[wsgi_req->uh->modifier1]->exception_class(wsgi_req);
		if (ub_exc_class) {
			if (uwsgi_buffer_append(ub, ub_exc_class->buf, ub_exc_class->pos)) {
				uwsgi_buffer_destroy(ub_exc_class);
				goto error;
			}
			uwsgi_buffer_destroy(ub_exc_class);
		}
		else {
			goto notavail;
		}
	}
	else {
notavail:
		if (uwsgi_buffer_append(ub, "-Not available-", 15)) goto error;
	}

	if (uwsgi_buffer_append(ub, "\n\n", 2)) goto error;

	if (uwsgi_buffer_append(ub, "Exception message: ", 19)) goto error;

        if (uwsgi.p[wsgi_req->uh->modifier1]->exception_msg) {
                struct uwsgi_buffer *ub_exc_msg = uwsgi.p[wsgi_req->uh->modifier1]->exception_msg(wsgi_req);
                if (ub_exc_msg) {
                        if (uwsgi_buffer_append(ub, ub_exc_msg->buf, ub_exc_msg->pos)) {
                                uwsgi_buffer_destroy(ub_exc_msg);
                                goto error;
                        }
                        uwsgi_buffer_destroy(ub_exc_msg);
                }
                else {
                        goto notavail2;
                }
        }
        else {
notavail2:
                if (uwsgi_buffer_append(ub, "-Not available-", 15)) goto error;
        }

	if (uwsgi_buffer_append(ub, "\n\n", 2)) goto error;

	if (uwsgi_hooked_parse(wsgi_req->buffer, wsgi_req->uh->pktsize, append_vars_to_ubuf, ub)) {
		goto error;
	}

	if (uwsgi_response_write_body_do(wsgi_req, ub->buf, ub->pos)) {
		goto error;
	}

	uwsgi_buffer_destroy(ub);
	return 0;

error:
	uwsgi_buffer_destroy(ub);
	return -1;

}
