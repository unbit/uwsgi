#include "uwsgi_python.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_python up;

static char *nl = "\r\n";
static char *h_sep = ": ";
static const char *http_protocol = "HTTP/1.1";

// check here

PyObject *py_uwsgi_spit(PyObject * self, PyObject * args) {
	PyObject *headers, *head;
	PyObject *h_key, *h_value;
	int i, j;
	PyObject *exc_info = NULL;

	struct wsgi_request *wsgi_req = current_wsgi_req();

	int base = 0;

	// avoid double sending of headers
	if (wsgi_req->headers_sent) {
		return PyErr_Format(PyExc_IOError, "headers already sent");
	}

	// decref old status line
	if (wsgi_req->status_header) {
		Py_DECREF((PyObject *)wsgi_req->status_header);
		wsgi_req->status_header = NULL;
	}

	if (wsgi_req->headers) {
		Py_DECREF((PyObject *)wsgi_req->headers);
		wsgi_req->headers = NULL;
	}

#ifdef PYTHREE
	if (wsgi_req->gc_tracker) {
		Py_DECREF((PyObject *)wsgi_req->gc_tracker);
		wsgi_req->gc_tracker = NULL;
	}
#endif

	// this must be done before headers management
	if (PyTuple_Size(args) > 2) {
		exc_info = PyTuple_GetItem(args, 2);
		if (exc_info && exc_info != Py_None) {
			PyObject *exc_type = PyTuple_GetItem(exc_info, 0);	
			PyObject *exc_val = PyTuple_GetItem(exc_info, 1);
			PyObject *exc_tb = PyTuple_GetItem(exc_info, 2);

			if (!exc_type || !exc_val || !exc_tb) {
				return NULL;
			}

			Py_INCREF(exc_type);
			Py_INCREF(exc_val);
			Py_INCREF(exc_tb);
			// in this way, error will be reported to the log
			PyErr_Restore(exc_type, exc_val, exc_tb);

			// the error is reported, let's continue...
			// return NULL
		}
	}

	head = PyTuple_GetItem(args, 0);
	if (!head) {
		return PyErr_Format(PyExc_TypeError, "start_response() takes at least 2 arguments");
	}

#ifdef PYTHREE
	// check for web3
        if ((self != Py_None && !PyUnicode_Check(head)) || (self == Py_None && !PyBytes_Check(head))) {
#else
	if (!PyString_Check(head)) {
#endif
		return PyErr_Format(PyExc_TypeError, "http status must be a string");
	}

#ifdef PYTHREE
	// this list maintains reference to encoded strings.. ugly hack, i know, but it works...
	wsgi_req->gc_tracker = (void *) PyList_New(0);
#endif

	if (uwsgi.shared->options[UWSGI_OPTION_CGI_MODE] == 0) {
		base = 4;

		if (wsgi_req->protocol_len == 0) {
			wsgi_req->hvec[0].iov_base = (char *) http_protocol;
			wsgi_req->protocol_len = 8;
		}
		else {
			wsgi_req->hvec[0].iov_base = wsgi_req->protocol;
		}

		wsgi_req->hvec[0].iov_len = wsgi_req->protocol_len;
		wsgi_req->hvec[1].iov_base = " ";
		wsgi_req->hvec[1].iov_len = 1;
#ifdef PYTHREE
		if (self != Py_None) {
			PyObject *zero = PyUnicode_AsASCIIString(head);
			wsgi_req->hvec[2].iov_base = PyBytes_AsString(zero);
			PyList_Append((PyObject *) wsgi_req->gc_tracker, zero);
			Py_DECREF(zero);
		}
		else {
			wsgi_req->hvec[2].iov_base = PyBytes_AsString(head);
		}
		wsgi_req->hvec[2].iov_len = strlen(wsgi_req->hvec[2].iov_base);
#else
		wsgi_req->hvec[2].iov_base = PyString_AsString(head);
		wsgi_req->hvec[2].iov_len = PyString_Size(head);
#endif
		wsgi_req->status = uwsgi_str3_num(wsgi_req->hvec[2].iov_base);
		wsgi_req->hvec[3].iov_base = nl;
		wsgi_req->hvec[3].iov_len = NL_SIZE;
	}
	else {
		// drop http status on cgi mode
		base = 3;
		wsgi_req->hvec[0].iov_base = "Status: ";
		wsgi_req->hvec[0].iov_len = 8;
#ifdef PYTHREE
		if (self != Py_None) {
			PyObject *zero = PyUnicode_AsASCIIString(head);
			wsgi_req->hvec[1].iov_base = PyBytes_AsString(zero);
			PyList_Append((PyObject *) wsgi_req->gc_tracker, zero);
                        Py_DECREF(zero);
		}
		else {
			wsgi_req->hvec[1].iov_base = PyBytes_AsString(head);
		}
		wsgi_req->hvec[1].iov_len = strlen(wsgi_req->hvec[1].iov_base);
#else
		wsgi_req->hvec[1].iov_base = PyString_AsString(head);
		wsgi_req->hvec[1].iov_len = PyString_Size(head);
#endif
		wsgi_req->status = uwsgi_str3_num(wsgi_req->hvec[1].iov_base);
		wsgi_req->hvec[2].iov_base = nl;
		wsgi_req->hvec[2].iov_len = NL_SIZE;
	}

	// incref status line
	wsgi_req->status_header = head;
	Py_INCREF((PyObject *)wsgi_req->status_header);

	headers = PyTuple_GetItem(args, 1);
	if (!headers) {
		return PyErr_Format(PyExc_TypeError, "start_response() takes at least 2 arguments");
	}

	wsgi_req->headers = headers;
	Py_INCREF((PyObject *)wsgi_req->headers);

	if (!PyList_Check(headers)) {
		return PyErr_Format(PyExc_TypeError, "http headers must be in a python list");
	}
	wsgi_req->header_cnt = PyList_Size(headers);

	if (wsgi_req->header_cnt > uwsgi.max_vars) {
		wsgi_req->header_cnt = uwsgi.max_vars;
	}
	for (i = 0; i < wsgi_req->header_cnt; i++) {
		j = (i * 4) + base;
		head = PyList_GetItem(headers, i);
		if (!head) {
			return NULL;
		}
		if (!PyTuple_Check(head)) {
			return PyErr_Format(PyExc_TypeError, "http header must be defined in a tuple");
		}
		h_key = PyTuple_GetItem(head, 0);
		if (!h_key) {
			return PyErr_Format(PyExc_TypeError, "http header must be a 2-item tuple");
		}
#ifdef PYTHREE
		if ((self != Py_None && !PyUnicode_Check(h_key)) || (self == Py_None && !PyBytes_Check(h_key))) {
#else
        	if (!PyString_Check(h_key)) {
#endif
			return PyErr_Format(PyExc_TypeError, "http header key must be a string");
		}
		h_value = PyTuple_GetItem(head, 1);
		if (!h_value) {
			return PyErr_Format(PyExc_TypeError, "http header must be a 2-item tuple");
		}
#ifdef PYTHREE
		if ((self != Py_None && !PyUnicode_Check(h_value)) || (self == Py_None && !PyBytes_Check(h_value))) {
#else
        	if (!PyString_Check(h_value)) {
#endif
			return PyErr_Format(PyExc_TypeError, "http header value must be a string");
		}

		

#ifdef PYTHREE
		if (self != Py_None) {
			PyObject *zero = PyUnicode_AsASCIIString(h_key);
			wsgi_req->hvec[j].iov_base = PyBytes_AsString(zero);
			PyList_Append((PyObject *) wsgi_req->gc_tracker, zero);
                        Py_DECREF(zero);
		}
		else {
			wsgi_req->hvec[j].iov_base = PyBytes_AsString(h_key);
		}
		wsgi_req->hvec[j].iov_len = strlen(wsgi_req->hvec[j].iov_base);
#else
		wsgi_req->hvec[j].iov_base = PyString_AsString(h_key);
		wsgi_req->hvec[j].iov_len = PyString_Size(h_key);
#endif
		wsgi_req->hvec[j + 1].iov_base = h_sep;
		wsgi_req->hvec[j + 1].iov_len = H_SEP_SIZE;
#ifdef PYTHREE
		if (self != Py_None) {
			PyObject *zero = PyUnicode_AsASCIIString(h_value);
			wsgi_req->hvec[j + 2].iov_base = PyBytes_AsString(zero);
			PyList_Append((PyObject *) wsgi_req->gc_tracker, zero);
                        Py_DECREF(zero);
		}
		else {
			wsgi_req->hvec[j + 2].iov_base = PyBytes_AsString(h_value);
		}
		wsgi_req->hvec[j + 2].iov_len = strlen(wsgi_req->hvec[j + 2].iov_base);
#else
		wsgi_req->hvec[j + 2].iov_base = PyString_AsString(h_value);
		wsgi_req->hvec[j + 2].iov_len = PyString_Size(h_value);
#endif


		wsgi_req->hvec[j + 3].iov_base = nl;
		wsgi_req->hvec[j + 3].iov_len = NL_SIZE;

		//uwsgi_log( "%.*s: %.*s\n", wsgi_req->hvec[j].iov_len, (char *)wsgi_req->hvec[j].iov_base, wsgi_req->hvec[j+2].iov_len, (char *) wsgi_req->hvec[j+2].iov_base);
	}

	j = (i * 4) + base;

	struct uwsgi_string_list *ah = uwsgi.additional_headers;
	while(ah) {
		if (wsgi_req->header_cnt+1 <= uwsgi.max_vars) {
			wsgi_req->header_cnt++;
			wsgi_req->hvec[j].iov_base = ah->value;
        		wsgi_req->hvec[j].iov_len = ah->len;
			j++;
			wsgi_req->hvec[j].iov_base = nl;
        		wsgi_req->hvec[j].iov_len = NL_SIZE;
			j++;
			ah = ah->next;
		}
		else {
			uwsgi_log("no more space in iovec. consider increasing max-vars...\n");
			break;
		}
	}


	// \r\n
	wsgi_req->hvec[j].iov_base = nl;
	wsgi_req->hvec[j].iov_len = NL_SIZE;

	wsgi_req->headers_hvec = j;

	if (up.start_response_nodelay) {
		if (uwsgi_python_do_send_headers(wsgi_req)) {
			return NULL;
		}
	}

	//uwsgi_log("%d %p\n", wsgi_req->poll.fd, up.wsgi_writeout);
	Py_INCREF(up.wsgi_writeout);
	return up.wsgi_writeout;
}

int uwsgi_python_do_send_headers(struct wsgi_request *wsgi_req) {

	if (!wsgi_req->headers_hvec) return 0;

#ifdef __sun__
        int remains = wsgi_req->headers_hvec + 1;
        int iov_size;
        struct iovec* iov_ptr = wsgi_req->hvec;
        ssize_t iov_ret;
        while(remains) {
                iov_size = UMIN(remains, IOV_MAX);
                UWSGI_RELEASE_GIL
                iov_ret = wsgi_req->socket->proto_writev_header(wsgi_req, iov_ptr, iov_size);
                UWSGI_GET_GIL
                wsgi_req->headers_size += iov_ret;
                iov_ptr += iov_size;
                remains -= iov_size;
        }
#else
        UWSGI_RELEASE_GIL
                wsgi_req->headers_size = wsgi_req->socket->proto_writev_header(wsgi_req, wsgi_req->hvec, wsgi_req->headers_hvec + 1);
        UWSGI_GET_GIL
#endif

	wsgi_req->headers_sent = 1;

	// decref status line
	if (wsgi_req->status_header) {
		Py_DECREF((PyObject *)wsgi_req->status_header);
		wsgi_req->status_header = NULL;
	}

	if (wsgi_req->headers) {
		Py_DECREF((PyObject *)wsgi_req->headers);
		wsgi_req->headers = NULL;
	}

#ifdef PYTHREE
	if (wsgi_req->gc_tracker) {
		Py_DECREF((PyObject *)wsgi_req->gc_tracker);
		wsgi_req->gc_tracker = NULL;
	}
#endif

        if (wsgi_req->write_errors > uwsgi.write_errors_tolerance && !uwsgi.disable_write_exception) {
                uwsgi_py_write_set_exception(wsgi_req);
                return -1;
        }

	return 0;

}
