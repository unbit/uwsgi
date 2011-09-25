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

	// this must be done before headers management
	if (PyTuple_Size(args) > 2) {
		exc_info = PyTuple_GetItem(args, 2);
		if (exc_info && exc_info != Py_None) {
			PyObject *exc_type = PyTuple_GetItem(exc_info, 0);	
			PyObject *exc_val = PyTuple_GetItem(exc_info, 1);
			PyObject *exc_tb = PyTuple_GetItem(exc_info, 2);

			if (!exc_type || !exc_val || !exc_tb) {
				PyErr_Print();
				goto clear;
			}

			Py_INCREF(exc_type);
			Py_INCREF(exc_val);
			Py_INCREF(exc_tb);
			// in this way, error will be reported to the log
			PyErr_Restore(exc_type, exc_val, exc_tb);

			// the error is reported, let's continue...
			//goto clear;	
		}
	}

	head = PyTuple_GetItem(args, 0);
	if (!head) {
		goto clear;
	}

#ifdef PYTHREE
        if (!PyUnicode_Check(head)) {
#else
	if (!PyString_Check(head)) {
#endif
		uwsgi_log( "http status must be a string !\n");
		goto clear;
	}


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
		wsgi_req->hvec[2].iov_base = PyBytes_AsString(PyUnicode_AsASCIIString(head));
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
		wsgi_req->hvec[1].iov_base = PyBytes_AsString(PyUnicode_AsASCIIString(head));
		wsgi_req->hvec[1].iov_len = strlen(wsgi_req->hvec[1].iov_base);
#else
		wsgi_req->hvec[1].iov_base = PyString_AsString(head);
		wsgi_req->hvec[1].iov_len = PyString_Size(head);
#endif
		wsgi_req->status = uwsgi_str3_num(wsgi_req->hvec[1].iov_base);
		wsgi_req->hvec[2].iov_base = nl;
		wsgi_req->hvec[2].iov_len = NL_SIZE;
	}

	headers = PyTuple_GetItem(args, 1);
	if (!headers) goto clear;


	if (!PyList_Check(headers)) {
		uwsgi_log( "http headers must be in a python list\n");
		goto clear;
	}
	wsgi_req->header_cnt = PyList_Size(headers);

	if (wsgi_req->header_cnt > uwsgi.max_vars) {
		wsgi_req->header_cnt = uwsgi.max_vars;
	}
	for (i = 0; i < wsgi_req->header_cnt; i++) {
		j = (i * 4) + base;
		head = PyList_GetItem(headers, i);
		if (!head) {
			goto clear;
		}
		if (!PyTuple_Check(head)) {
			uwsgi_log( "http header must be defined in a tuple !\n");
			goto clear;
		}
		h_key = PyTuple_GetItem(head, 0);
		if (!h_key) {
			goto clear;
		}
		h_value = PyTuple_GetItem(head, 1);
		if (!h_value) {
			goto clear;
		}

#ifdef PYTHREE
		wsgi_req->hvec[j].iov_base = PyBytes_AsString(PyUnicode_AsASCIIString(h_key));
		wsgi_req->hvec[j].iov_len = strlen(wsgi_req->hvec[j].iov_base);
#else
		wsgi_req->hvec[j].iov_base = PyString_AsString(h_key);
		wsgi_req->hvec[j].iov_len = PyString_Size(h_key);
#endif
		wsgi_req->hvec[j + 1].iov_base = h_sep;
		wsgi_req->hvec[j + 1].iov_len = H_SEP_SIZE;
#ifdef PYTHREE
		wsgi_req->hvec[j + 2].iov_base = PyBytes_AsString(PyUnicode_AsASCIIString(h_value));
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

#ifdef __sun__
	int remains = j + 1;
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
		wsgi_req->headers_size = wsgi_req->socket->proto_writev_header(wsgi_req, wsgi_req->hvec, j + 1);
	UWSGI_GET_GIL
#endif

	//uwsgi_log("%d %p\n", wsgi_req->poll.fd, up.wsgi_writeout);
	Py_INCREF(up.wsgi_writeout);

	return up.wsgi_writeout;

clear:

	Py_INCREF(Py_None);
	return Py_None;
}
