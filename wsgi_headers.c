#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

static char *nl = "\r\n";
static char *h_sep = ": ";
static const char *http_protocol = "HTTP/1.1";

PyObject *py_uwsgi_spit(PyObject * self, PyObject * args) {
	PyObject *headers, *head;
	PyObject *h_key, *h_value;
	int i, j;

struct wsgi_request *wsgi_req = uwsgi.wsgi_req;

#ifdef UWSGI_STACKLESS
	if (uwsgi.stackless) {
        	PyThreadState *ts = PyThreadState_GET();
        	wsgi_req = find_request_by_tasklet(ts->st.current);
	}
#endif

#ifndef UNBIT
	int base = 0;
#else
	int base = 4;
#endif

	// use writev()


	head = PyTuple_GetItem(args, 0);
	if (!head) {
		goto clear;
	}

	if (!PyString_Check(head)) {
		fprintf(stderr, "http status must be a string !\n");
		goto clear;
	}


#ifndef UNBIT
	if (uwsgi.shared->options[UWSGI_OPTION_CGI_MODE] == 0) {
		base = 4;
#endif


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
		wsgi_req->status = atoi(wsgi_req->hvec[2].iov_base);
		wsgi_req->hvec[3].iov_base = nl;
		wsgi_req->hvec[3].iov_len = NL_SIZE;
#ifndef UNBIT
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
		wsgi_req->status = atoi(wsgi_req->hvec[1].iov_base);
		wsgi_req->hvec[2].iov_base = nl;
		wsgi_req->hvec[2].iov_len = NL_SIZE;
	}
#endif


#ifdef UNBIT
	if (wsgi_req->unbit_flags & (unsigned long long) 1) {
		if (tmp_dir_fd >= 0 && tmp_filename[0] != 0 && wsgi_req->status == 200 && wsgi_req->method_len == 3 && wsgi_req->method[0] == 'G' && wsgi_req->method[1] == 'E' && wsgi_req->method[2] == 'T') {
			save_to_disk = openat(tmp_dir_fd, tmp_filename, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP);
		}
	}
#endif


	headers = PyTuple_GetItem(args, 1);
	if (!headers) {
		goto clear;
	}
	if (!PyList_Check(headers)) {
		fprintf(stderr, "http headers must be in a python list\n");
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
			fprintf(stderr, "http header must be defined in a tuple !\n");
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
		//fprintf(stderr, "%.*s: %.*s\n", wsgi_req->hvec[j].iov_len, (char *)wsgi_req->hvec[j].iov_base, wsgi_req->hvec[j+2].iov_len, (char *) wsgi_req->hvec[j+2].iov_base);
	}


#ifdef UNBIT
	if (save_to_disk >= 0) {
		for (j = 0; j < i; j += 4) {
			if (!strncasecmp(wsgi_req->hvec[j].iov_base, "Set-Cookie", wsgi_req->hvec[j].iov_len)) {
				close(save_to_disk);
				save_to_disk = -1;
				break;
			}
		}
	}
#endif

	// \r\n
	j = (i * 4) + base;
	wsgi_req->hvec[j].iov_base = nl;
	wsgi_req->hvec[j].iov_len = NL_SIZE;

	wsgi_req->headers_size = writev(wsgi_req->poll.fd, wsgi_req->hvec, j + 1);
	if (wsgi_req->headers_size < 0) {
		perror("writev()");
	}
	Py_INCREF(uwsgi.wsgi_writeout);


	return uwsgi.wsgi_writeout;

      clear:

	Py_INCREF(Py_None);
	return Py_None;
}
