#include "uwsgi_python.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_python up;


/*

TODO:

define a new type ASGIReplyChannl exposing a send() method
calling the write protocol hook

*/


void *uwsgi_request_subhandler_asgi(struct wsgi_request *wsgi_req, struct uwsgi_app *wi) {

	int i;
        PyObject *pydictkey, *pydictvalue;

	PyObject *content = PyDict_New();

        for (i = 0; i < wsgi_req->var_cnt; i += 2) {
#ifdef UWSGI_DEBUG
                uwsgi_debug("%.*s: %.*s\n", wsgi_req->hvec[i].iov_len, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i+1].iov_len, wsgi_req->hvec[i+1].iov_base);
#endif
		if (wsgi_req->hvec[i].iov_len < 6) continue;
		if (!uwsgi_startswith(wsgi_req->hvec[i].iov_base, "HTTP_", 5)) {
			(void) uwsgi_lower(wsgi_req->hvec[i].iov_base+5, wsgi_req->hvec[i].iov_len-5);
#ifdef PYTHREE
                	pydictkey = PyUnicode_DecodeLatin1(wsgi_req->hvec[i].iov_base+5, wsgi_req->hvec[i].iov_len-5, NULL);
                	pydictvalue = PyUnicode_DecodeLatin1(wsgi_req->hvec[i + 1].iov_base, wsgi_req->hvec[i + 1].iov_len, NULL);
#else
                	pydictkey = PyString_FromStringAndSize(wsgi_req->hvec[i].iov_base+5, wsgi_req->hvec[i].iov_len-5);
                	pydictvalue = PyString_FromStringAndSize(wsgi_req->hvec[i + 1].iov_base, wsgi_req->hvec[i + 1].iov_len);
#endif
			PyObject *old_value = PyDict_GetItem(content, pydictkey);
			if (old_value) {
				if (PyString_Check(old_value)) {
					PyObject *new_value = PyList_New(0);
					PyList_Append(new_value, old_value);
					old_value = new_value;
                			PyDict_SetItem(content, pydictkey, old_value);
					Py_DECREF(old_value);
				}
				PyList_Append(old_value, pydictvalue);
			}
			else {
                		PyDict_SetItem(content, pydictkey, pydictvalue);
			}
                	Py_DECREF(pydictkey);
                	Py_DECREF(pydictvalue);
		}
        }

	PyDict_SetItemString(wsgi_req->async_environ, "content", content);
	Py_DECREF(content);

	wsgi_req->async_app = wi->callable;

	// call
	if (PyTuple_GetItem(wsgi_req->async_args, 0) != wsgi_req->async_environ) {
	    if (PyTuple_SetItem(wsgi_req->async_args, 0, wsgi_req->async_environ)) {
	        uwsgi_log_verbose("unable to set environ to the python application callable, consider using the holy env allocator\n");
	        return NULL;
	    }
	}
	return python_call(wsgi_req->async_app, wsgi_req->async_args, uwsgi.catch_exceptions, wsgi_req);
}


int uwsgi_response_subhandler_asgi(struct wsgi_request *wsgi_req) {
	return UWSGI_OK;
}

