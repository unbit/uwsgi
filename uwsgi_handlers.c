#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

int uwsgi_request_eval(struct wsgi_request *wsgi_req) {
	PyObject *code, *py_dict;

	UWSGI_GET_GIL
		PyObject *m = PyImport_AddModule("__main__");
	if (m == NULL) {
		PyErr_Print();
		return -1;
	}

	py_dict = PyModule_GetDict(m);
	// make it a valid c string
	wsgi_req->buffer[wsgi_req->uh.pktsize] = 0;
	// need to find a way to cache compilations...
	code = Py_CompileString(wsgi_req->buffer, "uWSGI", Py_file_input);
	if (code == NULL) {
		PyErr_Print();
		UWSGI_RELEASE_GIL
			return -1;
	}
	PyEval_EvalCode((PyCodeObject *)code, py_dict, py_dict );
	Py_DECREF(code);
	if (PyErr_Occurred()) {
		PyErr_Print();
		UWSGI_RELEASE_GIL
			return -1;
	}

	UWSGI_RELEASE_GIL
		return UWSGI_OK;
}

/* uwsgi FASTFUNC|26 */
int uwsgi_request_fastfunc(struct wsgi_request *wsgi_req) {

	PyObject *ffunc;
	int ret = UWSGI_OK;

	UWSGI_GET_GIL

		// CHECK HERE
		ffunc = PyList_GetItem(uwsgi.fastfuncslist, wsgi_req->uh.modifier2);
	if (ffunc) {
		uwsgi_log( "managing fastfunc %d\n", wsgi_req->uh.modifier2);
		ret = uwsgi_python_call(wsgi_req, ffunc, NULL);
	}

	UWSGI_RELEASE_GIL
		return ret;
}

/* uwsgi MARSHAL|33 */
int uwsgi_request_marshal(struct wsgi_request *wsgi_req) {
	PyObject *func_result;

	UWSGI_GET_GIL

		PyObject *umm = PyDict_GetItemString(uwsgi.embedded_dict,
				"message_manager_marshal");
	if (umm) {
		PyObject *ummo = PyMarshal_ReadObjectFromString(wsgi_req->buffer,
				wsgi_req->uh.pktsize);
		if (ummo) {
			if (!PyTuple_SetItem(uwsgi.embedded_args, 0, ummo)) {
				if (!PyTuple_SetItem(uwsgi.embedded_args, 1, PyInt_FromLong(wsgi_req->uh.modifier2))) {
					func_result = PyEval_CallObject(umm, uwsgi.embedded_args);
					if (PyErr_Occurred()) {
						PyErr_Print();
					}
					if (func_result) {
						PyObject *marshalled = PyMarshal_WriteObjectToString(func_result, 1);
						if (!marshalled) {
							PyErr_Print();
						}
						else {
							if (PyString_Size(marshalled) <= 0xFFFF) {
								wsgi_req->uh.pktsize = (uint16_t)
									PyString_Size(marshalled);
								if (write(wsgi_req->poll.fd, wsgi_req, 4) == 4) {
									if (write(wsgi_req->poll.fd, PyString_AsString(marshalled), wsgi_req->uh.pktsize) != wsgi_req->uh.pktsize) {
										uwsgi_error("write()");
									}
								}
								else {
									uwsgi_error("write()");
								}
							}
							else {
								uwsgi_log( "marshalled object is too big. skip\n");
							}
							Py_DECREF(marshalled);
						}
						Py_DECREF(func_result);
					}
				}
			}
			//Py_DECREF(ummo);
		}
	}
	PyErr_Clear();

	UWSGI_RELEASE_GIL
		return 0;
}
