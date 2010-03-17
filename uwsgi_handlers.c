#include "uwsgi.h"

/* uwsgi PING|100 */
int uwsgi_request_ping(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {
	char len;

	fprintf(stderr, "PING\n");
	wsgi_req->modifier_arg = 1;
	wsgi_req->size = 0;

	len = strlen(uwsgi->shared->warning_message);
	if (len > 0) {
		// endianess check is not needed as the warning message can be max 80 chars
		wsgi_req->size = len;
	}
	if (write(wsgi_req->poll.fd, wsgi_req, 4) != 4) {
		perror("write()");
	}

	if (len > 0) {
		if (write(wsgi_req->poll.fd, uwsgi->shared->warning_message, len)
		    != len) {
			perror("write()");
		}
	}

	return 0;
}

/* uwsgi ADMIN|10 */
int uwsgi_request_admin(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {
	uint32_t opt_value = 0;
	int i;

	if (wsgi_req->size >= 4) {
		memcpy(&opt_value, &wsgi_req->buffer, 4);
		// TODO: check endianess
	}
	fprintf(stderr, "setting internal option %d to %d\n", wsgi_req->modifier_arg, opt_value);
	uwsgi->shared->options[wsgi_req->modifier_arg] = opt_value;
	wsgi_req->modifier = 255;
	wsgi_req->size = 0;
	wsgi_req->modifier_arg = 1;
	i = write(wsgi_req->poll.fd, wsgi_req, 4);
	if (i != 4) {
		perror("write()");
	}

	return 0;
}

/* uwsgi FASTFUNC|26 */
int uwsgi_request_fastfunc(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {

	PyObject *zero, *func_result, *fchunk, *func_chunks;

	zero = PyList_GetItem(uwsgi->fastfuncslist, wsgi_req->modifier_arg);
	if (zero) {
		fprintf(stderr, "managing fastfunc %d\n", wsgi_req->modifier_arg);
		func_result = PyEval_CallObject(zero, NULL);
		if (PyErr_Occurred()) {
			PyErr_Print();
		}
		if (func_result) {
			func_chunks = PyObject_GetIter(func_result);
			if (func_chunks) {
				while ((fchunk = PyIter_Next(func_chunks))) {
					if (PyString_Check(fchunk)) {
						wsgi_req->response_size += write(wsgi_req->poll.fd, PyString_AsString(fchunk), PyString_Size(fchunk));
					}
					Py_DECREF(fchunk);
				}
				Py_DECREF(func_chunks);
			}
			Py_DECREF(func_result);
		}
	}
	PyErr_Clear();

	return 0;
}

/* uwsgi MARSHAL|33 */
int uwsgi_request_marshal(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {
	PyObject *func_result;

	PyObject *umm = PyDict_GetItemString(uwsgi->embedded_dict,
					     "message_manager_marshal");
	if (umm) {
		PyObject *ummo = PyMarshal_ReadObjectFromString(&wsgi_req->buffer,
								wsgi_req->size);
		if (ummo) {
			if (!PyTuple_SetItem(uwsgi->embedded_args, 0, ummo)) {
				if (!PyTuple_SetItem(uwsgi->embedded_args, 1, PyInt_FromLong(wsgi_req->modifier_arg))) {
					func_result = PyEval_CallObject(umm, uwsgi->embedded_args);
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
								wsgi_req->size = (uint16_t)
									PyString_Size(marshalled);
								if (write(wsgi_req->poll.fd, wsgi_req, 4) == 4) {
									if (write(wsgi_req->poll.fd, PyString_AsString(marshalled), wsgi_req->size) != wsgi_req->size) {
										perror("write()");
									}
								}
								else {
									perror("write()");
								}
							}
							else {
								fprintf(stderr, "marshalled object is too big. skip\n");
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

	return 0;
}
