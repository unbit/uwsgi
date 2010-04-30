#ifdef UWSGI_ERLANG

#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

static void erlang_log(void);

PyObject *py_erlang_connect(PyObject * self, PyObject * args) {

	char *erlang_node;
	int fd;


	if (!PyArg_ParseTuple(args, "s:erlang_connect", &erlang_node)) {
		return NULL;
	}

	UWSGI_SET_BLOCKING;
	fd = erl_connect(erlang_node);
	UWSGI_UNSET_BLOCKING;
	return PyInt_FromLong(fd);
}

PyObject *py_erlang_recv_message(PyObject * self, PyObject * args) {
	int erfd;
	struct pollfd erpoll;
	ErlMessage emsg;
	PyObject *pyer = NULL;
	unsigned char erlang_buffer[8192];
	int eret;
	int timeout = uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT];

	if (!PyArg_ParseTuple(args, "i|i:erlang_recv_message", &erfd, &timeout)) {
		return NULL;
	}

	if (erfd < 0) {
		goto clear;
	}

	erpoll.fd = erfd;
	erpoll.events = POLLIN;
      cycle:
	memset(&emsg, 0, sizeof(ErlMessage));
	UWSGI_SET_BLOCKING;
	if (timeout > 0) {
		eret = poll(&erpoll, 1, timeout * 1000);
		if (eret < 0) {
			uwsgi_error("poll()");
			goto clear;
		}
		else if (eret == 0) {
			goto clear;
		}
	}
	if (erl_receive_msg(erfd, erlang_buffer, 8192, &emsg) == ERL_MSG) {
		if (emsg.type == ERL_TICK) {
			goto cycle;
		}
		if (emsg.msg) {
			pyer = eterm_to_py(emsg.msg);
		}
		if (emsg.msg) {
			erl_free_compound(emsg.msg);
		}
		if (emsg.to) {
			erl_free_compound(emsg.to);
		}
		if (emsg.from) {
			erl_free_compound(emsg.from);
		}
		if (!pyer) {
			goto clear;
		}
		UWSGI_UNSET_BLOCKING;
		return pyer;
	}

      clear:
	UWSGI_UNSET_BLOCKING;
	Py_INCREF(Py_None);
	return Py_None;

}

PyObject *py_erlang_send_message(PyObject * self, PyObject * args) {

	ETERM *pymessage;
	ETERM *pid;
	int erfd;
	PyObject *ermessage, *erdest, *zero;

	int er_number, er_serial, er_creation;
	char *er_node;

	if (!PyArg_ParseTuple(args, "iOO|i:erlang_send_message", &erfd, &erdest, &ermessage)) {
		return NULL;
	}

	if (erfd < 0) {
		goto clear;
	}

	if (!PyString_Check(erdest) && !PyDict_Check(erdest)) {
		goto clear;
	}

	pymessage = py_to_eterm(ermessage);
	if (!pymessage) {
		goto clear;
	}


	if (PyString_Check(erdest)) {
		if (!erl_reg_send(erfd, PyString_AsString(erdest), pymessage)) {
			erl_err_msg("erl_reg_send()");
			goto clear2;
		}
	}
	else if (PyDict_Check(erdest)) {
		zero = PyDict_GetItemString(erdest, "node");
		if (!zero) {
			goto clear2;
		}
		if (!PyString_Check(zero)) {
			goto clear2;
		}
		er_node = PyString_AsString(zero);

		zero = PyDict_GetItemString(erdest, "number");
		if (!zero) {
			goto clear2;
		}
		if (!PyInt_Check(zero)) {
			goto clear2;
		}
		er_number = PyInt_AsLong(zero);

		zero = PyDict_GetItemString(erdest, "serial");
		if (!zero) {
			goto clear2;
		}
		if (!PyInt_Check(zero)) {
			goto clear2;
		}
		er_serial = PyInt_AsLong(zero);

		zero = PyDict_GetItemString(erdest, "creation");
		if (!zero) {
			goto clear2;
		}
		if (!PyInt_Check(zero)) {
			goto clear2;
		}
		er_creation = PyInt_AsLong(zero);

		pid = erl_mk_pid((const char *) er_node, er_number, er_serial, er_creation);

		if (!pid) {
			goto clear2;
		}

		if (!erl_send(erfd, pid, pymessage)) {
			erl_err_msg("erl_send()");
			erl_free_term(pid);
			goto clear2;
		}

		erl_free_term(pid);
	}
	else {
		goto clear;
	}

	erl_free_compound(pymessage);

	Py_INCREF(Py_True);
	return Py_True;

      clear2:
	erl_free_compound(pymessage);
      clear:
	PyErr_Print();
	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_erlang_rpc(PyObject * self, PyObject * args) {

	int fd, timeout = uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT];
	char *emod, *efun;
	PyObject *eargs, *pyer = NULL;
	ETERM *pyargs, *rex;
	ErlMessage emsg;
	int eret;

	if (!PyArg_ParseTuple(args, "issO|i:erlang_rpc", &fd, &emod, &efun, &eargs, &timeout)) {
		return NULL;
	}

	if (fd < 0) {
		goto clear;
	}

	pyargs = py_to_eterm(eargs);
	if (!pyargs) {
		goto clear;
	}


	if (erl_rpc_to(fd, emod, efun, pyargs)) {
		erl_err_msg("erl_rpc_to()");
		goto clear2;
	}


      cycle:
	memset(&emsg, 0, sizeof(ErlMessage));
	UWSGI_SET_BLOCKING;
	eret = erl_rpc_from(fd, timeout * 1000, &emsg);
	if (eret == ERL_TICK) {
		goto cycle;
	}
	else if (eret == ERL_MSG) {
		if (emsg.msg) {
			if (ERL_IS_TUPLE(emsg.msg)) {
				rex = erl_element(1, emsg.msg);
				if (!rex) {
					goto clear2;
				}
				if (!strncmp("rex", ERL_ATOM_PTR(rex), ERL_ATOM_SIZE(rex))) {
					erl_free_term(rex);
					rex = erl_element(2, emsg.msg);
					if (!rex) {
						goto clear2;
					}
					pyer = eterm_to_py(rex);
					erl_free_term(rex);
				}
				else {
					erl_free_term(rex);
				}
			}
		}
		if (emsg.msg) {
			erl_free_compound(emsg.msg);
		}
		if (emsg.to) {
			erl_free_compound(emsg.to);
		}
		if (emsg.from) {
			erl_free_compound(emsg.from);
		}
		if (!pyer) {
			goto clear2;
		}
		erl_free_compound(pyargs);
		UWSGI_UNSET_BLOCKING;
		return pyer;
	}
	else {
		erl_err_msg("erl_rpc_from()");
	}

      clear2:
	UWSGI_UNSET_BLOCKING;
	erl_free_compound(pyargs);

      clear:
	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *py_erlang_close(PyObject * self, PyObject * args) {

	int fd;

	if (!PyArg_ParseTuple(args, "i:erlang_close", &fd)) {
		return NULL;
	}


	if (fd >= 0) {
		erl_close_connection(fd);
	}

	Py_INCREF(Py_True);
	return Py_True;
}

static PyMethodDef uwsgi_erlang_methods[] = {
	{"erlang_connect", py_erlang_connect, METH_VARARGS, ""},
	{"erlang_send_message", py_erlang_send_message, METH_VARARGS, ""},
	{"erlang_recv_message", py_erlang_recv_message, METH_VARARGS, ""},
	{"erlang_rpc", py_erlang_rpc, METH_VARARGS, ""},
	{"erlang_close", py_erlang_close, METH_VARARGS, ""},
	{NULL, NULL},
};


int init_erlang(char *nodename, char *cookie) {

	struct sockaddr_in e_addr;

	char *ip;
	char *node;
	int efd;
	int rlen;
	char *cookiefile;
	char *cookiehome;
	char cookievalue[128];
	int cookiefd;

	PyMethodDef *uwsgi_function;


	ip = strchr(nodename, '@');

	if (ip == NULL) {
		uwsgi_log( "*** invalid erlang node name ***\n");
		return -1;
	}

	if (cookie == NULL) {
		// get the cookie from the home
		cookiehome = getenv("HOME");
		if (!cookiehome) {
			uwsgi_log( "unable to get erlang cookie from your home.\n");
			return -1;
		}
		cookiefile = malloc(strlen(cookiehome) + 1 + strlen(".erlang.cookie") + 1);
		if (!cookiefile) {
			uwsgi_error("malloc()");
		}
		cookiefile[0] = 0;
		strcat(cookiefile, cookiehome);
		strcat(cookiefile, "/.erlang.cookie");

		cookiefd = open(cookiefile, O_RDONLY);
		if (cookiefd < 0) {
			uwsgi_error("open()");
			free(cookiefile);
			return -1;
		}

		memset(cookievalue, 0, 128);
		if (read(cookiefd, cookievalue, 127) < 1) {
			uwsgi_log( "invalid cookie found in %s\n", cookiefile);
			close(cookiefd);
			free(cookiefile);
			return -1;
		}
		cookie = cookievalue;
		close(cookiefd);
		free(cookiefile);
	}

	node = malloc((ip - nodename) + 1);
	if (node == NULL) {
		uwsgi_error("malloc()");
		return -1;
	}
	memset(node, 0, (ip - nodename) + 1);
	memcpy(node, nodename, ip - nodename);

	erl_init(NULL, 0);

	if (erl_connect_xinit(ip + 1, node, nodename, NULL, cookie, 0) == -1) {
		uwsgi_log( "*** unable to initialize erlang c-node ***\n");
		return -1;
	}

	efd = socket(AF_INET, SOCK_STREAM, 0);
	if (efd < 0) {
		uwsgi_error("socket()");
		return -1;
	}


	memset(&e_addr, 0, sizeof(struct sockaddr_in));
	e_addr.sin_family = AF_INET;
	e_addr.sin_addr.s_addr = inet_addr(ip + 1);

	rlen = 1;
	if (setsockopt(efd, SOL_SOCKET, SO_REUSEADDR, &rlen, sizeof(rlen))) {
		uwsgi_error("setsockopt()");
		close(efd);
		return -1;
	}

	if (bind(efd, (struct sockaddr *) &e_addr, sizeof(struct sockaddr_in)) < 0) {
		uwsgi_error("bind()");
		close(efd);
		return -1;
	}

	rlen = sizeof(struct sockaddr_in);
	if (getsockname(efd, (struct sockaddr *) &e_addr, (socklen_t *) & rlen)) {
		uwsgi_error("getsockname()");
		close(efd);
		return -1;
	}

	if (listen(efd, uwsgi.listen_queue)) {
		uwsgi_error("listen()");
		close(efd);
		return -1;
	}

	if (erl_publish(ntohs(e_addr.sin_port)) < 0) {
		uwsgi_log( "*** unable to subscribe with EPMD ***\n");
		close(efd);
		return -1;
	}

	uwsgi_log( "Erlang C-Node initialized on port %d you can access it with name %s\n", ntohs(e_addr.sin_port), nodename);

	for (uwsgi_function = uwsgi_erlang_methods; uwsgi_function->ml_name != NULL; uwsgi_function++) {
		PyObject *func = PyCFunction_New(uwsgi_function, NULL);
		PyDict_SetItemString(uwsgi.embedded_dict, uwsgi_function->ml_name, func);
		Py_DECREF(func);
	}

	return efd;

}

ETERM *py_to_eterm(PyObject * pobj) {
	int i;
	int count;
	PyObject *pobj2;
	ETERM *eobj = NULL;
	ETERM *eobj2 = NULL;
	ETERM **eobj3;

	if (pobj == NULL) {
		return erl_mk_empty_list();
	}

	if (PyString_Check(pobj)) {
		eobj = erl_mk_atom(PyString_AsString(pobj));
	}
	else if (PyInt_Check(pobj)) {
		eobj = erl_mk_int(PyInt_AsLong(pobj));
	}
	else if (PyList_Check(pobj)) {
		eobj = erl_mk_empty_list();
		for (i = PyList_Size(pobj) - 1; i >= 0; i--) {
			pobj2 = PyList_GetItem(pobj, i);
			eobj2 = py_to_eterm(pobj2);
			eobj = erl_cons(eobj2, eobj);
		}
	}
	else if (PyDict_Check(pobj)) {
		// a pid
		char *er_node;
		int er_number, er_serial, er_creation;
		pobj2 = PyDict_GetItemString(pobj, "node");
		if (!pobj2) {
			PyErr_Print();
			goto clear;
		}
		if (!PyString_Check(pobj2)) {
			goto clear;
		}
		er_node = PyString_AsString(pobj2);

		pobj2 = PyDict_GetItemString(pobj, "number");
		if (!pobj2) {
			PyErr_Print();
			goto clear;
		}
		if (!PyInt_Check(pobj2)) {
			goto clear;
		}
		er_number = PyInt_AsLong(pobj2);

		pobj2 = PyDict_GetItemString(pobj, "serial");
		if (!pobj2) {
			PyErr_Print();
			goto clear;
		}
		if (!PyInt_Check(pobj2)) {
			goto clear;
		}
		er_serial = PyInt_AsLong(pobj2);

		pobj2 = PyDict_GetItemString(pobj, "creation");
		if (!pobj2) {
			PyErr_Print();
			goto clear;
		}
		if (!PyInt_Check(pobj2)) {
			goto clear;
		}
		er_creation = PyInt_AsLong(pobj2);

		eobj = erl_mk_pid(er_node, er_number, er_serial, er_creation);
	}
	else if (PyTuple_Check(pobj)) {
		count = PyTuple_Size(pobj);
		eobj3 = malloc(sizeof(ETERM *) * count);
		for (i = 0; i < count; i++) {
			pobj2 = PyTuple_GetItem(pobj, i);
			if (!pobj2) {
				break;
			}
			eobj3[i] = py_to_eterm(pobj2);
		}
		eobj = erl_mk_tuple(eobj3, count);
		free(eobj3);
	}
	else {
		uwsgi_log( "UNMANAGED PYTHON TYPE: %s\n", pobj->ob_type->tp_name);
	}

      clear:
	if (eobj == NULL) {
		return erl_mk_empty_list();
	}

	return eobj;
}

PyObject *eterm_to_py(ETERM * obj) {
	int i;
	int count;
	ETERM *obj2;
	PyObject *eobj = NULL;

	if (obj == NULL) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	switch (ERL_TYPE(obj)) {

	case ERL_CONS:
	case ERL_NIL:
		count = erl_length(obj);
		eobj = PyList_New(0);
		for (i = 0; i < count; i++) {
			obj2 = erl_hd(obj);
			PyList_Append(eobj, eterm_to_py(obj2));
			obj = erl_tl(obj);
		}
		break;
	case ERL_TUPLE:
		eobj = PyTuple_New(erl_size(obj));
		for (i = 1; i <= erl_size(obj); i++) {
			obj2 = erl_element(i, obj);
			PyTuple_SetItem(eobj, i - 1, eterm_to_py(obj2));
		}
		break;
	case ERL_ATOM:
		eobj = PyString_FromStringAndSize(ERL_ATOM_PTR(obj), ERL_ATOM_SIZE(obj));
		break;
	case ERL_INTEGER:
		eobj = PyInt_FromLong(ERL_INT_VALUE(obj));
		break;
	case ERL_BINARY:
		uwsgi_log( "FOUND A BINARY %.*s\n", ERL_BIN_SIZE(obj), ERL_BIN_PTR(obj));
		break;
	case ERL_PID:
		eobj = PyDict_New();
		if (PyDict_SetItemString(eobj, "node", PyString_FromString(ERL_PID_NODE(obj)))) {
			PyErr_Print();
			break;
		}
		if (PyDict_SetItemString(eobj, "number", PyInt_FromLong(ERL_PID_NUMBER(obj)))) {
			PyErr_Print();
			break;
		}
		if (PyDict_SetItemString(eobj, "serial", PyInt_FromLong(ERL_PID_SERIAL(obj)))) {
			PyErr_Print();
			break;
		}
		if (PyDict_SetItemString(eobj, "creation", PyInt_FromLong(ERL_PID_CREATION(obj)))) {
			PyErr_Print();
			break;
		}
	default:
		uwsgi_log( "UNMANAGED ETERM TYPE: %d\n", ERL_TYPE(obj));
		break;

	}

	if (eobj == NULL) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	return eobj;
}

void erlang_loop(struct wsgi_request *wsgi_req) {

	ErlConnect econn;
	ErlMessage em;
	ETERM *eresponse;

	PyObject *callable = PyDict_GetItemString(uwsgi.embedded_dict, "erlang_func");
	if (!callable) {
		PyErr_Print();
		uwsgi_log( "- you have not defined a uwsgi.erlang_func callable, Erlang message manager will be disabled until you define it -\n");
	}

	PyObject *pargs = PyTuple_New(1);
	if (!pargs) {
		PyErr_Print();
		uwsgi_log( "- error preparing arg tuple for uwsgi.erlang_func callable, Erlang message manager will be disabled -\n");
	}

	while (uwsgi.workers[uwsgi.mywid].manage_next_request) {


		UWSGI_CLEAR_STATUS;

		wsgi_req->poll.fd = erl_accept(uwsgi.erlangfd, &econn);

		if (wsgi_req->poll.fd >= 0) {

			UWSGI_SET_ERLANGING;
			for (;;) {
				if (erl_receive_msg(wsgi_req->poll.fd, (unsigned char *) wsgi_req->buffer, uwsgi.buffer_size, &em) == ERL_MSG) {
					if (em.type == ERL_TICK)
						continue;

					if (!callable) {
						callable = PyDict_GetItemString(uwsgi.embedded_dict, "erlang_func");
					}

					if (!callable) {
						uwsgi_log( "- you still have not defined a uwsgi.erlang_func callable, Erlang message rejected -\n");
					}

					PyObject *zero = eterm_to_py(em.msg);
					if (em.msg) {
						erl_free_compound(em.msg);
					}
					if (em.to) {
						erl_free_compound(em.to);
					}

					if (!zero) {
						PyErr_Print();
						continue;
					}

					if (PyTuple_SetItem(pargs, 0, zero)) {
						PyErr_Print();
						continue;
					}

					PyObject *erlang_result = PyEval_CallObject(callable, pargs);

					//Py_DECREF(zero);

					if (erlang_result) {
						eresponse = py_to_eterm(erlang_result);
						if (eresponse) {
							erl_send(wsgi_req->poll.fd, em.from, eresponse);
							erl_free_compound(eresponse);
						}
						Py_DECREF(erlang_result);
					}

					if (em.from) {
						erl_free_compound(em.from);
					}

					uwsgi.workers[0].requests++;
					uwsgi.workers[uwsgi.mywid].requests++;
					if (uwsgi.shared->options[UWSGI_OPTION_LOGGING])
						erlang_log();
				}
				else {
					break;
				}
			}
			erl_close_connection(wsgi_req->poll.fd);

			UWSGI_UNSET_ERLANGING;
		}
	}
}

static void erlang_log() {
	if (uwsgi.shared->options[UWSGI_OPTION_MEMORY_DEBUG]) {
		get_memusage();
	}
	else {
		uwsgi.workers[uwsgi.mywid].rss_size = 0;
		uwsgi.workers[uwsgi.mywid].vsz_size = 0;
	}
	uwsgi_log( "[Erlang worker %d pid %d] request %llu done {rss: %llu vsz: %llu}\n", uwsgi.mywid, uwsgi.mypid, uwsgi.workers[uwsgi.mywid].requests, uwsgi.workers[uwsgi.mywid].rss_size, uwsgi.workers[uwsgi.mywid].vsz_size);
}

#else
#warning "*** Erlang support is disabled ***"
#endif
