#ifdef UWSGI_ERLANG

#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

PyObject *py_erlang_connect(PyObject *self, PyObject *args) {

	char *erlang_node ;
	int fd ;


	if (!PyArg_ParseTuple(args, "s:erlang_connect", &erlang_node)) {
                return NULL ;
        }

	UWSGI_SET_BLOCKING ;
	fd = erl_connect(erlang_node) ;
	UWSGI_UNSET_BLOCKING ;
	return PyInt_FromLong(fd);
}

PyObject *py_erlang_recv_message(PyObject *self, PyObject *args) {
	int erfd ;
	ErlMessage emsg;

	if (!PyArg_ParseTuple(args, "i:erlang_recv_message", &erfd)) {
                return NULL ;
        }

	if (erl_receive_msg(erfd, (unsigned char *) uwsgi.buffer, uwsgi.buffer_size, &emsg) == ERL_MSG) {
		return eterm_to_py(emsg.msg);
	}

	Py_INCREF(Py_None);
	return Py_None;
	
}

PyObject *py_erlang_send_message(PyObject *self, PyObject *args) {

	ETERM *pymessage ;
	PyObject *erfd, *ermessage, *erdest, *zero ;

	int er_number, er_serial, er_creation ;
	char *er_node;

	erfd = PyTuple_GetItem(args, 0);
	if (!erfd) {
		goto clear;	
	}

	erdest = PyTuple_GetItem(args, 1);
	if (!erdest) {
		goto clear;
	}

	if (!PyString_Check(erdest) && !PyDict_Check(erdest)) {
		goto clear;
	}

	ermessage = PyTuple_GetItem(args, 2);
	if (!ermessage) {
		goto clear;
	}

	pymessage = py_to_eterm(ermessage);
	if (!pymessage) {
		goto clear;
	}


	if (PyString_Check(erdest)) {
		if (!erl_reg_send(PyInt_AsLong(erfd), PyString_AsString(erdest), pymessage)) {
			erl_err_msg("erl_reg_send()");
			goto clear;
		}
	}
	else if (PyDict_Check(erdest)) {
		fprintf(stderr,"ready to send\n");
		zero = PyDict_GetItemString(erdest,"node");
		if (!zero) { goto clear; } if (!PyString_Check(zero)) { goto clear; }
		er_node = PyString_AsString(zero);

		zero = PyDict_GetItemString(erdest,"number");
		if (!zero) { goto clear; } if (!PyInt_Check(zero)) { goto clear; }
		er_number = PyInt_AsLong(zero);

		zero = PyDict_GetItemString(erdest,"serial");
		if (!zero) { goto clear; } if (!PyInt_Check(zero)) { goto clear; }
		er_serial = PyInt_AsLong(zero);

		zero = PyDict_GetItemString(erdest,"creation");
		if (!zero) { goto clear; } if (!PyInt_Check(zero)) { goto clear; }
		er_creation = PyInt_AsLong(zero);

		if (!erl_send(PyInt_AsLong(erfd), erl_mk_pid((const char *) er_node, er_number,er_serial,er_creation), pymessage)) {
			erl_err_msg("erl_send()");
			goto clear;
		}
	}
	else {
		goto clear;
	}

	Py_INCREF(Py_True);
	return Py_True;

clear:
	PyErr_Print();
	Py_INCREF(Py_None);
	return Py_None;	
}

PyObject *py_erlang_close(PyObject *self, PyObject *args) {
	
	int fd;

	if (!PyArg_ParseTuple(args, "i:erlang_close", &fd)) {
                return NULL ;
        }

	erl_close_connection(fd);

	Py_INCREF(Py_True);
        return Py_True;
}

static PyMethodDef uwsgi_erlang_methods[] = {
  {"erlang_connect", py_erlang_connect, METH_VARARGS, ""},
  {"erlang_send_message", py_erlang_send_message, METH_VARARGS, ""},
  {"erlang_recv_message", py_erlang_recv_message, METH_VARARGS, ""},
  {"erlang_close", py_erlang_close, METH_VARARGS, ""},
  {NULL, NULL},
};


int init_erlang(char *nodename) {

	struct sockaddr_in e_addr;

	char *ip ;
	char *node ;
	int efd ;
	int rlen ;

	PyMethodDef *uwsgi_function;


	ip = strchr(nodename, '@');

	if (ip == NULL) {
		fprintf(stderr,"*** invalid erlang node name ***\n");
		return -1;
	}

	node = malloc((ip-nodename)+1);
	if (node == NULL) {
		perror("malloc()");
		return -1;
	}
	memset(node,0, (ip-nodename)+1);
	memcpy(node, nodename, ip-nodename);
	
	erl_init(NULL, 0);

        if (erl_connect_xinit(ip+1, node, nodename, NULL, "RVHWRLDVUWOTBIRRALYZ", 0) == -1) {
		fprintf(stderr,"*** unable to initialize erlang c-node ***\n");
		return -1;
	}

	efd = socket(AF_INET, SOCK_STREAM, 0);
        if (efd < 0) {
                perror("socket()");
		return -1;
        }


        memset(&e_addr, 0, sizeof(struct sockaddr_in));
        e_addr.sin_family = AF_INET;
        e_addr.sin_addr.s_addr = inet_addr(ip+1);

        rlen = 1 ;
        if (setsockopt(efd, SOL_SOCKET, SO_REUSEADDR, &rlen, sizeof(rlen))) {
                perror("setsockopt()");
		close(efd);
		return -1;
        }

        if (bind(efd, (struct sockaddr *)&e_addr, sizeof(struct sockaddr_in)) < 0) {
                perror("bind()");
		close(efd);
		return -1;
        }

	rlen = sizeof(struct sockaddr_in);
	if (getsockname(efd, (struct sockaddr *) &e_addr, (socklen_t *) &rlen)) {
                perror("getsockname()");
		close(efd);
		return -1;
        }
	
	if (listen(efd, uwsgi.listen_queue)) {
		perror("listen()");
		close(efd);
		return -1;
	}

	if (erl_publish(ntohs(e_addr.sin_port)) < 0) {
		fprintf(stderr,"*** unable to subscribe with EPMD ***\n");
		close(efd);
		return -1;
        }

	fprintf(stderr,"Erlang C-Node initialized on port %d you can access it with name %s\n", ntohs(e_addr.sin_port), nodename);

	for (uwsgi_function = uwsgi_erlang_methods; uwsgi_function->ml_name != NULL; uwsgi_function++) {
                PyObject *func = PyCFunction_New(uwsgi_function, NULL);
                PyDict_SetItemString(uwsgi.embedded_dict, uwsgi_function->ml_name, func);
                Py_DECREF(func);
        }

	return efd;
	
}

ETERM *py_to_eterm(PyObject *pobj) {
        int i;
	int count;
        PyObject *pobj2 ;
	ETERM *eobj = NULL ;
	ETERM *eobj2 = NULL ;
	ETERM **eobj3 ;

	if (pobj == NULL) {
		return erl_mk_empty_list() ;
	}

	if (PyString_Check(pobj)) {
		fprintf(stderr,"creating atom from string\n");
		eobj = erl_mk_atom(PyString_AsString(pobj));
	}
	else if (PyInt_Check(pobj)) {
		fprintf(stderr,"creating ERLANG int\n");
		eobj = erl_mk_int(PyInt_AsLong(pobj));
	}
	else if (PyList_Check(pobj)) {
		eobj = erl_mk_empty_list();
		for(i=0;i<PyList_Size(pobj);i++) {
			pobj2 = PyList_GetItem(pobj, i);
			eobj2 = py_to_eterm(pobj2);
			eobj = erl_cons(eobj2, eobj);
		}
		fprintf(stderr,"created list\n");
	}
	else if (PyDict_Check(pobj)) {
		// a pid
		char *er_node;
		int er_number, er_serial, er_creation;
		pobj2 = PyDict_GetItemString(pobj, "node"); if (!pobj2) { PyErr_Print(); goto clear;} if (!PyString_Check(pobj2)) { goto clear; }
		er_node = PyString_AsString(pobj2);

		pobj2 = PyDict_GetItemString(pobj, "number"); if (!pobj2) { PyErr_Print(); goto clear;} if (!PyInt_Check(pobj2)) { goto clear; }
		er_number = PyInt_AsLong(pobj2);

		pobj2 = PyDict_GetItemString(pobj, "serial"); if (!pobj2) { PyErr_Print(); goto clear;} if (!PyInt_Check(pobj2)) { goto clear; }
		er_serial = PyInt_AsLong(pobj2);

		pobj2 = PyDict_GetItemString(pobj, "creation"); if (!pobj2) { PyErr_Print(); goto clear;} if (!PyInt_Check(pobj2)) { goto clear; }
		er_creation = PyInt_AsLong(pobj2);

		eobj = erl_mk_pid(er_node,er_number, er_serial, er_creation);
	}
	else if (PyTuple_Check(pobj)) {
		count = PyTuple_Size(pobj);
		fprintf(stderr,"PYTUPLE !!!\n");
		eobj3 = malloc(sizeof(ETERM *)*count) ;
		for(i=0;i<count;i++) {
			pobj2 = PyTuple_GetItem(pobj, i);
			if (!pobj2) {
				fprintf(stderr,"oops\n");
				break;
			}
			eobj3[i] = py_to_eterm(pobj2);
		}
		eobj = erl_mk_tuple(eobj3, count);
		free(eobj3);
	}

clear:
	if (eobj == NULL) {
		return erl_mk_empty_list() ;
	}

	return eobj ;
}

PyObject *eterm_to_py(ETERM *obj) {
        int i;
        int count ;
        ETERM *obj2  ;
	PyObject *eobj = NULL ;

        if (obj == NULL) {
		Py_INCREF(Py_None);
                return Py_None;
	}

        switch(ERL_TYPE(obj)) {

                case ERL_CONS:
                case ERL_NIL:
                        count = erl_length(obj) ;
			eobj = PyList_New(0);
                        for(i=0;i<count;i++) {
                                obj2 = erl_hd(obj);
                                PyList_Append(eobj, eterm_to_py(obj2));
                                obj = erl_tl(obj) ;
                        }
                        break;
                case ERL_TUPLE:
			eobj = PyTuple_New(erl_size(obj));
                        for(i = 1;i <= erl_size(obj);i++) {
                                obj2 = erl_element(i, obj);
                                PyTuple_SetItem(eobj, i-1, eterm_to_py(obj2));
                        }
                        break;
                case ERL_ATOM:
			eobj = PyString_FromStringAndSize(ERL_ATOM_PTR(obj), ERL_ATOM_SIZE(obj));
                        break;
                case ERL_INTEGER:
			eobj = PyInt_FromLong(ERL_INT_VALUE(obj));
                        break;
                case ERL_BINARY:
                        fprintf(stderr,"FOUND A BINARY %.*s\n", ERL_BIN_SIZE(obj), ERL_BIN_PTR(obj));
                        break;
                case ERL_PID:
                        fprintf(stderr,"FOUND A PID %s %d %d %d\n", ERL_PID_NODE(obj), ERL_PID_NUMBER(obj), ERL_PID_SERIAL(obj), ERL_PID_CREATION(obj));
			eobj = PyDict_New();
			if (PyDict_SetItemString(eobj, "node", PyString_FromString(ERL_PID_NODE(obj)) )) { PyErr_Print(); break;}
			if (PyDict_SetItemString(eobj, "number", PyInt_FromLong(ERL_PID_NUMBER(obj)) )) { PyErr_Print(); break;}
			if (PyDict_SetItemString(eobj, "serial", PyInt_FromLong(ERL_PID_SERIAL(obj)) )) { PyErr_Print(); break;}
			if (PyDict_SetItemString(eobj, "creation", PyInt_FromLong(ERL_PID_CREATION(obj)) )) { PyErr_Print(); break;}
                default:
                        fprintf(stderr,"UNMANAGED ETERM TYPE: %d\n", ERL_TYPE(obj));
                        break;

        }

        if (eobj == NULL) {
		Py_INCREF(Py_None);
                return Py_None;
	}

	return eobj;
}

void erlang_loop() {

	ErlConnect econn;
        ErlMessage em;
        ETERM *eresponse;
	
	int rlen;

	while(uwsgi.workers[uwsgi.mywid].manage_next_request) {


		UWSGI_CLEAR_STATUS ;
		
		uwsgi.poll.fd = erl_accept(uwsgi.erlangfd, &econn);

                fprintf(stderr, "ERL_ACCEPT: %d\n", uwsgi.poll.fd);
                if (uwsgi.poll.fd >=0) {

	 		UWSGI_SET_ERLANGING ;
                        for(;;) {
                        	rlen = erl_receive_msg(uwsgi.poll.fd, (unsigned char *) uwsgi.buffer, uwsgi.buffer_size, &em);
                                fprintf(stderr,"ERL: %d\n", rlen);
                                if (rlen == ERL_MSG) {
                                                PyObject *zero = eterm_to_py(em.msg);
                                                PyObject *callable = PyDict_GetItemString(uwsgi.embedded_dict, "erlang_func");
                                                if (!callable) {
                                                        fprintf(stderr,"AIAAA\n");
                                                        PyErr_Print();
                                                }
                                                PyObject *pargs = PyTuple_New(1);
                                                if (!pargs) {
                                                        fprintf(stderr,"oops1\n");
                                                        PyErr_Print();
                                                }
                                                if (PyTuple_SetItem(pargs,0,zero)) {
                                                        fprintf(stderr,"oops2\n");
                                                        PyErr_Print();
                                                }
                                                PyObject *erlang_result = PyEval_CallObject (callable, pargs);
                                                eresponse = py_to_eterm(erlang_result);

                                                rlen = erl_send(uwsgi.poll.fd, em.from, eresponse);
                                                fprintf(stderr,"ERL_SEND: %d\n", rlen);
                                        }
                        	}
			}
                        erl_close_connection(uwsgi.poll.fd);
                        fprintf(stderr,"CONNECTION CLOSED\n");

                        UWSGI_UNSET_ERLANGING ;
	}
}

#else
#warning "*** Erlang support is disabled ***"
#endif
