#ifdef UWSGI_ERLANG

#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

int init_erlang(char *nodename) {

	struct sockaddr_in e_addr;

	char *ip ;
	char *node ;
	int efd ;
	int rlen ;


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

	return efd;
	
}

ETERM *py_to_eterm(PyObject *pobj) {
        int i;
	int count;
        PyObject *pobj2 ;
	ETERM *eobj = NULL ;
	ETERM *eobj2 = NULL ;

	if (pobj == NULL) {
		return erl_mk_empty_list() ;
	}

	if (PyString_Check(pobj)) {
		fprintf(stderr,"creating atom from string\n");
		eobj = erl_mk_atom(PyString_AsString(pobj));
	}
	else if (PyInt_Check(pobj)) {
		eobj = erl_mk_int(PyInt_AsLong(pobj));
	}
	else if (PyList_Check(pobj)) {
		eobj = erl_mk_empty_list();
		for(i=0;i<PyList_Size(pobj);i++) {
			pobj2 = PyList_GetItem(pobj, i);
			eobj2 = py_to_eterm(pobj2);
			eobj = erl_cons(eobj2, eobj);
		}
	}
	else if (PyTuple_Check(pobj)) {
		count = PyTuple_Size(pobj);
		// allocate memory for the eterms...need to find a good way
	}

	if (eobj == NULL) {
		return erl_mk_empty_list() ;
	}

	return eobj ;
}

PyObject *eterm_to_py(ETERM *obj) {
        int i;
        int count ;
        ETERM *obj2 ;
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
                        fprintf(stderr,"FOUND A PID\n");
                        break;
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

void erlang_loop(char *buffer) {

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
                        	rlen = erl_receive_msg(uwsgi.poll.fd, (unsigned char *) buffer, uwsgi.buffer_size, &em);
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
