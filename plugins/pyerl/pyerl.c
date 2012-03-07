#include "../erlang/erlang.h"
#include "../python/uwsgi_python.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_erlang uerl;
extern struct uwsgi_python up;

ei_cnode *pyerl_cnode;

PyObject *pyerl_close(PyObject * self, PyObject * args) {

	int fd;

	if (!PyArg_ParseTuple(args, "i:erlang_close", &fd)) {
                return NULL;
        }

	if (fd >= 0)
		close(fd);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *pyerl_connect(PyObject * self, PyObject * args) {

	char *node = NULL;
	int fd;

	if (!PyArg_ParseTuple(args, "s:erlang_connect", &node)) {
                return NULL;
        }

	fd = ei_connect(pyerl_cnode, node); 	

	if (fd < 0) {
		return PyErr_Format(PyExc_ValueError, "Unable to connect to erlang node");
	}

	return PyInt_FromLong(fd);

}

int py_to_erl(PyObject *, ei_x_buff*);

PyObject *erl_to_py(ei_x_buff* x) {

	int etype, esize, arity;
	long long num;
	double fnum;
	char *atom, *binary;
	long bin_size;
	PyObject *pobj;
	PyObject *zero;
	erlang_pid epid;
	int i;

	ei_get_type(x->buff, &x->index, &etype, &esize);

	switch(etype) {
		case ERL_SMALL_INTEGER_EXT:
                case ERL_INTEGER_EXT:
                case ERL_SMALL_BIG_EXT:
                case ERL_LARGE_BIG_EXT:
			ei_decode_longlong(x->buff, &x->index, &num);
			return PyLong_FromLong(num);
		case ERL_FLOAT_EXT:
			ei_decode_double(x->buff, &x->index, &fnum);
			return PyFloat_FromDouble(fnum);
		case ERL_STRING_EXT:
			atom = uwsgi_malloc(esize+1);
			ei_decode_string(x->buff, &x->index, atom);
			pobj = PyString_FromString(atom);
			free(atom);
			Py_INCREF(pobj);
			return pobj;
		case ERL_ATOM_EXT:
			atom = uwsgi_malloc(esize+1);
			ei_decode_atom(x->buff, &x->index, atom);
#ifndef PyUnicode_FromString
			zero = PyString_FromString(atom);
			pobj = PyUnicode_FromObject(zero);
			Py_DECREF(zero);
#else
			pobj = PyUnicode_FromString(atom);
#endif
			free(atom);
			Py_INCREF(pobj);
			return pobj;
		case ERL_SMALL_TUPLE_EXT:
                case ERL_LARGE_TUPLE_EXT:
			ei_decode_tuple_header(x->buff, &x->index, &arity);
			pobj = PyTuple_New(arity);
			for(i=0;i<arity;i++) {
				zero = erl_to_py(x);
				PyTuple_SetItem(pobj, i, zero);
				Py_DECREF(zero);
			}		
			Py_INCREF(pobj);
			return pobj;
		case ERL_LIST_EXT:
		case ERL_NIL_EXT:
			ei_decode_list_header(x->buff, &x->index, &arity);
			if (!arity) {
				Py_INCREF(Py_None);
				return Py_None;
			}
			pobj = PyList_New(0);
			for(i=0;i<arity+1;i++) {
				zero = erl_to_py(x);
				PyList_Append(pobj, zero);
				Py_DECREF(zero);
			}
			Py_INCREF(pobj);
			return pobj;	
		case ERL_BINARY_EXT:
			binary = uwsgi_malloc(esize);
			ei_decode_binary(x->buff, &x->index, binary, &bin_size);
			pobj = PyString_FromStringAndSize(binary, bin_size);
			free(binary);
			Py_INCREF(pobj);
			return pobj;
		case ERL_PID_EXT:
			ei_decode_pid(x->buff, &x->index, &epid);	
			pobj = PyTuple_New(3);
			PyTuple_SetItem(pobj, 0, PyInt_FromLong(epid.num));
			PyTuple_SetItem(pobj, 1, PyInt_FromLong(epid.serial));
			PyTuple_SetItem(pobj, 2, PyInt_FromLong(epid.creation));
			Py_INCREF(pobj);
			return pobj;
		default:
			ei_skip_term(x->buff, &x->index);
			Py_INCREF(Py_None);
			return Py_None;
	}

	Py_INCREF(Py_None);
	return Py_None;
	
}

PyObject *pyerl_lock(PyObject * self, PyObject * args) {

	uwsgi_lock(uerl.lock);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *pyerl_unlock(PyObject * self, PyObject * args) {

	uwsgi_unlock(uerl.lock);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *pyerl_send(PyObject * self, PyObject * args) {
	PyObject *node;
        PyObject *reg;
        char *cnode;
        PyObject *pobj;
        ei_x_buff x;
        int fd;
        int close_fd = 0;
        erlang_pid epid;

        if (!PyArg_ParseTuple(args, "OOO:erlang_send", &node, &reg, &pobj)) {
                return NULL;
        }

        if (PyString_Check(node)) {
                cnode = PyString_AsString(node);
                fd = ei_connect(pyerl_cnode, cnode);
                close_fd = 1;
        }
        else if (PyInt_Check(node)) {
                fd = PyInt_AsLong(node);
        }
        else {
                return PyErr_Format(PyExc_ValueError, "invalid erlang node/descriptor");
        }

        if (fd < 0) {
                return PyErr_Format(PyExc_ValueError, "Unable to connect to erlang node");
        }


        ei_x_new_with_version(&x);

        if (py_to_erl(pobj, &x) < 0) {
                ei_x_free(&x);
                if (close_fd) close(fd);
                return PyErr_Format(PyExc_ValueError, "Unsupported object in Python->Erlang translation");
        }


        if (PyTuple_Check(reg) && PyTuple_Size(reg) == 3) {
                epid.num = PyInt_AsLong( PyTuple_GetItem(reg, 0) );
                epid.serial = PyInt_AsLong( PyTuple_GetItem(reg, 1) );
                epid.creation = PyInt_AsLong( PyTuple_GetItem(reg, 2) );
                ei_send(fd, &epid, x.buff, x.index);
        }
        else if (PyString_Check(reg)) {
                ei_reg_send(pyerl_cnode, fd, PyString_AsString(reg), x.buff, x.index);
        }
        else {
                ei_x_free(&x);
                if (close_fd) close(fd);
                return PyErr_Format(PyExc_ValueError, "Invalid Erlang process");
        }

	return PyInt_FromLong(fd);
}

PyObject *pyerl_sr(PyObject * self, PyObject * args) {

	PyObject *node;
	PyObject *reg;
	char *cnode;
	PyObject *pobj;
	ei_x_buff x;
	int fd;
	int close_fd = 0;
	erlang_msg em;
	erlang_pid epid;
	int eversion;
	PyObject *res;

	if (!PyArg_ParseTuple(args, "OOO:erlang_sr", &node, &reg, &pobj)) {
                return NULL;
        }

	if (PyString_Check(node)) {
		cnode = PyString_AsString(node);
		fd = ei_connect(pyerl_cnode, cnode); 	
		close_fd = 1;
	}
	else if (PyInt_Check(node)) {
		fd = PyInt_AsLong(node);
	}
	else {
		return PyErr_Format(PyExc_ValueError, "invalid erlang node/descriptor");
	}

	if (fd < 0) {
		return PyErr_Format(PyExc_ValueError, "Unable to connect to erlang node");
	}

	

	ei_x_new_with_version(&x);

	if (py_to_erl(pobj, &x) < 0) {
		ei_x_free(&x);
		if (close_fd) close(fd);
		return PyErr_Format(PyExc_ValueError, "Unsupported object in Python->Erlang translation");
	}

	
	if (PyTuple_Check(reg) && PyTuple_Size(reg) == 3) {
		epid.num = PyInt_AsLong( PyTuple_GetItem(reg, 0) );
		epid.serial = PyInt_AsLong( PyTuple_GetItem(reg, 1) );
		epid.creation = PyInt_AsLong( PyTuple_GetItem(reg, 2) );
		ei_send(fd, &epid, x.buff, x.index);
	}
	else if (PyString_Check(reg)) {
		ei_reg_send(pyerl_cnode, fd, PyString_AsString(reg), x.buff, x.index);
	}
	else {
		ei_x_free(&x);
                if (close_fd) close(fd);
                return PyErr_Format(PyExc_ValueError, "Invalid Erlang process");
	}

recv:
	ei_x_free(&x);

	ei_x_new(&x);

	if (ei_xreceive_msg(fd, &em, &x) == ERL_MSG) {

		if (em.msgtype == ERL_TICK) {
			goto recv;			
		}
		x.index = 0;
		ei_decode_version(x.buff, &x.index, &eversion);
		res = erl_to_py(&x);
		ei_x_free(&x);
		if (close_fd) close(fd);
		return res;
	}

	ei_x_free(&x);
	if (close_fd) close(fd);

        Py_INCREF(Py_None);
        return Py_None;
}

void pyerl_call_registered(void *func, ei_x_buff *x) {

	PyObject *pyargs = PyTuple_New(1);

	PyTuple_SetItem(pyargs, 0, erl_to_py(x));
	
        python_call((PyObject *) func, pyargs, 0, NULL);
}

PyObject *pyerl_register_process(PyObject * self, PyObject * args) {

	char *name;
	PyObject *callable;

	if (!PyArg_ParseTuple(args, "sO:erlang_register_process", &name, &callable)) {
                return NULL;
        }

	if (strlen(name) > 0xff-1)
	return PyErr_Format(PyExc_ValueError, "Invalid erlang process name");

	struct uwsgi_erlang_process *uep = uerl.uep, *old_uep;

        if (!uep) {
                uerl.uep = uwsgi_malloc(sizeof(struct uwsgi_erlang_process));
                uep = uerl.uep;
        }
        else {
                while(uep) {
                        old_uep = uep;
                        uep = uep->next;
                }

                uep = uwsgi_malloc(sizeof(struct uwsgi_erlang_process));
                old_uep->next = uep;
        }

	strcpy(uep->name, name);
	uep->plugin = pyerl_call_registered;
	uep->func = callable;
        uep->next = NULL;


	Py_INCREF(Py_None);
	return Py_None;
	
}

PyObject *pyerl_recv(PyObject * self, PyObject * args) {

	ei_x_buff x;
	erlang_msg em;
	PyObject *res;
	int eversion;
	int fd;

	if (!PyArg_ParseTuple(args, "i:erlang_recv", &fd)) {
                return NULL;
        }

recv:
	ei_x_new(&x);

	if (ei_xreceive_msg(fd, &em, &x) == ERL_MSG) {

		if (em.msgtype == ERL_TICK) {
			ei_x_free(&x);
			goto recv;
		}
                x.index = 0;
                ei_decode_version(x.buff, &x.index, &eversion);
                res = erl_to_py(&x);
                ei_x_free(&x);
                return res;
        }

        ei_x_free(&x);

	Py_INCREF(Py_None);
        return Py_None;
}

PyObject *pyerl_rpc(PyObject * self, PyObject * args) {

        PyObject *node;
        char *mod, *fun;
        char *cnode;
        PyObject *pobj;
        ei_x_buff x;
        ei_x_buff xr;
        int fd;
        int close_fd = 0;
        int eversion;
        PyObject *res;

        if (!PyArg_ParseTuple(args, "OssO:erlang_rpc", &node, &mod, &fun, &pobj)) {
                return NULL;
        }

        if (PyString_Check(node)) {
                cnode = PyString_AsString(node);
                fd = ei_connect(pyerl_cnode, cnode);
                close_fd = 1;
        }
        else if (PyInt_Check(node)) {
                fd = PyInt_AsLong(node);
        }
        else {
                return PyErr_Format(PyExc_ValueError, "Invalid erlang node/descriptor");
        }

        if (fd < 0) {
                return PyErr_Format(PyExc_ValueError, "Unable to connect to erlang node");
        }

        ei_x_new(&x);

        if (py_to_erl(pobj, &x) < 0) {
                ei_x_free(&x);
        	if (close_fd) close(fd);
                return PyErr_Format(PyExc_ValueError, "Unsupported object in Python->Erlang translation");
        }


	ei_x_new(&xr);
        if (ei_rpc(pyerl_cnode, fd, mod, fun, x.buff, x.index, &xr) < 0) {
		if (close_fd) close(fd);
		ei_x_free(&x);	
		ei_x_free(&xr);
		return PyErr_Format(PyExc_ValueError, "Error in Erlang rpc");
	}

        xr.index = 0;
        ei_decode_version(xr.buff, &xr.index, &eversion);

        res = erl_to_py(&xr);

        if (close_fd) close(fd);
        ei_x_free(&x);
        ei_x_free(&xr);
        return res;

}



static PyMethodDef uwsgi_pyerl_methods[] = {
        {"erlang_connect", pyerl_connect, METH_VARARGS, ""},
        {"erlang_close", pyerl_close, METH_VARARGS, ""},
        {"erlang_send_message", pyerl_send, METH_VARARGS, ""},
        {"erlang_send", pyerl_send, METH_VARARGS, ""},
        {"erlang_recv_message", pyerl_recv, METH_VARARGS, ""},
        {"erlang_recv", pyerl_recv, METH_VARARGS, ""},
        {"erlang_sr", pyerl_sr, METH_VARARGS, ""},
        {"erlang_rpc", pyerl_rpc, METH_VARARGS, ""},
        {"erlang_lock", pyerl_lock, METH_VARARGS, ""},
        {"erlang_unlock", pyerl_unlock, METH_VARARGS, ""},
        {"erlang_register_process", pyerl_register_process, METH_VARARGS, ""},
        {NULL, NULL},
};

void py_erl_init_functions() {

	PyMethodDef *uwsgi_function;

	PyDict_SetItemString(up.embedded_dict, "erlang_node", PyString_FromString(ei_thisnodename(pyerl_cnode)));

        for (uwsgi_function = uwsgi_pyerl_methods; uwsgi_function->ml_name != NULL; uwsgi_function++) {
                PyObject *func = PyCFunction_New(uwsgi_function, NULL);
                PyDict_SetItemString(up.embedded_dict, uwsgi_function->ml_name, func);
                Py_DECREF(func);
        }

}

int py_to_erl(PyObject *pobj, ei_x_buff *x) {
        int i;
        PyObject *pobj2;

        if (pobj == NULL || pobj == Py_None) {
		ei_x_encode_empty_list(x);
        }
        else if (PyString_Check(pobj)) {
                ei_x_encode_binary(x, PyString_AsString(pobj), PyString_Size(pobj));
        }
	else if (PyUnicode_Check(pobj)) {
                ei_x_encode_atom(x, PyString_AsString(pobj));
	}
        else if (PyInt_Check(pobj)) {
                ei_x_encode_long(x, PyInt_AsLong(pobj));
        }
        else if (PyList_Check(pobj)) {
		if (PyList_Size(pobj) > 0) {
			ei_x_encode_list_header(x, PyList_Size(pobj));
                	for (i = 0; i < PyList_Size(pobj); i++) {
                        	pobj2 = PyList_GetItem(pobj, i);
				if (py_to_erl(pobj2, x) < 0) return -1;
                	}
		}
		ei_x_encode_empty_list(x);
        }
	else if (PyTuple_Check(pobj)) {
		ei_x_encode_tuple_header(x, PyTuple_Size(pobj));
                for (i = 0; i < PyTuple_Size(pobj); i++) {
                        pobj2 = PyTuple_GetItem(pobj, i);
			if (py_to_erl(pobj2, x) < 0) return -1;
                }
        }
        else {
		return -1;
        }

	return x->index;
}



void pyerl_init() {

	up.extension = py_erl_init_functions;

	if (!uerl.name) {
		pyerl_cnode = uwsgi_malloc(sizeof(ei_cnode));
		memset(pyerl_cnode, 0, sizeof(ei_cnode));
		if (ei_connect_init(pyerl_cnode, "uwsgi", NULL, 0) < 0) {
			uwsgi_log("unable to initialize erlang connection\n");
			exit(1);
		}
		uwsgi_log("Erlang C-Node name: %s\n",ei_thisnodename(pyerl_cnode));
	}
	else {
		pyerl_cnode = &uerl.cnode;
	}

	uwsgi_log("enabled Python<->Erlang bridge\n");

}

struct uwsgi_plugin pyerl_plugin = {

        .post_init = pyerl_init,
};

