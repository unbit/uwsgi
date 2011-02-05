#include "../erlang/erlang.h"
#include "../python/uwsgi_python.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_erlang uerl;
extern struct uwsgi_python up;

ei_cnode *pyerl_cnode;

PyObject *pyerl_connect(PyObject * self, PyObject * args) {

	Py_INCREF(Py_None);
	return Py_None;
}

int py_to_erl(PyObject *, ei_x_buff*);

PyObject *pyerl_simple_send(PyObject * self, PyObject * args) {

	char *node;
	char *reg;
	PyObject *pobj;
	ei_x_buff x;
	int fd;

	if (!PyArg_ParseTuple(args, "ssO:erlang_simple_send", &node, &reg, &pobj)) {
                return NULL;
        }

	fd = ei_connect(pyerl_cnode, node); 	

	if (fd < 0) {
		return PyErr_Format(PyExc_ValueError, "Unable to connect to erlang node %s", node);
	}

	ei_x_new_with_version(&x);

	if (py_to_erl(pobj, &x) < 0) {
		ei_x_free(&x);
		return PyErr_Format(PyExc_ValueError, "Unsupported object in Python->Erlang translation");
	}

	
	ei_reg_send(pyerl_cnode, fd, reg, x.buff, x.index);

	close(fd);
	
	ei_x_free(&x);

        Py_INCREF(Py_None);
        return Py_None;
}


static PyMethodDef uwsgi_pyerl_methods[] = {
        {"erlang_connect", pyerl_connect, METH_VARARGS, ""},
        {"erlang_simple_send", pyerl_simple_send, METH_VARARGS, ""},
        {NULL, NULL},
};

void py_erl_init_functions() {

	PyMethodDef *uwsgi_function;

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
                ei_x_encode_string(x, PyString_AsString(pobj));
        }
        else if (PyInt_Check(pobj)) {
                ei_x_encode_long(x, PyInt_AsLong(pobj));
        }
        else if (PyList_Check(pobj)) {
		ei_x_encode_list_header(x, PyList_Size(pobj));
                for (i = 0; i < PyList_Size(pobj); i++) {
                        pobj2 = PyList_GetItem(pobj, i);
			if (py_to_erl(pobj2, x) < 0) return -1;
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

