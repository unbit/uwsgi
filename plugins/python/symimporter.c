#include "uwsgi_python.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_python up;


struct _symimporter {
	PyObject_HEAD;
} uwsgi_symbol_importer_object;

static char *symbolize(char *name) {

	char *base = uwsgi_concat2(name, "");
	char *ptr = base;
	while(*ptr != 0) {
		if (*ptr == '.') {
			*ptr = '_';
		}
		ptr++;
	}

	return base;
}

static char *name_to_symbol_module(char *name, char *what) {

	char *symbol = uwsgi_concat4("_binary_", name, "_py_", what);
        char *sym_ptr_start = dlsym(RTLD_DEFAULT, symbol);
	free(symbol);
	return sym_ptr_start;
}

static char *name_to_symbol_pkg(char *name, char *what) {

	char *symbol = uwsgi_concat4("_binary_", name, "___init___py_", what);
        char *sym_ptr_start = dlsym(RTLD_DEFAULT, symbol);
	free(symbol);
	return sym_ptr_start;
}

static PyObject* symimporter_find_module(PyObject *self, PyObject *args) {

	char *fullname;
	PyObject *path = NULL;

	if (!PyArg_ParseTuple(args, "s|O:find_module", &fullname, &path)) {
		return NULL;
	}

	char *fullname2 = symbolize(fullname);

	char *code_start = name_to_symbol_module(fullname2, "start");
	if (code_start) {
		free(fullname2);
		Py_INCREF(self);
		return self;
	}
	code_start = name_to_symbol_pkg(fullname2, "start");
	if (code_start) {
		free(fullname2);
		Py_INCREF(self);
		return self;
	}
	
	
	free(fullname2);
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject* symimporter_load_module(PyObject *self, PyObject *args) {

	char *code_start;
	char *code_end;
	char *fullname;
	char *source;
	char *modname;
	PyObject *code;
	if (!PyArg_ParseTuple(args, "s:load_module", &fullname)) {
                return NULL;
        }

	char *fullname2 = symbolize(fullname);

	code_start = name_to_symbol_module(fullname2, "start");
	if (code_start) {
		code_end = name_to_symbol_module(fullname2, "end");
		if (code_end) {
			PyObject *mod = PyImport_AddModule(fullname);
			if (!mod) goto clear;
			PyObject *dict = PyModule_GetDict(mod);
			if (!dict) goto clear;

			PyDict_SetItemString(dict, "__loader__", self);

			source = uwsgi_concat2n(code_start, code_end-code_start, "", 0);
			modname = uwsgi_concat3("sym://", fullname2, "_py");

			code = Py_CompileString(source, modname, Py_file_input);
			mod = PyImport_ExecCodeModuleEx(fullname, code, modname);

			Py_DECREF(code);
			free(source);
			free(modname);
			free(fullname2);
			return mod;	
		}
	}

	code_start = name_to_symbol_pkg(fullname2, "start");
        if (code_start) {
                code_end = name_to_symbol_pkg(fullname2, "end");
                if (code_end) {
                        PyObject *mod = PyImport_AddModule(fullname);
			if (!mod) goto clear;
                        PyObject *dict = PyModule_GetDict(mod);
			if (!dict) goto clear;

                        source = uwsgi_concat2n(code_start, code_end-code_start, "", 0);
			modname = uwsgi_concat3("sym://", symbolize(fullname), "___init___py");

			PyObject *pkgpath = Py_BuildValue("[O]", PyString_FromString(modname));

			PyDict_SetItemString(dict, "__path__", pkgpath);
			PyDict_SetItemString(dict, "__loader__", self);

                        code = Py_CompileString(source, modname, Py_file_input);
                        mod = PyImport_ExecCodeModuleEx(fullname, code, modname);

			Py_DECREF(code);
			free(source);
			free(modname);
			free(fullname2);
                        return mod;
                }
        }

clear:
	free(fullname2);
	Py_INCREF(Py_None);
        return Py_None;
}

static PyMethodDef symimporter_methods[] = {
    {"find_module", symimporter_find_module, METH_VARARGS},
    {"load_module", symimporter_load_module, METH_VARARGS},
};

static void uwsgi_symimporter_free(struct _symimporter *self) {
        PyObject_Del(self);
}


static PyTypeObject SymImporter_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "uwsgi.SymbolsImporter",
    sizeof(struct _symimporter),
    0,                                          /* tp_itemsize */
    (destructor) uwsgi_symimporter_free,            /* tp_dealloc */
    0,                                          /* tp_print */
    0,                                          /* tp_getattr */
    0,                                          /* tp_setattr */
    0,                                          /* tp_compare */
    0,                                          /* tp_repr */
    0,                                          /* tp_as_number */
    0,                                          /* tp_as_sequence */
    0,                                          /* tp_as_mapping */
    0,                                          /* tp_hash */
    0,                                          /* tp_call */
    0,                                          /* tp_str */
    0,                    /* tp_getattro */
    0,                                          /* tp_setattro */
    0,                                          /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,
    "uwsgi symbols importer",                                          /* tp_doc */
    0,                                          /* tp_traverse */
    0,                                          /* tp_clear */
    0,                                          /* tp_richcompare */
    0,                                          /* tp_weaklistoffset */
    0,                                          /* tp_iter */
    0,                                          /* tp_iternext */
    symimporter_methods,                        /* tp_methods */
    0,                                          /* tp_members */
    0,                                          /* tp_getset */
    0,                                          /* tp_base */
    0,                                          /* tp_dict */
    0,                                          /* tp_descr_get */
    0,                                          /* tp_descr_set */
    0,                                          /* tp_dictoffset */
    0,                 /* tp_init */
    PyType_GenericAlloc,                        /* tp_alloc */
    PyType_GenericNew,                          /* tp_new */
    PyObject_GC_Del,                            /* tp_free */
};

int uwsgi_init_symbol_import() {


	if (PyType_Ready(&SymImporter_Type) < 0) {
		uwsgi_log("unable to initialize symbols importer module\n");
		exit(1);
	}

	PyObject *uwsgi_em = PyImport_ImportModule("uwsgi");
	if (!uwsgi_em) {
		uwsgi_log("unable to get uwsgi module\n");
		exit(1);
	}

	if (PyModule_AddObject(uwsgi_em, "SymbolsImporter",
                           (PyObject *)&SymImporter_Type) < 0) {
		uwsgi_log("unable to initialize symbols importer module\n");
		exit(1);
	}

        return 0;
	
}

