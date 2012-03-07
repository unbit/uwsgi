#include <Python.h>

void uwsgi_cgi_load_python() {

	Py_Initialize();
}

void uwsgi_cgi_run_python(char *filename) {

	char **e, *p;
        PyObject *k, *env_value;

	FILE *fp = fopen(filename, "r");

	PySys_SetArgv(1, &filename);

	PyObject *os_module = PyImport_ImportModule("os");
        if (os_module) {
       		PyObject *os_module_dict = PyModule_GetDict(os_module);
        	PyObject *py_environ = PyDict_GetItemString(os_module_dict, "environ");
                if (py_environ) {
                	for (e = environ; *e != NULL; e++) {
                        	p = strchr(*e, '=');
                                if (p == NULL) continue;

                                k = PyString_FromStringAndSize(*e, (int)(p-*e));
                                if (k == NULL) {
                                	PyErr_Print();
                                        continue;
                                }

                                env_value = PyString_FromString(p+1);
                                if (env_value == NULL) {
                                	PyErr_Print();
                                        Py_DECREF(k);
                                        continue;
                                }

                                if (PyObject_SetItem(py_environ, k, env_value)) {
                                	PyErr_Print();
                                }

                                Py_DECREF(k);
                                Py_DECREF(env_value);

                        }

                }
        }


	PyRun_AnyFileEx(fp, filename, 1);
}
