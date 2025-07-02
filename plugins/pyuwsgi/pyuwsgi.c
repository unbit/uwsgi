#include "../python/uwsgi_python.h"

//FIXME: [upstream:python] needs PyAPI_FUNC(void)
extern void Py_GetArgcArgv(int *, char ***);

extern struct uwsgi_server uwsgi;
extern struct uwsgi_python up;

extern char **environ;

static int new_argc = -1;
static int orig_argc = -1;
static char **new_argv = NULL;
static char **orig_argv = NULL;
static char *new_argv_buf = NULL;


PyObject *
pyuwsgi_setup(PyObject *self, PyObject *args, PyObject *kwds)
{
    if (new_argv) {
        PyErr_SetString(
            PyExc_RuntimeError,
            "uWSGI already setup"
            );
        return NULL;
    }

    if (uwsgi.mywid) {
        PyErr_SetString(
            PyExc_RuntimeError,
            "uWSGI must be setup by master"
            );
        return NULL;
    }

    PyObject *iterator;

    if (args == NULL || PyObject_Size(args) == 0) {
        PyObject *argv = PySys_GetObject("argv");
        if (argv == NULL)
            return NULL;

        // during site.py maybe
        if (argv == Py_None) {
            argv = PyTuple_New(0);
            iterator = PyObject_GetIter(argv);
            Py_DECREF(argv);
        }
        else {
            iterator = PyObject_GetIter(argv);
            if (PyObject_Size(argv) > 0) {
                // forward past argv0
                PyObject *item = PyIter_Next(iterator);
                Py_DECREF(item);
            }
        }
    }
    else if (
        PyObject_Size(args) == 1
        && !PyString_Check(PyTuple_GetItem(args, 0))
        ) {
        iterator = PyObject_GetIter(PyTuple_GetItem(args, 0));
    }
    else {
        iterator = PyObject_GetIter(args);
    }

    if (iterator == NULL) {
        return NULL;
    }

    size_t size = 1;
    //FIXME: ARGS prior to and including -c/-m are REQUIRED!
    PyObject *item = PyString_FromString(orig_argv[0]);
    PyObject *args_li = PyList_New(0);
    PyList_Append(args_li, item);
    size += strlen(orig_argv[0]) + 1;
    Py_DECREF(item);

    while ((item = PyIter_Next(iterator))) {
        //TODO: call str(...) on everything
        PyList_Append(args_li, item);
        size += PyObject_Length(item) + 1;
        Py_DECREF(item);
    }

    Py_DECREF(iterator);

    new_argc = PyObject_Length(args_li);
    new_argv = uwsgi_calloc(sizeof(char *) * (new_argc + 1));
    new_argv_buf = uwsgi_calloc(size);

    int i = 0;
    char *new_argv_ptr = new_argv_buf;
    for(i=0; i < new_argc; i++) {
        PyObject *arg = PyList_GetItem(args_li, i);
        char *arg_str = PyString_AsString(arg);
        new_argv[i] = new_argv_ptr;
        strcpy(new_argv_ptr, arg_str);
        new_argv_ptr += strlen(arg_str) + 1;
    }

    PyObject *args_tup = PyList_AsTuple(args_li);
    PyObject_SetAttrString(self, "NEW_ARGV", args_tup);
    Py_DECREF(args_tup);
    Py_DECREF(args_li);

    // TODO: convention here is a goto methinks?
    if (PyErr_Occurred()) {
        free(new_argv_buf);
        free(new_argv);
        new_argv = 0;
        new_argc = 0;
        return NULL;
    }

    Py_INCREF(self);
    return self;
}


PyObject *
pyuwsgi_init(PyObject *self, PyObject *args, PyObject *kwds)
{
    if (pyuwsgi_setup(self, args, kwds) == NULL) {
        return NULL;
    }

    uwsgi_setup(orig_argc, orig_argv, environ);
    int rc = uwsgi_run();

    // never(?) here
    return Py_BuildValue("i", rc);
}


PyObject *
pyuwsgi_run(PyObject *self, PyObject *args, PyObject *kwds)
{
    // backcompat
    if (new_argv == NULL &&
        pyuwsgi_setup(self, args, kwds) == NULL) {
        return NULL;
    }

    uwsgi_setup(orig_argc, orig_argv, environ);
    int rc = uwsgi_run();

    // never(?) here
    return Py_BuildValue("i", rc);
}


PyMethodDef methods[] = {
    {"run",
        (PyCFunction) pyuwsgi_run,
        METH_VARARGS | METH_KEYWORDS,
     "run(...)"
     "\n>>> 0"
     "\n"
     "\n * Call setup(...) if not configured"
     "\n * Begin uWSGI mainloop"
     "\n   NOTE: will not return"
     "\n"
    },
    {"init",
        (PyCFunction) pyuwsgi_init,
        METH_VARARGS | METH_KEYWORDS,
     "init(...)"
     "\n>>> 0"
     "\n"
     "\n * Call setup(...)"
     "\n * Begin uWSGI mainloop"
     "\n   NOTE: will not return"
     "\n"
    },
    {"setup",
        (PyCFunction) pyuwsgi_setup,
        METH_VARARGS | METH_KEYWORDS,
     "setup('--master', ...)"
     "\n>>> <module 'uwsgi' from \"uwsgi.so\">"
     "\n"
     "\n * Initialize uWSGI core with (...)"
     "\n   MUST only call once          [RuntimeException]"
     "\n   MUST only call from master   [RuntimeException]"
     "\n"
    },
    {NULL, NULL, 0, NULL}
};


static void
pyuwsgi_set_orig_argv(PyObject *self)
{

    //  ask python for the original argc/argv saved in Py_Main()
    Py_GetArgcArgv(&orig_argc, &orig_argv);

    //  [re?]export to uwsgi.orig_argv
    PyObject *m_orig_argv;
    m_orig_argv = PyTuple_New(orig_argc);

    int i = 0;
    int i_cm = -1;

    for(i=0; i < orig_argc; i++) {
        char *arg = orig_argv[i];
        //XXX: _PyOS_optarg != 0 also indicates python quit early...
        //FIXME: [upstream:python] orig_argv could be mangled; reset
        // rel: https://bugs.python.org/issue8202
        orig_argv[i + 1] = arg + strlen(arg) + 1;

        // look for -c or -m and record the offset
        if (i_cm < 0) {
            if (strcmp(arg, "-c") || strcmp(arg, "-m")) {
                // python's getopt would've failed had + 1 not exist
                i_cm = i + 1;
            }
            else if (!uwsgi_startswith(arg, "-c", 2) ||
                     !uwsgi_startswith(arg, "-m", 2)) {
                //FIXME: ARGS prior to and including -c/-m are REQUIRED,
                // but NOT a part of the uWSGI argv! Needed to make
                // exec*() self-referential: exec*(...) -> uwsgi
                //
                // want: uwsgi.binary_argv[:] + uwsgi.argv[:]!
                //       binary_argv = [binary_path] + args
                i_cm = i;
            }
        }

        PyTuple_SetItem(m_orig_argv, i, PyString_FromString(arg));
    }

    //TODO: howto properly detect uwsgi already running...
    // orig_argv == uwsgi.orig_argv (?)
    // ^^^ but if Py_Main not called, python/main.c:orig_argv unset
    // howto interact/detect things in general
    PyObject *m_new_argv = PyTuple_New(0);
    PyObject_SetAttrString(self, "NEW_ARGV", m_new_argv);
    PyObject_SetAttrString(self, "ORIG_ARGV", m_orig_argv);
    Py_DECREF(m_new_argv);
    Py_DECREF(m_orig_argv);
}


static PyObject *
pyuwsgi_init_as(char *mod_name)
{

    PyObject *m;

    m = PyImport_GetModuleDict();
    if (m == NULL) {
        return NULL;
    }

    m = PyDict_GetItemString(m, mod_name);
    if (!m) {
        m = Py_InitModule(mod_name, NULL);
	}

    if (orig_argc < 0) {
        pyuwsgi_set_orig_argv(m);
    }

    int i;
    for (i=0; methods[i].ml_name != NULL; i++) {
        PyObject *fun = PyObject_GetAttrString(m, methods[i].ml_name);
        if (fun != NULL) {
            // already exists
            Py_DECREF(fun);
            continue;
        }

        PyErr_Clear();

        //  rel: Python/modsupport.c:Py_InitModule4
        PyObject* name = PyString_FromString(methods[i].ml_name);
        //  fun(self, ...)
        fun = PyCFunction_NewEx(&methods[i], m, name);
        Py_DECREF(name);
        //  module.fun
        PyObject_SetAttrString(m, methods[i].ml_name, fun);
        Py_DECREF(fun);
    }

    return m;
}


PyMODINIT_FUNC
initpyuwsgi()
{
    (void) pyuwsgi_init_as("pyuwsgi");
}


// allow the module to be called `uwsgi`
PyMODINIT_FUNC
inituwsgi()
{
    (void) pyuwsgi_init_as("uwsgi");
}


void pyuwsgi_load()
{
    if (new_argc > -1) {
        uwsgi.new_argc = new_argc;
        uwsgi.new_argv = new_argv;
    }
}


struct uwsgi_plugin pyuwsgi_plugin = {

        .name = "pyuwsgi",
        .on_load = pyuwsgi_load,
};

