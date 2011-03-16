#include "../../uwsgi.h"
#include <Python.h>

#include <frameobject.h>

#define MAX_PYTHONPATH 64
#define MAX_PYMODULE_ALIAS 64

#define LONG_ARGS_PYTHON_BASE      17000 + ((0 + 1) * 100)

#define LONG_ARGS_PYTHONPATH            LONG_ARGS_PYTHON_BASE + 1
#define LONG_ARGS_PASTE                 LONG_ARGS_PYTHON_BASE + 2
#define LONG_ARGS_PYARGV                LONG_ARGS_PYTHON_BASE + 3
#define LONG_ARGS_PYMODULE_ALIAS        LONG_ARGS_PYTHON_BASE + 4
#define LONG_ARGS_RELOAD_OS_ENV		LONG_ARGS_PYTHON_BASE + 5

#if PY_MINOR_VERSION == 4 && PY_MAJOR_VERSION == 2
#define Py_ssize_t ssize_t
#endif

#if PY_MAJOR_VERSION > 2
#define PYTHREE
#endif

#ifdef UWSGI_THREADING
#define UWSGI_GET_GIL up.gil_get();
#define UWSGI_RELEASE_GIL up.gil_release();
#else
#define UWSGI_GET_GIL
#define UWSGI_RELEASE_GIL
#endif

#ifndef PyVarObject_HEAD_INIT
#define PyVarObject_HEAD_INIT(x, y) PyObject_HEAD_INIT(x) y,
#endif


PyAPI_FUNC(PyObject *) PyMarshal_WriteObjectToString(PyObject *, int);
PyAPI_FUNC(PyObject *) PyMarshal_ReadObjectFromString(char *, Py_ssize_t);

#ifdef PYTHREE
#define UWSGI_PYFROMSTRING(x) PyUnicode_FromString(x)
#define UWSGI_PYFROMSTRINGSIZE(x, y) PyUnicode_FromStringAndSize(x, y)
#define PyInt_FromLong	PyLong_FromLong
#define PyInt_AsLong	PyLong_AsLong
#define PyInt_Check	PyLong_Check
#define PyString_Check	PyBytes_Check
#define	PyString_FromStringAndSize	PyBytes_FromStringAndSize
#define	PyString_FromFormat	PyBytes_FromFormat
#define	PyString_FromString	PyBytes_FromString
#define	PyString_Size		PyBytes_Size
#define	PyString_Concat		PyBytes_Concat
#define	PyString_AsString	(char *) PyBytes_AsString
#define PyFile_FromFile(A,B,C,D) PyFile_FromFd(fileno((A)), (B), (C), -1, NULL, NULL, NULL, 0)

#else
#define UWSGI_PYFROMSTRING(x) PyString_FromString(x)
#define UWSGI_PYFROMSTRINGSIZE(x, y) PyString_FromStringAndSize(x, y)
#endif

#define LOADER_DYN              0
#define LOADER_UWSGI            1
#define LOADER_FILE             2
#define LOADER_PASTE            3
#define LOADER_EVAL             4
#define LOADER_CALLABLE         5
#define LOADER_STRING_CALLABLE  6
#define LOADER_MOUNT            7

#define LOADER_MAX              8

struct uwsgi_python {

	char *home;
	int optimize;

	char *argv;
	int argc;

#ifdef PYTHREE
	wchar_t *py_argv[MAX_PYARGV];
#else
	char *py_argv[MAX_PYARGV];
#endif

	PyObject *wsgi_spitout;
	PyObject *wsgi_writeout;

	PyThreadState *main_thread;

	char *test_module;

	char *python_path[MAX_PYTHONPATH];
	int python_path_cnt;

	PyObject *loader_dict;
	PyObject* (*loaders[LOADER_MAX]) (void *);

	char *wsgi_config;
	char *file_config;
	char *paste;
	char *eval;


	char *callable;

	int ignore_script_name;
	int catch_exceptions;

	int *current_recursion_depth;
	struct _frame **current_frame;

	int current_main_recursion_depth;
	struct _frame *current_main_frame;

	void (*swap_ts)(struct wsgi_request *, struct uwsgi_app *);
	void (*reset_ts)(struct wsgi_request *, struct uwsgi_app *);

#ifdef UWSGI_THREADING
	pthread_key_t upt_save_key;
	pthread_key_t upt_gil_key;
	pthread_mutex_t lock_pyloaders;
	void (*gil_get) (void);
	void (*gil_release) (void);
#endif

	PyObject *workers_tuple;
	PyObject *embedded_dict;
	PyObject *embedded_args;
	PyObject *fastfuncslist;

	char *pymodule_alias[MAX_PYMODULE_ALIAS];
	int pymodule_alias_cnt;

	int pep3333_input;

	void (*extension)(void);

	int reload_os_env;
};



void init_uwsgi_vars(void);
void init_uwsgi_embedded_module(void);


void uwsgi_wsgi_config(char *);
void uwsgi_paste_config(char *);
void uwsgi_file_config(char *);
void uwsgi_eval_config(char *);

int init_uwsgi_app(int, void *, struct wsgi_request *wsgi_req, PyThreadState *);


PyObject *py_eventfd_read(PyObject *, PyObject *);
PyObject *py_eventfd_write(PyObject *, PyObject *);


int manage_python_response(struct wsgi_request *);
int uwsgi_python_call(struct wsgi_request *, PyObject *, PyObject *);
PyObject *python_call(PyObject *, PyObject *, int);

#ifdef UWSGI_SENDFILE
PyObject *py_uwsgi_sendfile(PyObject *, PyObject *);
ssize_t uwsgi_sendfile(struct wsgi_request *);
ssize_t uwsgi_do_sendfile(int, int, size_t, size_t, off_t*, int);
#endif

PyObject *py_uwsgi_write(PyObject *, PyObject *);
PyObject *py_uwsgi_spit(PyObject *, PyObject *);

void init_pyargv(void);

#ifdef UWSGI_WEB3
void *uwsgi_request_subhandler_web3(struct wsgi_request *, struct uwsgi_app *);
int uwsgi_response_subhandler_web3(struct wsgi_request *);
#endif

PyObject *uwsgi_uwsgi_loader(void *);
PyObject *uwsgi_dyn_loader(void *);
PyObject *uwsgi_file_loader(void *);
PyObject *uwsgi_eval_loader(void *);
PyObject *uwsgi_paste_loader(void *);
PyObject *uwsgi_callable_loader(void *);
PyObject *uwsgi_string_callable_loader(void *);
PyObject *uwsgi_mount_loader(void *);

char *get_uwsgi_pymodule(char *);
PyObject *get_uwsgi_pydict(char *);

int uwsgi_request_wsgi(struct wsgi_request *);
void uwsgi_after_request_wsgi(struct wsgi_request *);

void *uwsgi_request_subhandler_wsgi(struct wsgi_request *, struct uwsgi_app*);
int uwsgi_response_subhandler_wsgi(struct wsgi_request *);

void gil_real_get(void);
void gil_real_release(void);
void gil_fake_get(void);
void gil_fake_release(void);

void init_uwsgi_module_advanced(PyObject *);
void init_uwsgi_module_spooler(PyObject *);
void init_uwsgi_module_sharedarea(PyObject *);
void init_uwsgi_module_cache(PyObject *);
void init_uwsgi_module_queue(PyObject *);

PyObject *uwsgi_pyimport_by_filename(char *, char *);

void threaded_swap_ts(struct wsgi_request *, struct uwsgi_app *);
void simple_swap_ts(struct wsgi_request *, struct uwsgi_app *);
void threaded_reset_ts(struct wsgi_request *, struct uwsgi_app *);
void simple_reset_ts(struct wsgi_request *, struct uwsgi_app *);
