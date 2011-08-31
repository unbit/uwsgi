#include "uwsgi_python.h"

extern struct uwsgi_server uwsgi;

#ifdef HAS_NOT_PyFrame_GetLineNumber
int PyFrame_GetLineNumber(PyFrameObject *frame) {
	if (frame->f_trace) {
		return frame->f_lineno;
	}
	else {
		return PyCode_Addr2Line(frame->f_code, frame->f_lasti);
	}
}
#endif

int uwsgi_python_profiler_call(PyObject *obj, PyFrameObject *frame, int what, PyObject *arg) {

#ifndef UWSGI_PYPY
	switch(what) {
		case PyTrace_CALL:
			uwsgi_log("[uWSGI Python profiler] CALL: %s (line %d) -> %s %d args, stacksize %d\n",
				PyString_AsString(frame->f_code->co_filename),
				PyFrame_GetLineNumber(frame),
				PyString_AsString(frame->f_code->co_name), frame->f_code->co_argcount, frame->f_code->co_stacksize);
			break;
		case PyTrace_C_CALL:
			uwsgi_log("[uWSGI Python profiler] C CALL: %s (line %d) -> %s %d args, stacksize %d\n",
				PyString_AsString(frame->f_code->co_filename),
				PyFrame_GetLineNumber(frame),
				PyEval_GetFuncName(arg), frame->f_code->co_argcount, frame->f_code->co_stacksize);
			break;
	}
#endif

	return 0;
}
