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
	static uint64_t last_ts = 0;
        uint64_t now = uwsgi_micros();
        uint64_t delta = 0;

	switch(what) {
		case PyTrace_CALL:
			if (last_ts == 0) delta = 0;
                	else delta = now - last_ts;
                	last_ts = now;
			uwsgi_log("[uWSGI Python profiler %llu] CALL: %s (line %d) -> %s %d args, stacksize %d\n",
				(unsigned long long) delta,
				PyString_AsString(frame->f_code->co_filename),
				PyFrame_GetLineNumber(frame),
				PyString_AsString(frame->f_code->co_name), frame->f_code->co_argcount, frame->f_code->co_stacksize);
			break;
		case PyTrace_C_CALL:
			if (last_ts == 0) delta = 0;
                	else delta = now - last_ts;
                	last_ts = now;
			uwsgi_log("[uWSGI Python profiler %llu] C CALL: %s (line %d) -> %s %d args, stacksize %d\n",
				(unsigned long long) delta,
				PyString_AsString(frame->f_code->co_filename),
				PyFrame_GetLineNumber(frame),
				PyEval_GetFuncName(arg), frame->f_code->co_argcount, frame->f_code->co_stacksize);
			break;
	}
#endif

	return 0;
}

int uwsgi_python_tracer(PyObject *obj, PyFrameObject *frame, int what, PyObject *arg) {

#ifndef UWSGI_PYPY
	static uint64_t last_ts = 0;
	uint64_t now = uwsgi_micros();
	uint64_t delta = 0;

	if (what == PyTrace_LINE) {
		if (last_ts == 0) {
			delta = 0;
		}
		else {
			delta = now - last_ts;
		}
		last_ts = now;
		uwsgi_log("[uWSGI Python profiler %llu] file %s line %d: %s argc:%d\n", (unsigned long long)delta,  PyString_AsString(frame->f_code->co_filename), PyFrame_GetLineNumber(frame), PyString_AsString(frame->f_code->co_name), frame->f_code->co_argcount);
	}
#endif

        return 0;
}

