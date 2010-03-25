#include "uwsgi.h"

int manage_python_response(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {

	PyObject *pychunk ;
	ssize_t wsize ;
#ifdef UWSGI_SENDFILE
	ssize_t sf_len = 0 ;
#endif

	// return or yield ?
	if (PyString_Check((PyObject *)wsgi_req->async_result)) {
		//fprintf(stderr,"DOH !!!\n");
		if ((wsize = write(wsgi_req->poll.fd, PyString_AsString(wsgi_req->async_result), PyString_Size(wsgi_req->async_result))) < 0) {
                        perror("STRING write()");
                        goto clear;
                }
                wsgi_req->response_size += wsize;
		goto clear;
	}

	if (wsgi_req->sendfile_fd != -1) {
		sf_len = uwsgi_sendfile(uwsgi, wsgi_req);
		if (sf_len < 1) goto clear;
		wsgi_req->response_size += sf_len ;		
#ifdef UWSGI_ASYNC
		if (uwsgi->async > 1) {
			if (wsgi_req->response_size < wsgi_req->sendfile_fd_size) {
				return UWSGI_AGAIN;
			}
		}
#endif
		goto clear;
	}

	// ok its a yield
	if (!wsgi_req->async_placeholder) {
		//fprintf(stderr,"getting placeholder %d\n", wsgi_req->async_id);
		wsgi_req->async_placeholder = PyObject_GetIter(wsgi_req->async_result);
                if (!wsgi_req->async_placeholder) {
			goto clear2;
		}
		Py_DECREF((PyObject *)wsgi_req->async_result);
#ifdef UWSGI_ASYNC
		if (uwsgi->async > 1) {
			return UWSGI_AGAIN;
		}
#endif
	}

		//fprintf(stderr,"running yield %d %p\n", wsgi_req->async_id, wsgi_req);

	/*
	boh = wsgi_req->async_placeholder; boh2 = wsgi_req->async_result ;
	fprintf(stderr,"placeholder refcnt %d: %d\n", wsgi_req->async_switches, boh->ob_refcnt);
	*/

	//fprintf(stderr,"NEXT CHUNK\n");
	
	pychunk = PyIter_Next(wsgi_req->async_placeholder) ;

	/*
	boh = wsgi_req->async_placeholder; boh2 = wsgi_req->async_result ;
	fprintf(stderr,"AFTER NEXT %d/%d\n", boh->ob_refcnt, boh2->ob_refcnt);
	*/

	if (!pychunk) {
		//fprintf(stderr,"AIA\n");
		if (PyErr_Occurred()) PyErr_Print();
		goto clear;
	}

	//fprintf(stderr,"ob type %s\n", pychunk->ob_type->tp_name);
	if (PyString_Check(pychunk)) {
		if ((wsize = write(wsgi_req->poll.fd, PyString_AsString(pychunk), PyString_Size(pychunk))) < 0) {
			fprintf(stderr,"ITER ID %d %d\n", wsgi_req->async_id, wsgi_req->poll.fd);
			perror("ITER write()");
			Py_DECREF(pychunk);
			goto clear;
		}
		wsgi_req->response_size += wsize;
	}
	
	Py_DECREF(pychunk);
	//Py_DECREF(wsgi_req->async_placeholder);
	//Py_DECREF(wsgi_req->async_result);

	/*
	boh = wsgi_req->async_placeholder; boh2 = wsgi_req->async_result ;
	fprintf(stderr,"AFTER CHUNK %d/%d\n", boh->ob_refcnt, boh2->ob_refcnt);
	*/

	return UWSGI_AGAIN ;

clear:
	//fprintf(stderr,"finito\n");
	if (wsgi_req->async_environ) {
		PyDict_Clear(wsgi_req->async_environ);
	}
	if (wsgi_req->async_post) {
		fclose(wsgi_req->async_post);
		wsgi_req->fd_closed = 1 ;
	}
	Py_XDECREF((PyObject *)wsgi_req->async_placeholder);
clear2:
	Py_DECREF((PyObject *)wsgi_req->async_result);
	//fprintf(stderr,"RESULT REFCNT: %d\n", ((PyObject *) wsgi_req->async_result)->ob_refcnt);
	PyErr_Clear();
	return UWSGI_OK;
}


PyObject *python_call(PyObject *callable, PyObject *args) {
	
	PyObject *pyret;

	pyret =  PyEval_CallObject(callable, args);
	if (PyErr_Occurred()) {
		PyErr_Print();
	}

	return pyret;
}



int uwsgi_python_call(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req, PyObject *callable, PyObject *args) {
	
	wsgi_req->async_result = python_call(callable, args);

	if (wsgi_req->async_result) {
		while ( manage_python_response(uwsgi, wsgi_req) != UWSGI_OK) {
#ifdef UWSGI_ASYNC
			if (uwsgi->async > 1) {
				return UWSGI_AGAIN;
			}
#endif
		}
	}

	return UWSGI_OK;
}
