#ifdef UWSGI_STACKLESS

#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

struct wsgi_request* find_request_by_tasklet(PyTaskletObject *tasklet) {

        int i ;
        for(i=0;i<uwsgi.async;i++) {
                if (uwsgi.stackless_table[i]->tasklet == tasklet) {
                        return uwsgi.stackless_table[i]->wsgi_req;
                }
        }

        return NULL;
}


PyObject *py_uwsgi_stackless_worker(PyObject * self, PyObject * args) {

	PyThreadState *ts = PyThreadState_GET();
        struct wsgi_request *wsgi_req = find_request_by_tasklet(ts->st.current);
	PyObject *zero;

	int async_id = wsgi_req->async_id;

	//uwsgi_log("i am the tasklet worker\n");

	for(;;) {

		// wait for request
		zero = PyChannel_Receive(uwsgi.workers_channel);

		wsgi_req_setup(wsgi_req, async_id);
		
                if (wsgi_req_accept(uwsgi.serverfd, wsgi_req)) {
                        continue;
                }

		if (wsgi_req_recv(wsgi_req)) {
			continue;
		}

		uwsgi_close_request(&uwsgi, wsgi_req);


	}

}

PyMethodDef uwsgi_stackless_worker[] = { {"uwsgi_stackless_worker", py_uwsgi_stackless_worker, METH_VARARGS, ""} };

void stackless_init(struct uwsgi_server *uwsgi) {

	int i;
	struct wsgi_request* wsgi_req = uwsgi->wsgi_requests ;

	PyObject *tasklet_worker = PyCFunction_New(uwsgi_stackless_worker, NULL);

	uwsgi->workers_channel  = PyChannel_New(NULL);

	uwsgi->stackless_table = malloc( sizeof(struct stackless_req*) * uwsgi->async);
        if (!uwsgi->stackless_table) {
        	uwsgi_error("malloc()");
                exit(1);
        }
        for(i=0;i<uwsgi->async;i++) {
        	uwsgi->stackless_table[i] = malloc(sizeof(struct stackless_req));
                if (!uwsgi->stackless_table[i]) {
                	uwsgi_error("malloc()");
                        exit(1);
                }
		memset(uwsgi->stackless_table[i], 0, sizeof(struct stackless_req));
	}

	uwsgi_log("initializing %d tasklet...", uwsgi->async);

	// creating uwsgi->async tasklets
	for(i=0;i<uwsgi->async;i++) {
		wsgi_req->tasklet = PyTasklet_New(NULL, tasklet_worker);
		uwsgi->stackless_table[i]->tasklet = wsgi_req->tasklet;
		uwsgi->stackless_table[i]->wsgi_req = wsgi_req;
		// useless for now, it will be used for I/O or other messaging
		uwsgi->stackless_table[i]->channel = NULL;
		wsgi_req->async_id = i ;

		PyTasklet_Setup(wsgi_req->tasklet, PyTuple_New(0), NULL);
		//PyTasklet_Run(wsgi_req->tasklet);
		wsgi_req = next_wsgi_req(uwsgi, wsgi_req) ;
	}

	uwsgi_log("done\n");
}

void stackless_loop(struct uwsgi_server *uwsgi) {

	int i;
	PyTaskletObject *int_tasklet;

	// tasklets main loop
	for(;;) {
		//uwsgi->async_running = -1 ;
		//if (PyStackless_GetRunCount() > 0) {
			uwsgi->async_running = 0 ;
		//}
		uwsgi->async_nevents = async_wait(uwsgi->async_queue, uwsgi->async_events, uwsgi->async, uwsgi->async_running, 0);

                if (uwsgi->async_nevents < 0) {
                        continue;
                }

		for(i=0; i<uwsgi->async_nevents;i++) {

                        if (uwsgi->async_events[i].ASYNC_FD == uwsgi->serverfd) {
				//pass the connection to the first available tasklet
				uwsgi_log("sending new connection...\n");
				PyChannel_Send(uwsgi->workers_channel, Py_True);
			}

		}

		/*
		if (PyStackless_GetRunCount() > 0) {
			PyStackless_Schedule(Py_None, 0);
		}
		*/

		PyStackless_RunWatchdogEx( 10, PY_WATCHDOG_TOTALTIMEOUT);

		//int_tasklet = (PyTaskletObject *) PyStackless_RunWatchdog( 1000 );
		/*
		uwsgi_log("done watchdog %p\n", int_tasklet);
		if (!PyTasklet_IsCurrent(int_tasklet)) {
			uwsgi_log("re-insert: %d\n", 1);// PyTasklet_Insert(int_tasklet));
		}
		uwsgi_log("recycle\n");
		*/
	}

}

#endif
