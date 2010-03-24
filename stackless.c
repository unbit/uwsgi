#ifdef UWSGI_STACKLESS

#include "uwsgi.h"

// put global for now
PyChannelObject *workers_channel ;

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

	struct sockaddr_un c_addr;
        int c_len = sizeof(struct sockaddr_un);
	int async_id = wsgi_req->async_id;

	//fprintf(stderr,"i am the tasklet worker\n");

	for(;;) {

		zero = PyChannel_Receive(workers_channel);


		wsgi_req->poll.events = POLLIN;
                wsgi_req->app_id = uwsgi.default_app;
                wsgi_req->async_id = async_id;
#ifdef UWSGI_SENDFILE
                wsgi_req->sendfile_fd = -1;
#endif
                wsgi_req->hvec = &uwsgi.async_hvec[wsgi_req->async_id];

                wsgi_req->poll.fd = accept(uwsgi.serverfd, (struct sockaddr *) &c_addr, (socklen_t *) & c_len);

                if (wsgi_req->poll.fd < 0) {
                        perror("accept()");
                        continue;
                }

		fprintf(stderr,"tasklet %d received a request\n", wsgi_req->async_id);

                UWSGI_SET_IN_REQUEST;

                if (uwsgi.shared->options[UWSGI_OPTION_LOGGING])
                        gettimeofday(&wsgi_req->start_of_request, NULL);

                if (!uwsgi_parse_response(&wsgi_req->poll, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT], (struct uwsgi_header *) wsgi_req, &wsgi_req->buffer)) {
                        continue;
                }

                // enter harakiri mode
                if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0) {
                        set_harakiri(uwsgi.shared->options[UWSGI_OPTION_HARAKIRI]);
                }

                wsgi_req->async_status = (*uwsgi.shared->hooks[wsgi_req->modifier]) (&uwsgi, wsgi_req);

		uwsgi_close_request(&uwsgi, wsgi_req);


	}

}

PyMethodDef uwsgi_stackless_worker[] = { {"uwsgi_stackless_worker", py_uwsgi_stackless_worker, METH_VARARGS, ""} };

void stackless_loop(struct uwsgi_server *uwsgi) {

	struct wsgi_request* wsgi_req = uwsgi->wsgi_requests ;
	int i;

	PyObject *tasklet_worker = PyCFunction_New(uwsgi_stackless_worker, NULL);


	// creating channel
	//PyChannelObject *workers_channel  = PyChannel_New(NULL);
	workers_channel  = PyChannel_New(NULL);

	uwsgi->stackless_table = malloc( sizeof(struct stackless_req*) * uwsgi->async);
        if (!uwsgi->stackless_table) {
        	perror("malloc()");
                exit(1);
        }
        for(i=0;i<uwsgi->async;i++) {
        	uwsgi->stackless_table[i] = malloc(sizeof(struct stackless_req));
                if (!uwsgi->stackless_table[i]) {
                	perror("malloc()");
                        exit(1);
                }
	}

	fprintf(stderr,"initializing %d tasklet...", uwsgi->async);

	// creating uwsgi->async tasklets
	for(i=0;i<uwsgi->async;i++) {
		wsgi_req->tasklet = PyTasklet_New(NULL, tasklet_worker);
		uwsgi->stackless_table[i]->tasklet = wsgi_req->tasklet;
		uwsgi->stackless_table[i]->wsgi_req = wsgi_req;
		uwsgi->stackless_table[i]->channel = workers_channel;
		wsgi_req->async_id = i ;
		//fprintf(stderr,"tasklet %d %p\n", i, wsgi_req->tasklet);
		// put i in the python args
		PyTasklet_Setup(wsgi_req->tasklet, PyTuple_New(0), NULL);
		//PyTasklet_Run(wsgi_req->tasklet);
		wsgi_req = next_wsgi_req(uwsgi, wsgi_req) ;
	}

	fprintf(stderr,"done\n");

	// tasklets initialized, go to main loop
	for(;;) {
		//fprintf(stderr,"restarting loop\n");
		uwsgi->async_running = 0 ;
		uwsgi->async_nevents = async_wait(uwsgi->async_queue, uwsgi->async_events, uwsgi->async, uwsgi->async_running, 0);

                if (uwsgi->async_nevents < 0) {
                        continue;
                }

		for(i=0; i<uwsgi->async_nevents;i++) {

                        if (uwsgi->async_events[i].ASYNC_FD == uwsgi->serverfd) {
				//pass the connection to the first available tasklet
				PyChannel_Send(workers_channel, Py_True);
			}

		}

		if (PyStackless_GetRunCount() > 0) {
			PyStackless_Schedule(Py_None, 0);
		}
	}

}

#endif
