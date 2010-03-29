#ifdef UWSGI_UGREEN

/* uGreen -> uWSGI green threads */

/* 

TODO

configurable stack size
io and sleep management

*/

#include "uwsgi.h"

#define GREEN_STACK_SIZE 128 * 1024

extern struct uwsgi_server uwsgi;


static int u_green_blocking(struct uwsgi_server *uwsgi) {
        struct wsgi_request* wsgi_req = uwsgi->wsgi_requests ;
        int i ;

        for(i=0;i<uwsgi->async;i++) {
                if (wsgi_req->async_status != UWSGI_ACCEPTING) {
                        return 0 ;
                }
                wsgi_req = next_wsgi_req(uwsgi, wsgi_req) ;
        }

        return -1 ;
}

inline static void u_green_schedule_to_main(struct uwsgi_server *uwsgi, int async_id) {

	int py_current_recursion_depth;
	struct _frame* py_current_frame;

	PyThreadState* tstate = PyThreadState_GET();	
	py_current_recursion_depth = tstate->recursion_depth;
	py_current_frame = tstate->frame;

	swapcontext(uwsgi->ugreen_contexts[async_id], &uwsgi->ugreenmain);

	tstate = PyThreadState_GET();	
	tstate->recursion_depth = py_current_recursion_depth;
	tstate->frame = py_current_frame ;
}

inline static void u_green_schedule_to_req(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {

	int py_current_recursion_depth;
	struct _frame* py_current_frame;

	PyThreadState* tstate = PyThreadState_GET();	
	py_current_recursion_depth = tstate->recursion_depth;
	py_current_frame = tstate->frame;

	uwsgi->wsgi_req = wsgi_req;
	wsgi_req->async_switches++;
	swapcontext(&uwsgi->ugreenmain, uwsgi->ugreen_contexts[wsgi_req->async_id] );

	tstate = PyThreadState_GET();	
	tstate->recursion_depth = py_current_recursion_depth;
	tstate->frame = py_current_frame ;
}

PyObject *py_uwsgi_green_schedule(PyObject * self, PyObject * args) {

        struct wsgi_request *wsgi_req = current_wsgi_req(&uwsgi);

	u_green_schedule_to_main(&uwsgi, wsgi_req->async_id);

	Py_INCREF(Py_True);
	return Py_True;

}

PyMethodDef uwsgi_green_methods[] = {
	{"green_schedule", py_uwsgi_green_schedule, METH_VARARGS, ""},
	{ NULL, NULL }
};

static struct wsgi_request *find_first_accepting_wsgi_req(struct uwsgi_server *uwsgi) {

        struct wsgi_request* wsgi_req = uwsgi->wsgi_requests ;
        int i ;

        for(i=0;i<uwsgi->async;i++) {
                if (wsgi_req->async_status == UWSGI_ACCEPTING) {
                        return wsgi_req ;
                }
                wsgi_req = next_wsgi_req(uwsgi, wsgi_req) ;
        }

        return NULL ;
}


static void u_green_request(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req, int async_id) {


	for(;;) {
		wsgi_req_setup(wsgi_req, async_id);

		wsgi_req->async_status = UWSGI_ACCEPTING;

		u_green_schedule_to_main(uwsgi, async_id);

		if (wsgi_req_accept(uwsgi->serverfd, wsgi_req)) {
                        continue;
                }
		wsgi_req->async_status = UWSGI_OK;

		u_green_schedule_to_main(uwsgi, async_id);

                if (wsgi_req_recv(wsgi_req)) {
                        continue;
                }

		while(wsgi_req->async_status == UWSGI_AGAIN) {
			u_green_schedule_to_main(uwsgi, async_id);
			wsgi_req->async_status = (*uwsgi->shared->hooks[wsgi_req->modifier]) (uwsgi, wsgi_req);
		}

		u_green_schedule_to_main(uwsgi, async_id);

                uwsgi_close_request(uwsgi, wsgi_req);

	}

}

void u_green_init(struct uwsgi_server *uwsgi) {

	struct wsgi_request *wsgi_req = uwsgi->wsgi_requests ;

	int i;


	PyMethodDef *uwsgi_function;

	fprintf(stderr,"initializing %d uGreen threads with stack size of %lu (%lu KB)\n", uwsgi->async, (unsigned long) GREEN_STACK_SIZE,  (unsigned long) GREEN_STACK_SIZE/1024);


	uwsgi->ugreen_contexts = malloc( sizeof(ucontext_t*) * uwsgi->async);
	if (!uwsgi->ugreen_contexts) {
		perror("malloc()\n");
		exit(1);
	}


	for(i=0;i<uwsgi->async;i++) {
		uwsgi->ugreen_contexts[i] = malloc( sizeof(ucontext_t) );
		if (!uwsgi->ugreen_contexts[i]) {
			perror("malloc()");
			exit(1);
		}
		getcontext(uwsgi->ugreen_contexts[i]);
		uwsgi->ugreen_contexts[i]->uc_stack.ss_sp = mmap(NULL, GREEN_STACK_SIZE + uwsgi->page_size*2 , PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0) + uwsgi->page_size;
		if (!uwsgi->ugreen_contexts[i]->uc_stack.ss_sp) {
			perror("mmap()");
			exit(1);
		}
		// set guard pages for stack
		if (mprotect(uwsgi->ugreen_contexts[i]->uc_stack.ss_sp - uwsgi->page_size, uwsgi->page_size, PROT_NONE)) {
			perror("mprotect()");
			exit(1);
		}
		if (mprotect(uwsgi->ugreen_contexts[i]->uc_stack.ss_sp + GREEN_STACK_SIZE, uwsgi->page_size, PROT_NONE)) {
			perror("mprotect()");
			exit(1);
		}
		uwsgi->ugreen_contexts[i]->uc_stack.ss_size = GREEN_STACK_SIZE ;
		uwsgi->ugreen_contexts[i]->uc_link = NULL;
		makecontext(uwsgi->ugreen_contexts[i], (void (*) (void)) &u_green_request, 3, uwsgi, wsgi_req, i);
		wsgi_req->async_status = UWSGI_ACCEPTING;
		wsgi_req->async_id = i;
		wsgi_req = next_wsgi_req(uwsgi, wsgi_req) ;
	}

	for (uwsgi_function = uwsgi_green_methods; uwsgi_function->ml_name != NULL; uwsgi_function++) {
                PyObject *func = PyCFunction_New(uwsgi_function, NULL);
                PyDict_SetItemString(uwsgi->embedded_dict, uwsgi_function->ml_name, func);
                Py_DECREF(func);
        }
}


void u_green_loop(struct uwsgi_server *uwsgi) {

	struct wsgi_request *wsgi_req = uwsgi->wsgi_requests ;

	int i, current = 0 ;

	while(uwsgi->workers[uwsgi->mywid].manage_next_request) {

		uwsgi->async_running = u_green_blocking(uwsgi) ;

                uwsgi->async_nevents = async_wait(uwsgi->async_queue, uwsgi->async_events, uwsgi->async, uwsgi->async_running, 0);

                if (uwsgi->async_nevents < 0) {
                        continue;
                }

		if (uwsgi->async_nevents > 0) {
			wsgi_req = find_first_accepting_wsgi_req(uwsgi);
			if (!wsgi_req) goto cycle;
		}

                for(i=0; i<uwsgi->async_nevents;i++) {

                        if (uwsgi->async_events[i].ASYNC_FD == uwsgi->serverfd) {
				u_green_schedule_to_req(uwsgi, wsgi_req);
                        }

                }

cycle:
		wsgi_req = find_wsgi_req_by_id(uwsgi, current) ;
		if (wsgi_req->async_status != UWSGI_ACCEPTING) {
			u_green_schedule_to_req(uwsgi, wsgi_req);
		}
		current++;
		if (current >= uwsgi->async) current = 0;

	}

	if (uwsgi->workers[uwsgi->mywid].manage_next_request == 0) {
                reload_me();
        }
        else {
                goodbye_cruel_world();
        }

	// never here
	
}

#endif
