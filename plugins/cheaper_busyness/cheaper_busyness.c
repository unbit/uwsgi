#include "../../uwsgi.h"

/*

	Busyness cheaper algorithm (by Łukasz Mierzwa)

*/

extern struct uwsgi_server uwsgi;

// this global struct containes all of the relevant values
struct uwsgi_cheaper_busyness_global {
	uint64_t busyness;
	uint64_t *last_values;
	uint64_t *current_values;
	uint64_t tcheck;
	uint64_t overload;
} uwsgi_cheaper_busyness_global;

struct uwsgi_option uwsgi_cheaper_busyness_options[] = {

        {"cheaper-busyness", required_argument, 0, "set the cheaper busyness percent limit (default 50)", uwsgi_opt_set_64bit, &uwsgi_cheaper_busyness_global, 0},
        {0, 0, 0, 0, 0, 0 ,0},

};


int cheaper_busyness_algo(void) {

	int i;
	// we use microseconds
	uint64_t t = uwsgi.cheaper_overload*1000000;
	int overload = 0;

	// this happens on the first run, the required memory is allocated
	if (!uwsgi_cheaper_busyness_global.last_values) {
		uwsgi_cheaper_busyness_global.last_values = uwsgi_calloc(sizeof(uint64_t) * uwsgi.numproc);
	}

	if (!uwsgi_cheaper_busyness_global.current_values) {
		uwsgi_cheaper_busyness_global.current_values = uwsgi_calloc(sizeof(uint64_t) * uwsgi.numproc);
	}

	// set 50% by default
	if (!uwsgi_cheaper_busyness_global.busyness) uwsgi_cheaper_busyness_global.busyness = 50;

	// initialize with current time
	if (uwsgi_cheaper_busyness_global.tcheck == 0) uwsgi_cheaper_busyness_global.tcheck = uwsgi_micros();

	for (i = 0; i < uwsgi.numproc; i++) {
		uwsgi_cheaper_busyness_global.current_values[i] += uwsgi.workers[i+1].running_time-uwsgi_cheaper_busyness_global.last_values[i];
		uwsgi_cheaper_busyness_global.last_values[i] = uwsgi.workers[i+1].running_time;
	}

	uint64_t now = uwsgi_micros();
	if (now - uwsgi_cheaper_busyness_global.tcheck >= t) {
		uwsgi_cheaper_busyness_global.tcheck = now;
		for (i = 0; i < uwsgi.numproc; i++) {
			// calculate the busyness %
			uint64_t percent = ((uwsgi_cheaper_busyness_global.current_values[i]*100)/t);
			// overload detected ?
			if (percent >= uwsgi_cheaper_busyness_global.busyness) {
				uwsgi_cheaper_busyness_global.overload++;
				overload = 1;
			}
			uwsgi_cheaper_busyness_global.current_values[i] = 0;
		}
		// decrease load
		if (uwsgi_cheaper_busyness_global.overload > 0) {
			uwsgi_cheaper_busyness_global.overload--;
		}
		// load came back to 0, let's remove workers if needed
		if (uwsgi_cheaper_busyness_global.overload == 0) {
			overload = -1;
		}
	}	

	// here we choose what to do based on the overload value
	if (overload > 0)  {
        	int decheaped = 0;
        	for (i = 1; i <= uwsgi.numproc; i++) {
        		if (uwsgi.workers[i].cheaped == 1 && uwsgi.workers[i].pid == 0) {
                	decheaped++;
                	if (decheaped >= uwsgi.cheaper_step)
                		break;
                	}
		}
                // return the maximum number of workers to spawn
                return decheaped;

        }
        else if (overload < 0) {
		// count active workers
                int active_workers = 0;
                for (i = 1; i <= uwsgi.numproc; i++) {
                        if (uwsgi.workers[i].cheaped == 0 && uwsgi.workers[i].pid > 0) {
                                active_workers++;
                        }
                }

		// cheap a worker if too much are running
                if (active_workers > uwsgi.cheaper_count) {
                        return -1;
                }
        }

        return 0;
}



// registration hook
void uwsgi_cheaper_register_busyness(void) {
	uwsgi_register_cheaper_algo("busyness", cheaper_busyness_algo);
}

struct uwsgi_plugin cheaper_busyness_plugin = {

	.name = "cheaper_busyness",
        .on_load = uwsgi_cheaper_register_busyness,
	.options = uwsgi_cheaper_busyness_options,
	
};
