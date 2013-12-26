#include "../../uwsgi.h"

/*

	This plugins is meant as an example for custom implementations.

        -- Copy of Cheaper,  backlog algorithm (supported only on Linux) --

        increse the number of workers when the listen queue is higher than uwsgi.cheaper_overload.
        Decrese when lower.

*/

extern struct uwsgi_server uwsgi;

int cheaper_backlog2_algo(int can_spawn) {

        int i;
#ifdef __linux__
        int backlog = uwsgi.socket_timeout;
#else
        int backlog = 0;
#endif

        // if can_spawn == 0 we cannot spawn any new worker
        // this is set to 1 if --cheaper-rss-limit-* options are used and running workers are exceeding resources limit
        if (can_spawn && backlog > (int)uwsgi.cheaper_overload) {
                // activate the first available worker (taking step into account)
                int decheaped = 0;
                // search for cheaped workers
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
        else if (backlog < (int) uwsgi.cheaper_overload) {
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
void uwsgi_cheaper_register_backlog2(void) {
	uwsgi_register_cheaper_algo("backlog2", cheaper_backlog2_algo);
}

struct uwsgi_plugin cheaper_backlog2_plugin = {

	.name = "cheaper_backlog2",
        .on_load = uwsgi_cheaper_register_backlog2,
	
};
