#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;

struct uwsgi_carbon {
	struct uwsgi_string_list *servers;
	int freq;
	int timeout;
	char *id;
	int no_workers;
	unsigned long long *last_busyness_values;
	unsigned long long *current_busyness_values;
} u_carbon;

struct uwsgi_option carbon_options[] = {
	{"carbon", required_argument, 0, "push statistics to the specified carbon server", uwsgi_opt_add_string_list, &u_carbon.servers, UWSGI_OPT_MASTER},
	{"carbon-timeout", required_argument, 0, "set carbon connection timeout", uwsgi_opt_set_int, &u_carbon.timeout, 0},
	{"carbon-freq", required_argument, 0, "set carbon push frequency", uwsgi_opt_set_int, &u_carbon.freq, 0},
	{"carbon-id", required_argument, 0, "set carbon id", uwsgi_opt_set_str, &u_carbon.id, 0},
	{"carbon-no-workers", no_argument, 0, "disable generation of single worker metrics", uwsgi_opt_true, &u_carbon.no_workers, 0},
	{0, 0, 0, 0, 0, 0, 0},

};


void carbon_post_init() {

	int i;
	struct uwsgi_string_list *usl = u_carbon.servers;
	if (!uwsgi.sockets) return;
	if (!u_carbon.servers) return;

	while(usl) {
		uwsgi_log("added carbon server %s\n", usl->value);
		usl = usl->next;
	}

	if (u_carbon.freq < 1) u_carbon.freq = 60;
	if (u_carbon.timeout < 1) u_carbon.timeout = 3;
	if (!u_carbon.id) { 
		u_carbon.id = uwsgi_str(uwsgi.sockets->name);

		for(i=0;i<(int)strlen(u_carbon.id);i++) {
			if (u_carbon.id[i] == '.') u_carbon.id[i] = '_';
		}
	}

	if (!u_carbon.last_busyness_values) {
		u_carbon.last_busyness_values = uwsgi_calloc(sizeof(unsigned long long) * uwsgi.numproc);
	}

	if (!u_carbon.current_busyness_values) {
		u_carbon.current_busyness_values = uwsgi_calloc(sizeof(unsigned long long) * uwsgi.numproc);
	}

}

void carbon_master_cycle() {

	static time_t last_update = 0;
	char ptr[4096];
	int rlen, i;
	int fd;
	struct uwsgi_string_list *usl = u_carbon.servers;

	if (!u_carbon.servers) return ;

	if (last_update == 0) last_update = time(NULL);

	// update
	if (uwsgi.current_time - last_update >= u_carbon.freq) {

		for (i = 0; i < uwsgi.numproc; i++) {
			u_carbon.current_busyness_values[i] = uwsgi.workers[i+1].running_time - u_carbon.last_busyness_values[i];
			u_carbon.last_busyness_values[i] = uwsgi.workers[i+1].running_time;
		}

		while(usl) {
			fd = uwsgi_connect(usl->value, u_carbon.timeout, 0);
			if (fd < 0) goto nxt;
			// put the socket in non-blocking mode
			uwsgi_socket_nb(fd);

			unsigned long long total_rss = 0;
			unsigned long long total_vsz = 0;
			unsigned long long total_tx = 0;
			unsigned long long total_avg_rt = 0; // total avg_rt
			unsigned long long avg_rt = 0; // per worker avg_rt reported to carbon
			unsigned long long active_workers = 0; // number of workers used to calculate total avg_rt
			unsigned long long total_busyness = 0;
			unsigned long long total_avg_busyness = 0;
			unsigned long long worker_busyness = 0;
			unsigned long long total_harakiri = 0;

			rlen = snprintf(ptr, 4096, "uwsgi.%s.%s.requests %llu %llu\n", uwsgi.hostname, u_carbon.id, (unsigned long long ) uwsgi.workers[0].requests, (unsigned long long ) uwsgi.current_time);
			if (rlen < 1) goto clear;
			if (write(fd, ptr, rlen) <= 0) { uwsgi_error("write()"); goto clear;}

			for(i=1;i<=uwsgi.numproc;i++) {
				total_tx += uwsgi.workers[i].tx;
				if (uwsgi.workers[i].cheaped) {
					// also if worker is cheaped than we report its average response time as zero, sending last value might be confusing
					avg_rt = 0;
					worker_busyness = 0;
				}
				else {
					// global average response time is calcucalted from active/idle workers, cheaped workers are excluded, otherwise it is not accurate
					avg_rt = uwsgi.workers[i].avg_response_time;
					active_workers++;
					total_avg_rt += uwsgi.workers[i].avg_response_time;

					// calculate worker busyness
					worker_busyness = ((u_carbon.current_busyness_values[i-1]*100) / (u_carbon.freq*1000000));
					if (worker_busyness > 100) worker_busyness = 100;
					total_busyness += worker_busyness;

					// only running workers are counted in total memory stats
					total_rss += uwsgi.workers[i].rss_size;
					total_vsz += uwsgi.workers[i].vsz_size;

					total_harakiri += uwsgi.workers[i].harakiri_count/2;
				}

				//skip per worker metrics when disabled
				if (u_carbon.no_workers) continue;

				rlen = snprintf(ptr, 4096, "uwsgi.%s.%s.worker%d.requests %llu %llu\n", uwsgi.hostname, u_carbon.id, i, (unsigned long long ) uwsgi.workers[i].requests, (unsigned long long ) uwsgi.current_time);
				if (rlen < 1) goto clear;
				if (write(fd, ptr, rlen) <= 0) { uwsgi_error("write()"); goto clear;}

				rlen = snprintf(ptr, 4096, "uwsgi.%s.%s.worker%d.rss_size %llu %llu\n", uwsgi.hostname, u_carbon.id, i, (unsigned long long ) uwsgi.workers[i].rss_size, (unsigned long long ) uwsgi.current_time);
				if (rlen < 1) goto clear;
				if (write(fd, ptr, rlen) <= 0) { uwsgi_error("write()"); goto clear;}

				rlen = snprintf(ptr, 4096, "uwsgi.%s.%s.worker%d.vsz_size %llu %llu\n", uwsgi.hostname, u_carbon.id, i, (unsigned long long ) uwsgi.workers[i].vsz_size, (unsigned long long ) uwsgi.current_time);
				if (rlen < 1) goto clear;
				if (write(fd, ptr, rlen) <= 0) { uwsgi_error("write()"); goto clear;}

				rlen = snprintf(ptr, 4096, "uwsgi.%s.%s.worker%d.avg_rt %llu %llu\n", uwsgi.hostname, u_carbon.id, i, (unsigned long long ) avg_rt, (unsigned long long ) uwsgi.current_time);
				if (rlen < 1) goto clear;
				if (write(fd, ptr, rlen) <= 0) { uwsgi_error("write()"); goto clear;}

				rlen = snprintf(ptr, 4096, "uwsgi.%s.%s.worker%d.tx %llu %llu\n", uwsgi.hostname, u_carbon.id, i, (unsigned long long ) uwsgi.workers[i].tx, (unsigned long long ) uwsgi.current_time);
				if (rlen < 1) goto clear;
				if (write(fd, ptr, rlen) <= 0) { uwsgi_error("write()"); goto clear;}

				rlen = snprintf(ptr, 4096, "uwsgi.%s.%s.worker%d.busyness %llu %llu\n", uwsgi.hostname, u_carbon.id, i, (unsigned long long ) worker_busyness, (unsigned long long ) uwsgi.current_time);
				if (rlen < 1) goto clear;
				if (write(fd, ptr, rlen) <= 0) { uwsgi_error("write()"); goto clear;}

				rlen = snprintf(ptr, 4096, "uwsgi.%s.%s.worker%d.harakiri %llu %llu\n", uwsgi.hostname, u_carbon.id, i, (unsigned long long ) uwsgi.workers[i].harakiri_count/2, (unsigned long long ) uwsgi.current_time);
				if (rlen < 1) goto clear;
				if (write(fd, ptr, rlen) <= 0) { uwsgi_error("write()"); goto clear;}

			}

			rlen = snprintf(ptr, 4096, "uwsgi.%s.%s.rss_size %llu %llu\n", uwsgi.hostname, u_carbon.id, (unsigned long long ) total_rss, (unsigned long long ) uwsgi.current_time);
			if (rlen < 1) goto clear;
			if (write(fd, ptr, rlen) <= 0) { uwsgi_error("write()"); goto clear;}

			rlen = snprintf(ptr, 4096, "uwsgi.%s.%s.vsz_size %llu %llu\n", uwsgi.hostname, u_carbon.id, (unsigned long long ) total_vsz, (unsigned long long ) uwsgi.current_time);
			if (rlen < 1) goto clear;
			if (write(fd, ptr, rlen) <= 0) { uwsgi_error("write()"); goto clear;}

			rlen = snprintf(ptr, 4096, "uwsgi.%s.%s.avg_rt %llu %llu\n", uwsgi.hostname, u_carbon.id, (unsigned long long ) (active_workers ? total_avg_rt / active_workers : 0), (unsigned long long ) uwsgi.current_time);
			if (rlen < 1) goto clear;
			if (write(fd, ptr, rlen) <= 0) { uwsgi_error("write()"); goto clear;}

			rlen = snprintf(ptr, 4096, "uwsgi.%s.%s.tx %llu %llu\n", uwsgi.hostname, u_carbon.id, (unsigned long long ) total_tx, (unsigned long long ) uwsgi.current_time);
			if (rlen < 1) goto clear;
			if (write(fd, ptr, rlen) <= 0) { uwsgi_error("write()"); goto clear;}

			if (active_workers > 0) {
				total_avg_busyness = total_busyness / active_workers;
				if (total_avg_busyness > 100) total_avg_busyness = 100;
			} else {
				total_avg_busyness = 0;
			}
			rlen = snprintf(ptr, 4096, "uwsgi.%s.%s.busyness %llu %llu\n", uwsgi.hostname, u_carbon.id, (unsigned long long ) total_avg_busyness, (unsigned long long ) uwsgi.current_time);
			if (rlen < 1) goto clear;
			if (write(fd, ptr, rlen) <= 0) { uwsgi_error("write()"); goto clear;}

			rlen = snprintf(ptr, 4096, "uwsgi.%s.%s.active_workers %llu %llu\n", uwsgi.hostname, u_carbon.id, (unsigned long long ) active_workers, (unsigned long long ) uwsgi.current_time);
			if (rlen < 1) goto clear;
			if (write(fd, ptr, rlen) <= 0) { uwsgi_error("write()"); goto clear;}

			if (uwsgi.cheaper) {
				rlen = snprintf(ptr, 4096, "uwsgi.%s.%s.cheaped_workers %llu %llu\n", uwsgi.hostname, u_carbon.id, (unsigned long long ) uwsgi.numproc - active_workers, (unsigned long long ) uwsgi.current_time);
				if (rlen < 1) goto clear;
				if (write(fd, ptr, rlen) <= 0) { uwsgi_error("write()"); goto clear;}
			}

			rlen = snprintf(ptr, 4096, "uwsgi.%s.%s.harakiri %llu %llu\n", uwsgi.hostname, u_carbon.id, (unsigned long long ) total_harakiri, (unsigned long long ) uwsgi.current_time);
			if (rlen < 1) goto clear;
			if (write(fd, ptr, rlen) <= 0) { uwsgi_error("write()"); goto clear;}

clear:
			close(fd);
nxt:
			usl = usl->next;
		}
		last_update = time(NULL);
	}
}

struct uwsgi_plugin carbon_plugin = {

	.name = "carbon",
	
	.options = carbon_options,
	.master_cycle = carbon_master_cycle,
	.post_init = carbon_post_init,
};
