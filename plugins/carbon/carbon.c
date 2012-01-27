#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;

#define CARBON_OPT_BASE 178000
#define CARBON_OPT_CARBON		CARBON_OPT_BASE+1
#define CARBON_OPT_CARBON_ID		CARBON_OPT_BASE+2
#define CARBON_OPT_CARBON_FREQ		CARBON_OPT_BASE+3
#define CARBON_OPT_CARBON_TIMEOUT	CARBON_OPT_BASE+4

struct uwsgi_carbon {
	struct uwsgi_string_list *servers;
	int freq;
	int timeout;
	char *id;
} u_carbon;

struct uwsgi_option carbon_options[] = {
/*
	{"carbon", required_argument, 0, CARBON_OPT_CARBON},
	{"carbon-timeout", required_argument, 0, CARBON_OPT_CARBON_TIMEOUT},
	{"carbon-freq", required_argument, 0, CARBON_OPT_CARBON_FREQ},
	{"carbon-id", required_argument, 0, CARBON_OPT_CARBON_ID},
*/
	{0, 0, 0, 0, 0, 0, 0},

};


int carbon_init() {
	return 0;
}

/*
int carbon_opt(int i, char *optarg) {

	switch(i) {
		case CARBON_OPT_CARBON:
			uwsgi.master_process = 1;
			uwsgi_string_new_list(&u_carbon.servers, optarg);
			return 1;
		case CARBON_OPT_CARBON_ID:
			u_carbon.id = optarg;
			return 1;
		case CARBON_OPT_CARBON_FREQ:
			u_carbon.freq = atoi(optarg);
			return 1;
		case CARBON_OPT_CARBON_TIMEOUT:
			u_carbon.timeout = atoi(optarg);
			return 1;
	}

	return 0;
}
*/

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
		while(usl) {
			fd = uwsgi_connect(usl->value, u_carbon.timeout, 0);
			if (fd < 0) goto nxt;
			// put the socket in non-blocking mode
			uwsgi_socket_nb(fd);

			unsigned long long total_rss = 0;
			unsigned long long total_vsz = 0;
			unsigned long long avg_rt = 0;
			unsigned long long total_tx = 0;

			rlen = snprintf(ptr, 4096, "uwsgi.%s.%s.requests %llu %llu\n", uwsgi.hostname, u_carbon.id, (unsigned long long ) uwsgi.workers[0].requests, (unsigned long long ) uwsgi.current_time);
			if (rlen < 1) goto clear;
			if (write(fd, ptr, rlen) <= 0) { uwsgi_error("write()"); goto clear;}

			for(i=1;i<=uwsgi.numproc;i++) {
				rlen = snprintf(ptr, 4096, "uwsgi.%s.%s.worker%d.requests %llu %llu\n", uwsgi.hostname, u_carbon.id, i, (unsigned long long ) uwsgi.workers[i].requests, (unsigned long long ) uwsgi.current_time);
				if (rlen < 1) goto clear;
				if (write(fd, ptr, rlen) <= 0) { uwsgi_error("write()"); goto clear;}

				total_rss += uwsgi.workers[i].rss_size;
				rlen = snprintf(ptr, 4096, "uwsgi.%s.%s.worker%d.rss_size %llu %llu\n", uwsgi.hostname, u_carbon.id, i, (unsigned long long ) uwsgi.workers[i].rss_size, (unsigned long long ) uwsgi.current_time);
				if (rlen < 1) goto clear;
				if (write(fd, ptr, rlen) <= 0) { uwsgi_error("write()"); goto clear;}

				total_vsz += uwsgi.workers[i].vsz_size;
				rlen = snprintf(ptr, 4096, "uwsgi.%s.%s.worker%d.vsz_size %llu %llu\n", uwsgi.hostname, u_carbon.id, i, (unsigned long long ) uwsgi.workers[i].vsz_size, (unsigned long long ) uwsgi.current_time);
				if (rlen < 1) goto clear;
				if (write(fd, ptr, rlen) <= 0) { uwsgi_error("write()"); goto clear;}

				avg_rt += uwsgi.workers[i].avg_response_time;
				rlen = snprintf(ptr, 4096, "uwsgi.%s.%s.worker%d.avg_rt %llu %llu\n", uwsgi.hostname, u_carbon.id, i, (unsigned long long ) uwsgi.workers[i].avg_response_time, (unsigned long long ) uwsgi.current_time);
				if (rlen < 1) goto clear;
				if (write(fd, ptr, rlen) <= 0) { uwsgi_error("write()"); goto clear;}

				total_tx += uwsgi.workers[i].tx;
				rlen = snprintf(ptr, 4096, "uwsgi.%s.%s.worker%d.tx %llu %llu\n", uwsgi.hostname, u_carbon.id, i, (unsigned long long ) uwsgi.workers[i].tx, (unsigned long long ) uwsgi.current_time);
				if (rlen < 1) goto clear;
				if (write(fd, ptr, rlen) <= 0) { uwsgi_error("write()"); goto clear;}
			}

			rlen = snprintf(ptr, 4096, "uwsgi.%s.%s.rss_size %llu %llu\n", uwsgi.hostname, u_carbon.id, (unsigned long long ) total_rss, (unsigned long long ) uwsgi.current_time);
			if (rlen < 1) goto clear;
			if (write(fd, ptr, rlen) <= 0) { uwsgi_error("write()"); goto clear;}

			rlen = snprintf(ptr, 4096, "uwsgi.%s.%s.vsz_size %llu %llu\n", uwsgi.hostname, u_carbon.id, (unsigned long long ) total_vsz, (unsigned long long ) uwsgi.current_time);
			if (rlen < 1) goto clear;
			if (write(fd, ptr, rlen) <= 0) { uwsgi_error("write()"); goto clear;}

			rlen = snprintf(ptr, 4096, "uwsgi.%s.%s.avg_rt %llu %llu\n", uwsgi.hostname, u_carbon.id, (unsigned long long ) avg_rt / uwsgi.numproc, (unsigned long long ) uwsgi.current_time);
			if (rlen < 1) goto clear;
			if (write(fd, ptr, rlen) <= 0) { uwsgi_error("write()"); goto clear;}

			rlen = snprintf(ptr, 4096, "uwsgi.%s.%s.tx %llu %llu\n", uwsgi.hostname, u_carbon.id, (unsigned long long ) total_tx, (unsigned long long ) uwsgi.current_time);
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
	
	.options = carbon_options,

	.master_cycle = carbon_master_cycle,
	
	.post_init = carbon_post_init,
	.init = carbon_init,
};
