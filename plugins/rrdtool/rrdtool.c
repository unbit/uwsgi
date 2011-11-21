#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;

#define RRDTOOL_OPT_BASE 177000
#define RRDTOOL_OPT_RRDTOOL		RRDTOOL_OPT_BASE+1
#define RRDTOOL_OPT_RRDTOOL_MAX_DS	RRDTOOL_OPT_BASE+2
#define RRDTOOL_OPT_RRDTOOL_FREQ	RRDTOOL_OPT_BASE+3

struct uwsgi_rrdtool {
	void *lib;
	int (*create)(int, char **);
	int (*update)(int, char **);
	struct uwsgi_string_list *rrd;
	int max_ds;
	int freq;

	char *update_area;
} u_rrd;

struct option rrdtool_options[] = {
	{"rrdtool", required_argument, 0, RRDTOOL_OPT_RRDTOOL},
	{"rrdtool-freq", required_argument, 0, RRDTOOL_OPT_RRDTOOL_FREQ},
	{"rrdtool-max-ds", required_argument, 0, RRDTOOL_OPT_RRDTOOL_MAX_DS},
	{0, 0, 0, 0},

};


int rrdtool_init() {

	u_rrd.lib = dlopen("librrd.so", RTLD_LAZY);
	if (!u_rrd.lib) return -1;

	u_rrd.create = dlsym(u_rrd.lib, "rrd_create");
	if (!u_rrd.create) {
		dlclose(u_rrd.lib);
		return -1;
	}

	u_rrd.update = dlsym(u_rrd.lib, "rrd_update");
	if (!u_rrd.update) {
		dlclose(u_rrd.lib);
		return -1;
	}

	if (!u_rrd.max_ds) u_rrd.max_ds = 30;

	uwsgi_log_initial("*** RRDtool library available at %p ***\n", u_rrd.lib);

	return 0;
}

int rrdtool_opt(int i, char *optarg) {

	switch(i) {
		case RRDTOOL_OPT_RRDTOOL:
			uwsgi.master_process = 1;
			uwsgi_string_new_list(&u_rrd.rrd, optarg);
			return 1;
		case RRDTOOL_OPT_RRDTOOL_MAX_DS:
			u_rrd.max_ds = atoi(optarg);
			return 1;
		case RRDTOOL_OPT_RRDTOOL_FREQ:
			u_rrd.freq = atoi(optarg);
			return 1;
	}

	return 0;
}

void rrdtool_post_init() {

	struct uwsgi_string_list *usl = u_rrd.rrd;
	char **argv;
	int i;

	if (!u_rrd.lib || !u_rrd.create) return;

	// do not waste time if no --rrdtool option is defiend
	if (!u_rrd.rrd) return;

	if (uwsgi.numproc > u_rrd.max_ds) {
		uwsgi_log("!!! NOT ENOUGH SLOTS IN RRDTOOL DS TO HOST WORKERS DATA (increase them with --rrdtool-max-ds) !!!\n");
		dlclose(u_rrd.lib);
		return;
	}

	// alloc space for DS_REQ + DS WORKER + RRA + create + filename
	argv = uwsgi_malloc( sizeof(char *) * (1 + u_rrd.max_ds + 4 + 1 +1));

	argv[0] = "create";

	argv[2] = "DS:requests:DERIVE:600:0:U";

	// create DS for workers
	for(i=0;i<u_rrd.max_ds;i++) {
		int max_size = sizeof("DS:worker65536:DERIVE:600:0:U")+1;
		argv[3+i] = uwsgi_malloc( max_size );
		if (snprintf(argv[3+i], max_size, "DS:worker%d:DERIVE:600:0:U", i+1) < 25) {
			uwsgi_log("unable to create args for rrd_create()\n");
			exit(1);
		}
	}

	// create RRA
	argv[3+u_rrd.max_ds] = "RRA:AVERAGE:0.5:1:288" ;
	argv[3+u_rrd.max_ds+1] = "RRA:AVERAGE:0.5:12:168" ;
	argv[3+u_rrd.max_ds+2] = "RRA:AVERAGE:0.5:288:31" ;
	argv[3+u_rrd.max_ds+3] = "RRA:AVERAGE:0.5:2016:52";

	while(usl) {
		if (!uwsgi_file_exists(usl->value)) {
			argv[1] = usl->value;	
			if (u_rrd.create((1 + u_rrd.max_ds + 4 + 1 +1), argv)) {
				uwsgi_error("rrd_create()");
				exit(1);
			}
		}
		usl->value = realpath(usl->value, NULL);
		if (!usl->value) {
			uwsgi_error("realpath()");
			exit(1);
		}
		usl = usl->next;
	}

	// free DS
	for(i=0;i<u_rrd.max_ds;i++) {
		free(argv[3+i]);
	}

	free(argv);

	//now allocate memory for updates
	u_rrd.update_area = uwsgi_malloc( 1+((1+sizeof(UMAX64_STR)) * (u_rrd.max_ds+1))+1 );
	memset(u_rrd.update_area, 0, 1+((1+sizeof(UMAX64_STR)) * (u_rrd.max_ds+1))+1 );

	u_rrd.update_area[0] = 'N';	

	if (u_rrd.freq < 1) u_rrd.freq = 300;

}

void rrdtool_master_cycle() {

	static time_t last_update = 0;
	char *ptr;
	int rlen, i;
	char *argv[3];
	struct uwsgi_string_list *usl = u_rrd.rrd;

	if (!u_rrd.lib || !u_rrd.create || !u_rrd.rrd) return ;

	if (last_update == 0) last_update = time(NULL);

	// update
	if (uwsgi.current_time - last_update >= u_rrd.freq) {
		ptr = u_rrd.update_area+1;
		rlen = snprintf(ptr, 1+sizeof(UMAX64_STR), ":%llu", (unsigned long long )uwsgi.workers[0].requests);
		if (rlen < 2) return;
		ptr+=rlen;
		for(i=0;i<u_rrd.max_ds;i++) {
			if (i+1 <= uwsgi.numproc) {
				rlen = snprintf(ptr, 1+sizeof(UMAX64_STR), ":%llu", (unsigned long long )uwsgi.workers[1+i].requests);
				if (rlen < 2) return;
			}
			else {
				memcpy(ptr, ":U", 2);
				rlen = 2;
			}
			ptr+=rlen;
		}
		last_update = uwsgi.current_time;
		argv[0] = "update";
		argv[2] = u_rrd.update_area;
		while(usl) {
			argv[1] = usl->value;
			if (u_rrd.update(3, argv)) {
				uwsgi_log_verbose("ERROR: rrd_update(\"%s\", \"%s\")\n", argv[1], argv[2]);
			}
			usl = usl->next;
		}
	}
}

struct uwsgi_plugin rrdtool_plugin = {
	
	.options = rrdtool_options,
	.manage_opt = rrdtool_opt,

	.master_cycle = rrdtool_master_cycle,
	
	.post_init = rrdtool_post_init,
	.init = rrdtool_init,
};
