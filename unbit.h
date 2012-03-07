/* taken from http://wiki.unbit.it/UnbitKernel */
struct uidsec_struct {
	/* network limits */
	unsigned short ipv4_tcp_port;
	unsigned short ipv4_udp_port;
	unsigned short ipv4_tcp_control_port;

	int ipv4_tcp_socket_protection;
	unsigned long long ipv4_firewall_mask;

	/* limits */
	int fs_readonly;

	/* process markers */
	int domain_id;
	int fcgi_id;
	int scgi_id;
	int apps_id;
	int wapp_id;
	int ssh_id;
	int cron_id;

	/* thread ? */
	int cloned_vm;

	/* process limit */
	int max_dom_proc;
	int max_apps_proc;
	int max_apps_thread;
	int max_ssh_proc;
	int max_cron_proc;

	/* misc */
	int control_uid;
	int listen_backlog;
	int errors;

	/* counters */
	int accept_cnt;
	int accept_last;

	int fork_cnt;
	int fork_last;

	unsigned long long bio_read;
	unsigned long long bio_write;

	int memory_errors;

};

