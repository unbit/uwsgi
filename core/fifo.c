#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

/*

	the --master-fifo option create a unix named pipe (fifo) you can use to send management
	commands to the master:

	echo r > myfifo

*/

// this var can be accessed by plugins and hooks
void (*uwsgi_fifo_table[256])(int);

/*

this is called as soon as possibile allowing plugins (or hooks) to override it

*/
void uwsgi_master_fifo_prepare() {
	int i;
	for(i=0;i<256;i++) {
		uwsgi_fifo_table[i] = NULL;
	}

	uwsgi_fifo_table['-'] = uwsgi_cheaper_decrease;
	uwsgi_fifo_table['+'] = uwsgi_cheaper_increase;
	uwsgi_fifo_table['c'] = uwsgi_chain_reload;
	uwsgi_fifo_table['C'] = uwsgi_go_cheap;
	uwsgi_fifo_table['f'] = uwsgi_refork_master;
	uwsgi_fifo_table['l'] = uwsgi_log_reopen;
	uwsgi_fifo_table['L'] = uwsgi_log_rotate;
	uwsgi_fifo_table['p'] = suspend_resume_them_all;
	uwsgi_fifo_table['P'] = uwsgi_update_pidfiles;
	uwsgi_fifo_table['q'] = gracefully_kill_them_all;
	uwsgi_fifo_table['Q'] = kill_them_all;
	uwsgi_fifo_table['r'] = grace_them_all;
	uwsgi_fifo_table['R'] = reap_them_all;
	uwsgi_fifo_table['s'] = stats;
	uwsgi_fifo_table['w'] = uwsgi_reload_workers;
	uwsgi_fifo_table['W'] = uwsgi_brutally_reload_workers;

}

int uwsgi_master_fifo(char *path) {

	unlink(path);

	if (mkfifo(path, S_IRUSR|S_IWUSR)) {
		uwsgi_error("uwsgi_master_fifo()/mkfifo()");
		exit(1);
	}

	int fd = open(path, O_RDONLY|O_NONBLOCK);
	if (fd < 0) {
		uwsgi_error("uwsgi_master_fifo()/open()");
		exit(1);
	}

	uwsgi_socket_nb(fd);

	return fd;
}

int uwsgi_master_fifo_manage(int fd) {
	char cmd;
	ssize_t rlen = read(fd, &cmd, 1);
	if (rlen < 0) {
		if (uwsgi_is_again()) return 0;
		uwsgi_error("uwsgi_master_fifo_manage()/read()");
		exit(1);
	}
	// fifo destroyed, recreate it
	else if (rlen == 0) {
		close(fd);
		uwsgi.master_fifo_fd = uwsgi_master_fifo(uwsgi.master_fifo);
		event_queue_add_fd_read(uwsgi.master_queue, uwsgi.master_fifo_fd);
		return 0;
	}

	if (uwsgi_fifo_table[(int) cmd]) {
		uwsgi_fifo_table[(int) cmd](0);
	}
	
	return 0;
}
