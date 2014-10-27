/*

   uWSGI forkpty-router

   can use the uwsgi protocol, modifier2 means:

	0 -> stdin
	1-99 -> UNIX signal
	100 -> window rows (pktsize is the window size)
	101 -> window cols (pktsize is the window size)

*/

#include <uwsgi.h>
#include "../corerouter/cr.h"

extern struct uwsgi_server uwsgi;

#if defined(__linux__) || defined(__GNU_kFreeBSD__) || defined(__HURD__)
#include <pty.h>
#elif defined(__APPLE__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <util.h>
#elif defined(__FreeBSD__) || defined(__DragonFly__)
#include <libutil.h>
#endif
#if !defined(__FreeBSD__) && !defined(__DragonFly__)
#include <utmp.h>
#endif


static struct uwsgi_forkptyrouter {
	struct uwsgi_corerouter cr;
	char *cmd;
	uint16_t win_rows;
	uint16_t win_cols;
} ufpty;

extern struct uwsgi_server uwsgi;

struct forkptyrouter_session {
	struct corerouter_session session;
	// use the uwsgi protocol ?
	int uwsgi;
	size_t restore_size;
	struct winsize w;
	pid_t pid;
};

static void uwsgi_opt_forkpty_urouter(char *opt, char *value, void *cr) {
        struct uwsgi_corerouter *ucr = (struct uwsgi_corerouter *) cr;
        struct uwsgi_gateway_socket *ugs = uwsgi_new_gateway_socket(value, ucr->name);
        ugs->no_defer = 1;
	ugs->mode = 1;
        ucr->has_sockets++;
}


static struct uwsgi_option forkptyrouter_options[] = {
	{"forkptyrouter", required_argument, 0, "run the forkptyrouter on the specified address", uwsgi_opt_undeferred_corerouter, &ufpty, 0},
	{"forkpty-router", required_argument, 0, "run the forkptyrouter on the specified address", uwsgi_opt_undeferred_corerouter, &ufpty, 0},

	{"forkptyurouter", required_argument, 0, "run the forkptyrouter on the specified address", uwsgi_opt_forkpty_urouter, &ufpty, 0},
	{"forkpty-urouter", required_argument, 0, "run the forkptyrouter on the specified address", uwsgi_opt_forkpty_urouter, &ufpty, 0},

	{"forkptyrouter-command", required_argument, 0, "run the specified command on every connection (default: /bin/sh)", uwsgi_opt_set_str, &ufpty.cmd, 0},
	{"forkpty-router-command", required_argument, 0, "run the specified command on every connection (default: /bin/sh)", uwsgi_opt_set_str, &ufpty.cmd, 0},
	{"forkptyrouter-cmd", required_argument, 0, "run the specified command on every connection (default: /bin/sh)", uwsgi_opt_set_str, &ufpty.cmd, 0},
	{"forkpty-router-cmd", required_argument, 0, "run the specified command on every connection (default: /bin/sh)", uwsgi_opt_set_str, &ufpty.cmd, 0},

	{"forkptyrouter-rows", required_argument, 0, "set forkptyrouter default pty window rows", uwsgi_opt_set_16bit, &ufpty.win_rows, 0},
	{"forkptyrouter-cols", required_argument, 0, "set forkptyrouter default pty window cols", uwsgi_opt_set_16bit, &ufpty.win_cols, 0},

	{"forkptyrouter-processes", required_argument, 0, "prefork the specified number of forkptyrouter processes", uwsgi_opt_set_int, &ufpty.cr.processes, 0},
	{"forkptyrouter-workers", required_argument, 0, "prefork the specified number of forkptyrouter processes", uwsgi_opt_set_int, &ufpty.cr.processes, 0},
	{"forkptyrouter-zerg", required_argument, 0, "attach the forkptyrouter to a zerg server", uwsgi_opt_corerouter_zerg, &ufpty, 0},

	{"forkptyrouter-fallback", required_argument, 0, "fallback to the specified node in case of error", uwsgi_opt_add_string_list, &ufpty.cr.fallback, 0},

	{"forkptyrouter-events", required_argument, 0, "set the maximum number of concufptyent events", uwsgi_opt_set_int, &ufpty.cr.nevents, 0},
	{"forkptyrouter-cheap", no_argument, 0, "run the forkptyrouter in cheap mode", uwsgi_opt_true, &ufpty.cr.cheap, 0},

	{"forkptyrouter-timeout", required_argument, 0, "set forkptyrouter timeout", uwsgi_opt_set_int, &ufpty.cr.socket_timeout, 0},

	{"forkptyrouter-stats", required_argument, 0, "run the forkptyrouter stats server", uwsgi_opt_set_str, &ufpty.cr.stats_server, 0},
	{"forkptyrouter-stats-server", required_argument, 0, "run the forkptyrouter stats server", uwsgi_opt_set_str, &ufpty.cr.stats_server, 0},
	{"forkptyrouter-ss", required_argument, 0, "run the forkptyrouter stats server", uwsgi_opt_set_str, &ufpty.cr.stats_server, 0},
	{"forkptyrouter-harakiri", required_argument, 0, "enable forkptyrouter harakiri", uwsgi_opt_set_int, &ufpty.cr.harakiri, 0},

	{0, 0, 0, 0, 0, 0, 0},
};

// write to backend
static ssize_t fpty_instance_write(struct corerouter_peer *peer) {
	struct forkptyrouter_session *fpty_session = (struct forkptyrouter_session *) peer->session;
	ssize_t len = cr_write(peer, "fpty_instance_write()");
	// end on empty write
	if (!len) return 0;

	// the chunk has been sent, start (again) reading from client and instances
	if (cr_write_complete(peer)) {
		// reset the buffer
		if (fpty_session->uwsgi) {
			if (uwsgi_buffer_decapitate(peer->out, peer->out->pos)) return -1;
			peer->out->pos = fpty_session->restore_size;
		}
		else {
			peer->out->pos = 0;
		}
		cr_reset_hooks(peer);
	}

	return len;
}

// write to client
static ssize_t fpty_write(struct corerouter_peer *main_peer) {
	ssize_t len = cr_write(main_peer, "fpty_write()");
	// end on empty write
	if (!len) return 0;

	// ok this response chunk is sent, let's start reading again
	if (cr_write_complete(main_peer)) {
		// reset the buffer
		main_peer->out->pos = 0;
                cr_reset_hooks(main_peer);
        } 

	return len;
}

static ssize_t fpty_parse_uwsgi(struct corerouter_peer *peer) {
	
	struct forkptyrouter_session *fpty_session = (struct forkptyrouter_session *) peer->session;
	for(;;) {
	if (peer->in->pos < 4) return 0;
	struct uwsgi_header *uh = (struct uwsgi_header *) peer->in->buf;
	uint16_t pktsize = uh->pktsize;
	switch(uh->modifier2) {
		case 0:
			// stdin
			if ((size_t) (pktsize+4) > peer->in->pos) return 0;
			if (uwsgi_buffer_decapitate(peer->in, 4)) return -1;
			return pktsize;		
		case 100:	
			if (uwsgi_buffer_decapitate(peer->in, 4)) return -1;
			fpty_session->w.ws_row = pktsize;
			ioctl(peer->session->peers->fd, TIOCSWINSZ, &fpty_session->w);
			// rows
			break;
		case 101:
			if (uwsgi_buffer_decapitate(peer->in, 4)) return -1;
			fpty_session->w.ws_col = pktsize;
			ioctl(peer->session->peers->fd, TIOCSWINSZ, &fpty_session->w);
			// cols
			break;
		default:
			if (uwsgi_buffer_decapitate(peer->in, 4)) return -1;
			// send signal
			kill(fpty_session->pid, uh->modifier2);
			break;
	}
	}

	return 0;
}

// read from backend
static ssize_t fpty_instance_read(struct corerouter_peer *peer) {
	ssize_t len = cr_read(peer, "fpty_instance_read()");
	if (!len) return 0;

	// set the input buffer as the main output one
	peer->session->main_peer->out = peer->in;
	peer->session->main_peer->out_pos = 0;

	cr_write_to_main(peer, fpty_write);
	return len;
}

// read from client
static ssize_t fpty_read(struct corerouter_peer *main_peer) {
        struct forkptyrouter_session *fpty_session = (struct forkptyrouter_session *) main_peer->session;
	ssize_t len = cr_read(main_peer, "fpty_read()");
	if (!len) return 0;

	if (fpty_session->uwsgi) {
		ssize_t rlen = fpty_parse_uwsgi(main_peer);
		if (rlen < 0) return -1;
		if (rlen == 0) return 1;

		fpty_session->restore_size = main_peer->in->pos - rlen;	
		main_peer->session->peers->out = main_peer->in;
		main_peer->session->peers->out->pos = rlen;
	}
	else {
		main_peer->session->peers->out = main_peer->in;
	}
	main_peer->session->peers->out_pos = 0;

	cr_write_to_backend(main_peer->session->peers, fpty_instance_write);
	return len;
}

static void fpty_session_close(struct corerouter_session *cs) {
        struct forkptyrouter_session *fpty_session = (struct forkptyrouter_session *) cs;
	if (fpty_session->pid > 0) {
		int waitpid_status = 0;
		if (waitpid(fpty_session->pid, &waitpid_status, WNOHANG) < 0) {
			uwsgi_error("fpty_session_close()/waitpid()");
		}
	}
}


// allocate a new session
static int forkptyrouter_alloc_session(struct uwsgi_corerouter *ucr, struct uwsgi_gateway_socket *ugs, struct corerouter_session *cs, struct sockaddr *sa, socklen_t s_len) {

	// set default read hook
	cs->main_peer->last_hook_read = fpty_read;

	// wait4() on close
	cs->close = fpty_session_close;

	struct forkptyrouter_session *fpty_session = (struct forkptyrouter_session *) cs;
	if (ugs->mode == 1) {
		fpty_session->uwsgi = 1;
	}

	// default terminal size
	fpty_session->w.ws_row = ufpty.win_rows ? ufpty.win_rows : 24;
	fpty_session->w.ws_col = ufpty.win_cols ? ufpty.win_cols : 80;

	// add a new peer
	struct corerouter_peer *peer = uwsgi_cr_peer_add(cs);

	// on new connection generate a new pty
	fpty_session->pid = forkpty(&peer->fd, NULL, NULL, &fpty_session->w);
	if (fpty_session->pid < 0) {
		uwsgi_error("forkpty()");
		return -1;
	}
	else if (fpty_session->pid == 0) {
		if (ufpty.cmd) {
			char *space = strchr(ufpty.cmd, ' ');
			if (space) {
				char *argv[4];
				argv[0] = uwsgi_binsh();
				argv[1] = "-c";	
				argv[2] = ufpty.cmd;	
				argv[3] = NULL;	
				execv(argv[0], argv);
			}
			else {
				char *argv[2];
				argv[0] = ufpty.cmd;
				argv[1] = NULL;	
				execv(argv[0], argv);
			}
		}
		else {
			char *argv[2];
			argv[0] = "/bin/sh";
			argv[1] = NULL;	
			execv(argv[0], argv);
		}
		// never here;
		uwsgi_error("forkptyrouter_alloc_session()/execv()");
		exit(1);
	}

	ucr->cr_table[peer->fd] = peer;
	cr_reset_hooks_and_read(peer, fpty_instance_read);
	return 0;
}

static int forkptyrouter_init() {

	ufpty.cr.session_size = sizeof(struct forkptyrouter_session);
	ufpty.cr.alloc_session = forkptyrouter_alloc_session;
	uwsgi_corerouter_init((struct uwsgi_corerouter *) &ufpty);

	return 0;
}

static void forkptyrouter_setup() {
	ufpty.cr.name = uwsgi_str("uWSGI forkptyrouter");
	ufpty.cr.short_name = uwsgi_str("forkptyrouter");
}

struct uwsgi_plugin forkptyrouter_plugin = {

	.name = "forkptyrouter",
	.options = forkptyrouter_options,
	.init = forkptyrouter_init,
	.on_load = forkptyrouter_setup
};
