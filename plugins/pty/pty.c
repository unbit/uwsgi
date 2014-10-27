#include <uwsgi.h>
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

extern struct uwsgi_server uwsgi;

struct uwsgi_pty_client {
	int fd;
	struct uwsgi_pty_client *prev;
	struct uwsgi_pty_client *next;
};

static struct uwsgi_pty {
	char *addr;
	char *remote;
	char *uremote;
	int queue;
	int server_fd;
	int master_fd;
	int slave_fd;
	int log;
	int original_log;
	int input;
	int original_input;
	int no_isig;
	char *command;
	pid_t command_pid;
	struct uwsgi_pty_client *head;
	struct uwsgi_pty_client *tail;
} upty;

static struct uwsgi_pty_client *uwsgi_pty_client_new(int fd) {
	struct uwsgi_pty_client *upc = uwsgi_calloc(sizeof(struct uwsgi_pty_client));
	upc->fd = fd;
	if (upty.tail) {
		upc->prev = upty.tail;
		upty.tail->next = upc;
	}
	upty.tail = upc;
	if (!upty.head) upty.head = upc;
	return upc;
}

static void uwsgi_pty_client_remove(struct uwsgi_pty_client *upc) {
	struct uwsgi_pty_client *prev = upc->prev;
	struct uwsgi_pty_client *next = upc->next;

	if (prev) {
		prev->next = next;
	}

	if (next) {
		next->prev = prev;
	}

	if (upc == upty.head) {
		upty.head = next;
	}

	if (upc == upty.tail) {
		upty.tail = prev;
	}

	close(upc->fd);
	free(upc);
}

static struct uwsgi_option uwsgi_pty_options[] = {
	{"pty-socket", required_argument, 0, "bind the pty server on the specified address", uwsgi_opt_set_str, &upty.addr, 0},
	{"pty-log", no_argument, 0, "send stdout/stderr to the log engine too", uwsgi_opt_true, &upty.log, 0},
	{"pty-input", no_argument, 0, "read from original stdin in addition to pty", uwsgi_opt_true, &upty.input, 0},
	{"pty-connect", required_argument, 0, "connect the current terminal to a pty server", uwsgi_opt_set_str, &upty.remote, UWSGI_OPT_NO_INITIAL},
	{"pty-uconnect", required_argument, 0, "connect the current terminal to a pty server (using uwsgi protocol)", uwsgi_opt_set_str, &upty.uremote, UWSGI_OPT_NO_INITIAL},
	{"pty-no-isig", no_argument, 0, "disable ISIG terminal attribute in client mode", uwsgi_opt_true, &upty.no_isig, 0},
	{"pty-exec", required_argument, 0, "run the specified command soon after the pty thread is spawned", uwsgi_opt_set_str, &upty.command, 0},
	{0, 0, 0, 0, 0, 0, 0},
};

void uwsgi_pty_setterm(int fd) {
	struct termios tio;
        tcgetattr(fd, &tio);

        tio.c_iflag |= IGNPAR;
        tio.c_iflag &= ~(ISTRIP | IMAXBEL | BRKINT | INLCR | IGNCR | ICRNL | IXON | IXANY | IXOFF);
#ifdef IUCLC
        tio.c_iflag &= ~IUCLC;
#endif
        tio.c_lflag &= ~(ICANON | ECHO | ECHOE | ECHOK | ECHONL);
	if (upty.no_isig) {
		tio.c_lflag &= ~(ISIG);
	}
#ifdef IEXTEN
        tio.c_lflag &= ~IEXTEN;
#endif
        tio.c_oflag &= ~OPOST;
        tio.c_cc[VMIN] = 1;
        tio.c_cc[VTIME] = 0;

#ifdef B38400
	cfsetispeed(&tio, B38400);
	cfsetospeed(&tio, B38400);
#endif

        tcsetattr(fd, TCSANOW, &tio);
}

static void *uwsgi_pty_loop(void *arg) {

	/*
                if slave is ready there is something to send to the clients (and logs)

                if client is ready we have something to write to the master pty
        */

	// block signals on this thread
        sigset_t smask;
        sigfillset(&smask);
#ifndef UWSGI_DEBUG
        sigdelset(&smask, SIGSEGV);
#endif
        pthread_sigmask(SIG_BLOCK, &smask, NULL);

        for(;;) {
                char buf[8192];
                int interesting_fd = -1;
                int ret = event_queue_wait(upty.queue, -1, &interesting_fd);
                if (ret == 0) continue;
                if (ret < 0) continue;

		if (upty.input && interesting_fd == upty.original_input) {
			ssize_t rlen = read(upty.original_input, buf, 8192);
                        if (rlen <= 0) continue;
                        if (write(upty.master_fd, buf, rlen) != rlen) {
				// what to do ?
                        }
			continue;
		}

                if (interesting_fd == upty.master_fd) {
                        ssize_t rlen = read(upty.master_fd, buf, 8192);
                        if (rlen == 0) exit(1);
                        if (rlen < 0) {
                                uwsgi_error("uwsgi_pty_loop()/read()");
				continue;
                        }
			if (upty.log && upty.original_log >= 0) {
                        	if (write(upty.original_log, buf, rlen) != rlen) {
					// what to do ?
                        	}
			}
			struct uwsgi_pty_client *upc = upty.head;	
			while(upc) {
                        	if (write(upc->fd, buf, rlen) != rlen) {
					struct uwsgi_pty_client *tmp_upc = upc->next;
					uwsgi_pty_client_remove(upc);	
					upc = tmp_upc;
					continue;
				}
				upc = upc->next;
			}
                        continue;
                }

                if (interesting_fd == upty.server_fd) {
                        struct sockaddr_un client_src;
			memset(&client_src, 0, sizeof(struct sockaddr_un));
                        socklen_t client_src_len = 0;

                        int client_fd = accept(upty.server_fd, (struct sockaddr *) &client_src, &client_src_len);
                        if (client_fd < 0) {
                                uwsgi_error("accept()");
				continue;
                        }
			struct uwsgi_pty_client *upc = uwsgi_pty_client_new(client_fd);
                        event_queue_add_fd_read(upty.queue, upc->fd);
                        continue;
                }

		struct uwsgi_pty_client *upc = upty.head;
		while(upc) {
                	if (interesting_fd == upc->fd) {
                        	ssize_t rlen = read(upc->fd, buf, 8192);
                        	if (rlen <= 0) {
					uwsgi_pty_client_remove(upc);
					break;
                        	}
                        	if (write(upty.master_fd, buf, rlen) != rlen) {
				}
				break;
			}
			upc = upc->next;
                }

                continue;

        }

}

static void uwsgi_pty_init() {

	if (!upty.addr) return;
	if (!uwsgi.master_process) return;
	if (uwsgi.mywid > 1) return;

	char *tcp_port = strrchr(upty.addr, ':');
        if (tcp_port) {
        	// disable deferred accept for this socket
                int current_defer_accept = uwsgi.no_defer_accept;
                uwsgi.no_defer_accept = 1;
                upty.server_fd = bind_to_tcp(upty.addr, uwsgi.listen_queue, tcp_port);
                uwsgi.no_defer_accept = current_defer_accept;
	}
        else {
        	upty.server_fd = bind_to_unix(upty.addr, uwsgi.listen_queue, uwsgi.chmod_socket, uwsgi.abstract_socket);
        }

	if (upty.log) {
		upty.original_log = dup(1);
	}

	if (upty.input) {
		upty.original_input = dup(0);
	}

	if (openpty(&upty.master_fd, &upty.slave_fd, NULL, NULL, NULL)) {
		uwsgi_error("uwsgi_pty_init()/openpty()");
		exit(1);
	}


	uwsgi_log("pty server %s (fd: %d) enabled on %s master: %d slave: %d\n", upty.addr, upty.server_fd, ttyname(upty.slave_fd), upty.master_fd, upty.slave_fd);

	upty.queue = event_queue_init();

	event_queue_add_fd_read(upty.queue, upty.master_fd);
	event_queue_add_fd_read(upty.queue, upty.server_fd);
	if (upty.input) {
		event_queue_add_fd_read(upty.queue, upty.original_input);
		uwsgi_pty_setterm(upty.original_input);
	}

	login_tty(upty.slave_fd);

	if (upty.command) {
		upty.command_pid = uwsgi_run_command(upty.command, NULL, -1);
	}

	pthread_t t;
	pthread_create(&t, NULL, uwsgi_pty_loop, NULL);

}

static void uwsgi_pty_winch() {
	// 2 uwsgi packets
	char uwsgi_pkt[8];
#ifdef TIOCGWINSZ
	struct winsize w;
	ioctl(0, TIOCGWINSZ, &w);
	uwsgi_pkt[0] = 0;
	uwsgi_pkt[1] = (uint8_t) (w.ws_row & 0xff);
        uwsgi_pkt[2] = (uint8_t) ((w.ws_row >> 8) & 0xff);
	uwsgi_pkt[3] = 100;
	uwsgi_pkt[4] = 0;
	uwsgi_pkt[5] = (uint8_t) (w.ws_col & 0xff);
        uwsgi_pkt[6] = (uint8_t) ((w.ws_col >> 8) & 0xff);
	uwsgi_pkt[7] = 101;
#endif
	if (write(upty.server_fd, uwsgi_pkt, 8) != 8) {
		uwsgi_error("uwsgi_pty_winch()/write()");
		exit(1);
	}
}

static int uwsgi_pty_client() {
	if (!upty.remote && !upty.uremote) return 0;

	char *remote = upty.uremote ? upty.uremote : upty.remote;

	uwsgi_log("[pty] connecting to %s ...\n", remote);

	// save current terminal settings
	if (!tcgetattr(0, &uwsgi.termios)) {
        	uwsgi.restore_tc = 1;
        }

	upty.server_fd = uwsgi_connect(remote, uwsgi.socket_timeout, 0);
	if (upty.server_fd < 0) {
		uwsgi_error("uwsgi_pty_client()/connect()");
		exit(1);
	}

	//uwsgi_socket_nb(upty.server_fd);
	//uwsgi_socket_nb(0);

	uwsgi_log("[pty] connected.\n");


	uwsgi_pty_setterm(0);

	if (upty.uremote) {
		signal(SIGWINCH, uwsgi_pty_winch);
		// send current terminal size
		uwsgi_pty_winch();
	}

	upty.queue = event_queue_init();
	event_queue_add_fd_read(upty.queue, upty.server_fd);
	event_queue_add_fd_read(upty.queue, 0);

	for(;;) {
		char buf[8192];
		int interesting_fd = -1;
                int ret = event_queue_wait(upty.queue, -1, &interesting_fd);		
		if (ret == 0) break;
		if (ret < 0) {
			if (errno == EINTR) continue;
			break;
		}
		if (interesting_fd == 0) {
			ssize_t rlen = read(0, buf, 8192);
			if (rlen <= 0) break;
			if (upty.uremote) {
				struct uwsgi_header uh;
				uh.modifier1 = 0;
				uh.pktsize = rlen;
				uh.modifier2 = 0;
				if (write(upty.server_fd, &uh, 4) != 4) break;
			}
			if (write(upty.server_fd, buf, rlen) != rlen) break;
			continue;
		}	

		if (interesting_fd == upty.server_fd) {
			ssize_t rlen = read(upty.server_fd, buf, 8192);
                        if (rlen <= 0) break;
                        if (write(0, buf, rlen) != rlen) break;
                        continue;
		}
	}

	exit(0);
	// never here
	return 0;
}

struct uwsgi_plugin pty_plugin = {
	.name = "pty",
	.options = uwsgi_pty_options,
	.init = uwsgi_pty_client,
	.post_fork = uwsgi_pty_init,
};
