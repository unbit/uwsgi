#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

int bind_to_unix(char *socket_name, int listen_queue, int chmod_socket, int abstract_socket) {

	int serverfd;
	struct sockaddr_un *uws_addr;

	uwsgi_log( "binding on UNIX socket: %s\n", socket_name);

	// leave 1 byte for abstract namespace (108 linux -> 104 bsd/mac)
	if (strlen(socket_name) > 102) {
		uwsgi_log( "invalid socket name\n");
		exit(1);
	}

	uws_addr = malloc(sizeof(struct sockaddr_un));
	if (uws_addr == NULL) {
		uwsgi_error("malloc()");
		exit(1);
	}

	memset(uws_addr, 0, sizeof(struct sockaddr_un));
	serverfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (serverfd < 0) {
		uwsgi_error("socket()");
		exit(1);
	}
	if (abstract_socket == 0) {
		if (unlink(socket_name) != 0 && errno != ENOENT) {
			uwsgi_error("unlink()");
		}
	}

	if (abstract_socket == 1) {
		uwsgi_log( "setting abstract socket mode (warning: only Linux supports this)\n");
	}

	uws_addr->sun_family = AF_UNIX;
	memcpy(uws_addr->sun_path + abstract_socket, socket_name, 102);
	
#ifdef __HAIKU__
    if (bind(serverfd, (struct sockaddr *) uws_addr, sizeof(struct sockaddr_un))) {
#else
	if (bind(serverfd, (struct sockaddr *) uws_addr, strlen(socket_name) + abstract_socket + ((void *) uws_addr->sun_path - (void *) uws_addr)) != 0) {
#endif
		uwsgi_error("bind()");
		exit(1);
	}
	

	if (listen(serverfd, listen_queue) != 0) {
		uwsgi_error("listen()");
		exit(1);
	}

	// chmod unix socket for lazy users
	if (chmod_socket == 1 && abstract_socket == 0) {
		if (uwsgi.chmod_socket_value) {
			if (chmod(socket_name, uwsgi.chmod_socket_value) != 0) {
				uwsgi_error("chmod()");
			}
		}
		else {
			uwsgi_log( "chmod() socket to 666 for lazy and brave users\n");
			if (chmod(socket_name, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) != 0) {
				uwsgi_error("chmod()");
			}
		}
	}

	free(uws_addr);

	return serverfd;
}

#ifdef UWSGI_SCTP

#define MAX_SCTP_ADDRESS 4
/* sctp address format sctp:127.0.0.1,192.168.0.17:3031 */
int bind_to_sctp(char *socket_name, int listen_queue, char *sctp_port) {
	int serverfd;
	struct sockaddr_in uws_addr[MAX_SCTP_ADDRESS];
	int num_ip = 0;

	struct sctp_initmsg sctp_im;


	sctp_port[0] = 0;
	memset(uws_addr, 0, sizeof(struct sockaddr_in) * MAX_SCTP_ADDRESS);
	memset(&sctp_im, 0, sizeof(struct sctp_initmsg));

	while (socket_name != NULL && num_ip < MAX_SCTP_ADDRESS) {
		char *ap;
		while ((ap = strsep(&socket_name, ",")) != NULL) {
			if (*ap != '\0') {
				uws_addr[num_ip].sin_family = AF_INET;
				uws_addr[num_ip].sin_port = htons(atoi(sctp_port + 1));
				uws_addr[num_ip].sin_addr.s_addr = inet_addr(ap);
				num_ip++;
			}
		}
	}

	serverfd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
	if (serverfd < 0) {
		uwsgi_error("socket()");
		exit(1);
	}

	uwsgi_log( "binding on %d SCTP interfaces on port: %d\n", num_ip, ntohs(uws_addr[0].sin_port));


	if (sctp_bindx(serverfd, (struct sockaddr *) uws_addr, num_ip, SCTP_BINDX_ADD_ADDR) != 0) {
		uwsgi_error("sctp_bindx()");
		exit(1);
	}

	sctp_im.sinit_max_instreams = 0xFFFF;
	sctp_im.sinit_num_ostreams = 0xFFFF;

	if (setsockopt(serverfd, IPPROTO_SCTP, SCTP_INITMSG, &sctp_im, sizeof(sctp_im))) {
		uwsgi_error("setsockopt()");
	}

	if (listen(serverfd, listen_queue) != 0) {
		uwsgi_error("listen()");
		exit(1);
	}

	return serverfd;
}
#endif

#ifdef UWSGI_UDP
int bind_to_udp(char *socket_name) {
	int serverfd;
	struct sockaddr_in uws_addr;
	char *udp_port;

#ifdef UWSGI_MULTICAST
	struct ip_mreq mc;
#endif

	udp_port = strchr(socket_name, ':');
	if (udp_port == NULL) {
		return -1;
	}

	udp_port[0] = 0;
	memset(&uws_addr, 0, sizeof(struct sockaddr_in));
	uws_addr.sin_family = AF_INET;
	uws_addr.sin_port = htons(atoi(udp_port + 1));

	if (socket_name[0] != 0) {
		uws_addr.sin_addr.s_addr = inet_addr(socket_name);
	}
	else {
		uws_addr.sin_addr.s_addr = INADDR_ANY;
	}

	

	serverfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (serverfd < 0) {
		uwsgi_error("socket()");
		return -1;
	}

#ifdef UWSGI_MULTICAST
	if (uwsgi.multicast_group) {
		uws_addr.sin_addr.s_addr = INADDR_ANY;
		// if multicast is enabled remember to bind to INADDR_ANY
		mc.imr_multiaddr.s_addr = inet_addr(uwsgi.multicast_group);
		if (socket_name[0] == 0) {
			mc.imr_interface.s_addr = INADDR_ANY;
		}
		else {
			mc.imr_interface.s_addr = inet_addr(socket_name);
		}
	}
#endif

	uwsgi_log( "binding on UDP port: %d\n", ntohs(uws_addr.sin_port));

	if (bind(serverfd, (struct sockaddr *) &uws_addr, sizeof(uws_addr)) != 0) {
		uwsgi_error("bind()");
		close(serverfd);
		return -1;
	}

#ifdef UWSGI_MULTICAST
	if (uwsgi.multicast_group) {
		uwsgi_log( "joining uWSGI multicast group: %s:%d\n", uwsgi.multicast_group, ntohs(uws_addr.sin_port));
		if (setsockopt(serverfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mc, sizeof(mc))) {
			uwsgi_error("setsockopt()");
		}
	}
#endif

	return serverfd;

}
#endif

int uwsgi_connect(char *socket_name, int timeout) {

	char *tcp_port = strchr(socket_name, ':');	

	if (tcp_port) {
		tcp_port[0] = 0;
		tcp_port++;
		return connect_to_tcp(socket_name, atoi(tcp_port), timeout);
	}
	
	return connect_to_unix(socket_name, timeout);
}

int connect_to_unix(char *socket_name, int timeout) {

	struct pollfd uwsgi_poll;
        struct sockaddr_un uws_addr;

        memset(&uws_addr, 0, sizeof(struct sockaddr_un));

        uws_addr.sun_family = AF_UNIX;
        memcpy(uws_addr.sun_path, socket_name, 102);

        uwsgi_poll.fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (uwsgi_poll.fd < 0) {
                uwsgi_error("socket()");
                return -1;
        }

        uwsgi_poll.events = POLLIN;

        if (timed_connect(&uwsgi_poll, (const struct sockaddr *) &uws_addr, sizeof(struct sockaddr_un), timeout)) {
                uwsgi_error("connect()");
                close(uwsgi_poll.fd);
                return -1;
        }

        return uwsgi_poll.fd;
	
}

int connect_to_tcp(char *socket_name, int port, int timeout) {

	struct pollfd uwsgi_poll;
	struct sockaddr_in uws_addr;

	memset(&uws_addr, 0, sizeof(struct sockaddr_in));

	uws_addr.sin_family = AF_INET;
	uws_addr.sin_port = htons(port);

	if (socket_name[0] == 0) {
		uws_addr.sin_addr.s_addr = INADDR_ANY;
	}
	else {
		uws_addr.sin_addr.s_addr = inet_addr(socket_name);
	}

	socket_name[strlen(socket_name)] = ':' ;

	uwsgi_poll.fd = socket(AF_INET, SOCK_STREAM, 0);
	if (uwsgi_poll.fd < 0) {
		uwsgi_error("socket()");
		return -1;
	}

	uwsgi_poll.events = POLLIN;

	if (timed_connect(&uwsgi_poll, (const struct sockaddr *) &uws_addr, sizeof(struct sockaddr_in), timeout)) {
		uwsgi_error("connect()");
		close(uwsgi_poll.fd);
		return -1;
	}

	return uwsgi_poll.fd;

}

int bind_to_tcp(char *socket_name, int listen_queue, char *tcp_port) {

	int serverfd;
	struct sockaddr_in uws_addr;
	int reuse = 1;

	tcp_port[0] = 0;
	memset(&uws_addr, 0, sizeof(struct sockaddr_in));

	uws_addr.sin_family = AF_INET;
	uws_addr.sin_port = htons(atoi(tcp_port + 1));


	if (socket_name[0] == 0) {
		uws_addr.sin_addr.s_addr = INADDR_ANY;
	}
	else {
		uws_addr.sin_addr.s_addr = inet_addr(socket_name);
	}

	serverfd = socket(AF_INET, SOCK_STREAM, 0);
	if (serverfd < 0) {
		uwsgi_error("socket()");
		exit(1);
	}

	if (setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, (const void *) &reuse, sizeof(int)) < 0) {
		uwsgi_error("setsockopt()");
		exit(1);
	}

	if (!uwsgi.no_defer_accept) {

#ifdef __linux__
		if (setsockopt(serverfd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT], sizeof(int))) {
			uwsgi_error("setsockopt()");
		}
// OSX has no SO_ACCEPTFILTER !!!
#elif defined(__freebsd__)
		struct  accept_filter_arg afa;
		strcpy(afa.af_name, "dataready");
		afa.af_arg[0] = 0;
		if (setsockopt(serverfd, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(struct  accept_filter_arg))) {
			uwsgi_error("setsockopt()");
		}
#endif

	}


	uwsgi_log( "binding on TCP port: %d\n", ntohs(uws_addr.sin_port));

	if (bind(serverfd, (struct sockaddr *) &uws_addr, sizeof(uws_addr)) != 0) {
		if (errno == EADDRINUSE) {
			uwsgi_log("probably another instance of uWSGI is running on the same address.\n");
		}
		uwsgi_error("bind()");
		exit(1);
	}

	if (listen(serverfd, listen_queue) != 0) {
		uwsgi_error("listen()");
		exit(1);
	}


	return serverfd;
}

int timed_connect(struct pollfd *fdpoll, const struct sockaddr *addr, int addr_size, int timeout) {

	int arg, ret;
	int soopt;
	socklen_t solen = sizeof(int);
	int cnt;
	/* set non-blocking socket */

	arg = fcntl(fdpoll->fd, F_GETFL, NULL);
	if (arg < 0) {
		uwsgi_error("fcntl()");
		return -1;
	}
	arg |= O_NONBLOCK;
	if (fcntl(fdpoll->fd, F_SETFL, arg) < 0) {
		uwsgi_error("fcntl()");
		return -1;
	}

	ret = connect(fdpoll->fd, addr, addr_size);
	if (ret < 0) {
		/* check what happened */

		// in progress ?
		if (errno == EINPROGRESS) {
			if (timeout < 1)
				timeout = 3;
			fdpoll->events = POLLOUT;
			cnt = poll(fdpoll, 1, timeout * 1000);
			/* check for errors */
			if (cnt < 0 && errno != EINTR) {
				uwsgi_error("poll()");
				return -1;
			}
			/* something hapened on the socket ... */
			else if (cnt > 0) {
				if (getsockopt(fdpoll->fd, SOL_SOCKET, SO_ERROR, (void *) (&soopt), &solen) < 0) {
					uwsgi_error("getsockopt()");
					return -1;
				}
				/* is something bad ? */
				if (soopt) {
					return -1;
				}
			}
			/* timeout */
			else {
				return -1;
			}
		}
		else {
			return -1;
		}
	}

	/* re-set blocking socket */
	arg &= (~O_NONBLOCK);
	if (fcntl(fdpoll->fd, F_SETFL, arg) < 0) {
		uwsgi_error("fcntl()");
		return -1;
	}

	return 0;

}
