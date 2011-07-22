#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

int bind_to_unix(char *socket_name, int listen_queue, int chmod_socket, int abstract_socket) {

	int serverfd;
	struct sockaddr_un *uws_addr;
	socklen_t len;

	// leave 1 byte for abstract namespace (108 linux -> 104 bsd/mac)
	if (strlen(socket_name) > 102) {
		uwsgi_log("invalid socket name\n");
		uwsgi_nuclear_blast();
	}

	if (socket_name[0] == '@') {
		abstract_socket = 1;
	}
	else if (strlen(socket_name) > 1 && socket_name[0] == '\\' && socket_name[1] == '0') {
		abstract_socket = 1;
	}

	uws_addr = malloc(sizeof(struct sockaddr_un));
	if (uws_addr == NULL) {
		uwsgi_error("malloc()");
		uwsgi_nuclear_blast();
	}

	memset(uws_addr, 0, sizeof(struct sockaddr_un));
	serverfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (serverfd < 0) {
		uwsgi_error("socket()");
		uwsgi_nuclear_blast();
	}
	if (abstract_socket == 0) {
		if (unlink(socket_name) != 0 && errno != ENOENT) {
			uwsgi_error("unlink()");
		}
	}

	if (abstract_socket == 1) {
		uwsgi_log("setting abstract socket mode (warning: only Linux supports this)\n");
	}

	uws_addr->sun_family = AF_UNIX;
	if (socket_name[0] == '@') {
		memcpy(uws_addr->sun_path + abstract_socket, socket_name+1, UMIN(strlen(socket_name+1), 101));
		len = strlen(socket_name) + 1;
	}
	else if (strlen(socket_name) > 1 && socket_name[0] == '\\' && socket_name[1] == '0') {
		memcpy(uws_addr->sun_path + abstract_socket, socket_name+2, UMIN(strlen(socket_name+2), 101));
		len = strlen(socket_name+1) + 1;
		
	}
	else if (abstract_socket) {
		memcpy(uws_addr->sun_path + 1, socket_name, UMIN(strlen(socket_name), 101));
		len = strlen(socket_name)+1;
	}
	else {
		memcpy(uws_addr->sun_path + abstract_socket, socket_name, UMIN(strlen(socket_name), 102));
		len = strlen(socket_name);
	}

#ifdef __HAIKU__
	if (bind(serverfd, (struct sockaddr *) uws_addr, sizeof(struct sockaddr_un))) {
#else
	if (bind(serverfd, (struct sockaddr *) uws_addr, len + ((void *) uws_addr->sun_path - (void *) uws_addr)) != 0) {
#endif
		uwsgi_error("bind()");
		uwsgi_nuclear_blast();
	}


	if (listen(serverfd, listen_queue) != 0) {
		uwsgi_error("listen()");
		uwsgi_nuclear_blast();
	}

	// chmod unix socket for lazy users
	if (chmod_socket == 1 && abstract_socket == 0) {
		if (uwsgi.chmod_socket_value) {
			if (chmod(socket_name, uwsgi.chmod_socket_value) != 0) {
				uwsgi_error("chmod()");
			}
		}
		else {
			uwsgi_log("chmod() socket to 666 for lazy and brave users\n");
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
		uwsgi_nuclear_blast();
	}

	uwsgi_log("binding on %d SCTP interfaces on port: %d\n", num_ip, ntohs(uws_addr[0].sin_port));


	if (sctp_bindx(serverfd, (struct sockaddr *) uws_addr, num_ip, SCTP_BINDX_ADD_ADDR) != 0) {
		uwsgi_error("sctp_bindx()");
		uwsgi_nuclear_blast();
	}

	sctp_im.sinit_max_instreams = 0xFFFF;
	sctp_im.sinit_num_ostreams = 0xFFFF;

	if (setsockopt(serverfd, IPPROTO_SCTP, SCTP_INITMSG, &sctp_im, sizeof(sctp_im))) {
		uwsgi_error("setsockopt()");
	}

	if (listen(serverfd, listen_queue) != 0) {
		uwsgi_error("listen()");
		uwsgi_nuclear_blast();
	}

	return serverfd;
}
#endif

#ifdef UWSGI_UDP
int bind_to_udp(char *socket_name, int multicast, int broadcast) {
	int serverfd;
	struct sockaddr_in uws_addr;
	char *udp_port;
	int bcast = 1;

#ifdef UWSGI_MULTICAST
	struct ip_mreq mc;
	uint8_t loop = 1;
#endif

	udp_port = strchr(socket_name, ':');
	if (udp_port == NULL) {
		return -1;
	}

	udp_port[0] = 0;

	if (socket_name[0] == 0 && multicast) {
		uwsgi_log("invalid multicast address\n");
		return -1;
	}
	memset(&uws_addr, 0, sizeof(struct sockaddr_in));
	uws_addr.sin_family = AF_INET;
	uws_addr.sin_port = htons(atoi(udp_port + 1));

	if (broadcast) {
		uws_addr.sin_addr.s_addr = INADDR_BROADCAST;
	}
	else if (socket_name[0] != 0) {
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
	if (multicast) {
		// if multicast is enabled remember to bind to INADDR_ANY
		uws_addr.sin_addr.s_addr = INADDR_ANY;
		mc.imr_multiaddr.s_addr = inet_addr(socket_name);
		mc.imr_interface.s_addr = INADDR_ANY;
	}
#endif

	if (broadcast) {
		if (setsockopt(serverfd, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof(bcast))) {
			perror("setsockopt");
			close(serverfd);
			return -1;
		}
	}

	if (bind(serverfd, (struct sockaddr *) &uws_addr, sizeof(uws_addr)) != 0) {
		uwsgi_error("bind()");
		close(serverfd);
		return -1;
	}

#ifdef UWSGI_MULTICAST
	if (multicast) {
		uwsgi_log("[uWSGI] joining multicast group: %s:%d\n", socket_name, ntohs(uws_addr.sin_port));
		if (setsockopt(serverfd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop))) {
			uwsgi_error("setsockopt()");
		}

		if (setsockopt(serverfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mc, sizeof(mc))) {
			uwsgi_error("setsockopt()");
		}

	}
#endif

	udp_port[0] = ':';
	return serverfd;

}
#endif

int uwsgi_connectn(char *socket_name, uint16_t len, int timeout, int async) {

	int fd;

	char *zeroed_socket_name = uwsgi_concat2n(socket_name, len, "", 0);
	fd = uwsgi_connect(zeroed_socket_name, timeout, async);

	free(zeroed_socket_name);
	return fd;
}

int uwsgi_connect(char *socket_name, int timeout, int async) {

	int ret;
	char *tcp_port = strchr(socket_name, ':');

	if (tcp_port) {
		tcp_port[0] = 0;
		tcp_port++;
		ret = connect_to_tcp(socket_name, atoi(tcp_port), timeout, async);
		// reset the socket name
		tcp_port--;
		tcp_port[0] = ':';
		return ret;
	}

	return connect_to_unix(socket_name, timeout, async);
}

int connect_to_unix(char *socket_name, int timeout, int async) {

	struct pollfd uwsgi_poll;
	struct sockaddr_un uws_addr;
	socklen_t un_size = sizeof(struct sockaddr_un);

	memset(&uws_addr, 0, sizeof(struct sockaddr_un));

	uws_addr.sun_family = AF_UNIX;

	if (socket_name[0] == '@'){
		un_size = sizeof(uws_addr.sun_family) + strlen(socket_name) + 1;
		memcpy(uws_addr.sun_path+1, socket_name+1, UMIN(strlen(socket_name+1), 101));
	}
	else if (strlen(socket_name) > 1 && socket_name[0] == '\\' && socket_name[1] == '0') {
		un_size = sizeof(uws_addr.sun_family) + strlen(socket_name+1) + 1;
		memcpy(uws_addr.sun_path+1, socket_name+2, UMIN(strlen(socket_name+2), 101));
	}
	else {
		memcpy(uws_addr.sun_path, socket_name, UMIN(strlen(socket_name), 102));
	}

	uwsgi_poll.fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (uwsgi_poll.fd < 0) {
		uwsgi_error("socket()");
		return -1;
	}

	uwsgi_poll.events = POLLIN;

	if (timed_connect(&uwsgi_poll, (const struct sockaddr *) &uws_addr, un_size, timeout, async)) {
		uwsgi_error("connect()");
		close(uwsgi_poll.fd);
		return -1;
	}

	return uwsgi_poll.fd;

}

int connect_to_tcp(char *socket_name, int port, int timeout, int async) {

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

	socket_name[strlen(socket_name)] = ':';

	uwsgi_poll.fd = socket(AF_INET, SOCK_STREAM, 0);
	if (uwsgi_poll.fd < 0) {
		uwsgi_error("socket()");
		return -1;
	}

	uwsgi_poll.events = POLLIN;

	if (timed_connect(&uwsgi_poll, (const struct sockaddr *) &uws_addr, sizeof(struct sockaddr_in), timeout, async)) {
		//uwsgi_error("connect()");
		close(uwsgi_poll.fd);
		return -1;
	}

	return uwsgi_poll.fd;

}

char *generate_socket_name(char *socket_name) {

	char *asterisk = strchr(socket_name, '*');

	char *tcp_port;
	int i;
	char *ptr = socket_name;

	// ltrim spaces

	for (i = 0; i < (int) strlen(socket_name); i++) {
		if (isspace((int) socket_name[i])) {
			ptr++;
		}
		else {
			break;
		}
	}

	socket_name = ptr;

	if (socket_name[0] == 0) {
		uwsgi_log("invalid/empty uwsgi socket name\n");
		exit(1);
	}

	tcp_port = strchr(socket_name, ':');
	if (!tcp_port)
		return socket_name;

	if (asterisk) {

#ifndef UWSGI_HAS_IFADDRS
		uwsgi_log("your system does not support ifaddrs subsystem\n");
#else
		char *new_socket;

#ifdef UWSGI_DEBUG
		uwsgi_log("generate_socket_name(%s)\n", socket_name);
#endif
		// get all the AF_INET addresses available
		struct ifaddrs *ifap = NULL, *ifa, *ifaf;
		if (getifaddrs(&ifap)) {
			uwsgi_error("getifaddrs()");
			uwsgi_nuclear_blast();
		}

		// here socket_name will be truncated
		asterisk[0] = 0;

#ifdef UWSGI_DEBUG
		uwsgi_log("asterisk found\n");
#endif

		char new_addr[16];
		struct sockaddr_in *sin;
		ifa = ifap;
		while (ifa) {
			memset(new_addr, 0, 16);
			sin = (struct sockaddr_in *) ifa->ifa_addr;
			if (inet_ntop(AF_INET, (void *) &sin->sin_addr.s_addr, new_addr, 16)) {
				if (!strncmp(socket_name, new_addr, strlen(socket_name))) {
					asterisk[0] = '*';
					new_socket = uwsgi_concat3(new_addr, ":", tcp_port + 1);
					uwsgi_log("found %s for %s on interface %s\n", new_socket, socket_name, ifa->ifa_name);
					freeifaddrs(ifap);
					return new_socket;
				}

			}

			ifaf = ifa;
			ifa = ifaf->ifa_next;

		}

		uwsgi_log("unable to find avalid socket address\n");
#endif
		uwsgi_nuclear_blast();
	}
	return socket_name;
}

socklen_t socket_to_un_addr(char *socket_name, struct sockaddr_un *sun_addr) {

	size_t len = strlen(socket_name);

	if (len > 102) {
		uwsgi_log("invalid UNIX socket address: %s\n", socket_name);
		uwsgi_nuclear_blast();
	}

	memset(sun_addr, 0, sizeof(struct sockaddr_un));

        sun_addr->sun_family = AF_UNIX;

	// abstract socket
        if (socket_name[0] == '@') {
		memcpy(sun_addr->sun_path+1, socket_name+1, UMIN(len-1, 101));
		len = strlen(socket_name) + 1;
        }
	else if (len > 1 && socket_name[0] == '\\' && socket_name[1] == '0') {
		memcpy(sun_addr->sun_path+1, socket_name+2, UMIN(len-2, 101));
		len = strlen(socket_name+1) + 1;
	}
        else {
		memcpy(sun_addr->sun_path, socket_name, UMIN(len, 102));
        }

        return sizeof(sun_addr->sun_family)+len;
}

socklen_t socket_to_in_addr(char *socket_name, char *port, struct sockaddr_in *sin_addr) {

	memset(sin_addr, 0, sizeof(struct sockaddr_in));
	
	sin_addr->sin_family = AF_INET;
	if (port) {
		port[0] = 0;
		sin_addr->sin_port = htons(atoi(port + 1));
	}

	if (socket_name[0] == 0) {
                sin_addr->sin_addr.s_addr = INADDR_ANY;
        }
        else {
                sin_addr->sin_addr.s_addr = inet_addr(socket_name);
        }

	return sizeof(struct sockaddr_in);
	
}

int bind_to_tcp(char *socket_name, int listen_queue, char *tcp_port) {

	int serverfd;
	struct sockaddr_in uws_addr;
	int reuse = 1;

	socket_to_in_addr(socket_name, tcp_port, &uws_addr);

	serverfd = socket(AF_INET, SOCK_STREAM, 0);
	if (serverfd < 0) {
		uwsgi_error("socket()");
		uwsgi_nuclear_blast();
	}

	if (setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, (const void *) &reuse, sizeof(int)) < 0) {
		uwsgi_error("setsockopt()");
		uwsgi_nuclear_blast();
	}

#ifdef __linux__
#ifdef IP_FREEBIND
	if (uwsgi.freebind) {
		if (setsockopt(serverfd, SOL_IP, IP_FREEBIND, (const void *) &uwsgi.freebind, sizeof(int)) < 0) {
			uwsgi_error("setsockopt()");
			uwsgi_nuclear_blast();
		}
	}
#endif
#endif

	if (uwsgi.reuse_port) {
#ifdef SO_REUSEPORT
		if (setsockopt(serverfd, SOL_SOCKET, SO_REUSEPORT, (const void *) &uwsgi.reuse_port, sizeof(int)) < 0) {
			uwsgi_error("setsockopt()");
			uwsgi_nuclear_blast();
		}
#else
		uwsgi_log("!!! your system does not support SO_REUSEPORT !!!\n");
#endif
	}

	if (!uwsgi.no_defer_accept) {

#ifdef __linux__
		if (setsockopt(serverfd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT], sizeof(int))) {
			uwsgi_error("setsockopt()");
		}
		// OSX has no SO_ACCEPTFILTER !!!
#elif defined(__freebsd__)
		struct accept_filter_arg afa;
		strcpy(afa.af_name, "dataready");
		afa.af_arg[0] = 0;
		if (setsockopt(serverfd, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(struct accept_filter_arg))) {
			uwsgi_error("setsockopt()");
		}
#endif

	}


	if (bind(serverfd, (struct sockaddr *) &uws_addr, sizeof(uws_addr)) != 0) {
		if (errno == EADDRINUSE) {
			uwsgi_log("probably another instance of uWSGI is running on the same address.\n");
		}
		uwsgi_error("bind()");
		uwsgi_nuclear_blast();
	}

	if (listen(serverfd, listen_queue) != 0) {
		uwsgi_error("listen()");
		uwsgi_nuclear_blast();
	}


	if (tcp_port)
		tcp_port[0] = ':';

	return serverfd;
}

void uwsgi_socket_nb(int fd) {
	int arg;

	arg = fcntl(fd, F_GETFL, NULL);
        if (arg < 0) {
                uwsgi_error("fcntl()");
                return;
        }
        arg |= O_NONBLOCK;
        if (fcntl(fd, F_SETFL, arg) < 0) {
                uwsgi_error("fcntl()");
                return;
        }

}

int timed_connect(struct pollfd *fdpoll, const struct sockaddr *addr, int addr_size, int timeout, int async) {

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

	if (async) {
		if (ret < 0 && errno != EINPROGRESS) {
			return -1;
		}
	}

	/* re-set blocking socket */
	arg &= (~O_NONBLOCK);
	if (fcntl(fdpoll->fd, F_SETFL, arg) < 0) {
		uwsgi_error("fcntl()");
		return -1;
	}

	if (async)
		return 0;

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



	return 0;

}

int uwsgi_count_sockets(struct uwsgi_socket *uwsgi_sock) {

	int count = 0;
	while(uwsgi_sock) {
		count++;
		uwsgi_sock = uwsgi_sock->next;
	}

	return count;
}

int uwsgi_get_socket_num(struct uwsgi_socket *uwsgi_sock) {

	int count = 0;
	struct uwsgi_socket *current_sock = uwsgi.sockets;

	while(current_sock) {
		if (uwsgi_sock == current_sock) {
			return count;
		}
		count++;
		current_sock = current_sock->next;
	}

	return -1;
}

int uwsgi_get_shared_socket_num(struct uwsgi_socket *uwsgi_sock) {

        int count = 0;
        struct uwsgi_socket *current_sock = uwsgi.shared_sockets;

        while(current_sock) {
                if (uwsgi_sock == current_sock) {
                        return count;
                }
                count++;
                current_sock = current_sock->next;
        }

        return -1;
}


struct uwsgi_socket *uwsgi_new_shared_socket(char *name) {

        struct uwsgi_socket *uwsgi_sock = uwsgi.shared_sockets, *old_uwsgi_sock;

        if (!uwsgi_sock) {
                uwsgi.shared_sockets = uwsgi_malloc(sizeof(struct uwsgi_socket));
                uwsgi_sock = uwsgi.shared_sockets;
        }
        else {
                while(uwsgi_sock) {
                        old_uwsgi_sock = uwsgi_sock;
                        uwsgi_sock = uwsgi_sock->next;
                }

                uwsgi_sock = uwsgi_malloc(sizeof(struct uwsgi_socket));
                old_uwsgi_sock->next = uwsgi_sock;
        }

        memset(uwsgi_sock, 0, sizeof(struct uwsgi_socket));
        uwsgi_sock->name = name;

        return uwsgi_sock;
}


struct uwsgi_socket *uwsgi_new_socket(char *name) {

	struct uwsgi_socket *uwsgi_sock = uwsgi.sockets, *old_uwsgi_sock;
	struct sockaddr_in sin;
	socklen_t socket_type_len;

	if (!uwsgi_sock) {
		uwsgi.sockets = uwsgi_malloc(sizeof(struct uwsgi_socket));
		uwsgi_sock = uwsgi.sockets;
	}
	else {
		while(uwsgi_sock) {
			old_uwsgi_sock = uwsgi_sock;
			uwsgi_sock = uwsgi_sock->next;
		}

		uwsgi_sock = uwsgi_malloc(sizeof(struct uwsgi_socket));
		old_uwsgi_sock->next = uwsgi_sock;
	}

	memset(uwsgi_sock, 0, sizeof(struct uwsgi_socket)); 
	uwsgi_sock->name = name;

	if (!name) return uwsgi_sock;

	char *tcp_port = strchr(name, ':');
	if (tcp_port) {
		// INET socket, check for 0 port
		if (tcp_port[1] == 0 || tcp_port[1] == '0') {
			uwsgi_sock->fd = bind_to_tcp(name, uwsgi.listen_queue, tcp_port);
                        uwsgi_sock->family = AF_INET;
			uwsgi_sock->bound = 1;

			uwsgi_sock->auto_port = 1;

			socket_type_len = sizeof(struct sockaddr_in);

			if (getsockname(uwsgi_sock->fd, (struct sockaddr *)&sin, &socket_type_len)) {
				uwsgi_error("getsockname()");
				exit(1);
			}


			char *auto_port = uwsgi_num2str(ntohs(sin.sin_port));
			uwsgi_sock->name = uwsgi_concat3n(name, tcp_port-name, ":", 1, auto_port, strlen(auto_port));
		}
		// is it fd 0 ?
		else if (tcp_port[1] == ':') {
			uwsgi_sock->fd = 0;
                        uwsgi_sock->family = AF_INET;
			uwsgi_sock->bound = 1;

			socket_type_len = sizeof(struct sockaddr_in);

			if (getsockname(0, (struct sockaddr *)&sin, &socket_type_len)) {
				uwsgi_error("getsockname()");
				exit(1);
			}


			char *auto_port = uwsgi_num2str(ntohs(sin.sin_port));
			char *auto_ip = inet_ntoa(sin.sin_addr);
			uwsgi_sock->name = uwsgi_concat3n(auto_ip, strlen(auto_ip), ":", 1, auto_port, strlen(auto_port));
		}
	}
	
	return uwsgi_sock;
}

void uwsgi_add_socket_from_fd(struct uwsgi_socket *uwsgi_sock, int fd) {

	socklen_t socket_type_len;
	union uwsgi_sockaddr_ptr gsa, isa;
	union uwsgi_sockaddr usa;
	int abstract = 0;

#ifdef UWSGI_DEBUG
	uwsgi_log("creating socket from fd %d\n", fd);
#endif

	socket_type_len = sizeof(struct sockaddr_un);
	gsa.sa = &usa.sa;
	if (!getsockname(fd, gsa.sa, &socket_type_len)) {
		if (socket_type_len <= 2) {
			// unbound socket
			return;
		}
		if (gsa.sa->sa_family == AF_UNIX) {
			if (usa.sa_un.sun_path[0] == 0) abstract = 1;
			// is it a zerg ?
			if (uwsgi_sock->name == NULL) {
				uwsgi_sock->fd = fd;
				uwsgi_sock->family = AF_UNIX;
				uwsgi_sock->bound = 1;
				uwsgi_sock->name = uwsgi_concat2(usa.sa_un.sun_path+abstract, "");
				if (uwsgi.zerg) {
					uwsgi_log("uwsgi zerg socket %d attached to UNIX address %s fd %d\n", uwsgi_get_socket_num(uwsgi_sock), usa.sa_un.sun_path+abstract, uwsgi_sock->fd);
				}
				else {
					uwsgi_log("uwsgi socket %d attached to UNIX address %s fd %d\n", uwsgi_get_socket_num(uwsgi_sock), usa.sa_un.sun_path+abstract, uwsgi_sock->fd);
				}
				return;
			}
			if (!strcmp(usa.sa_un.sun_path+abstract, uwsgi_sock->name+abstract)) {
				uwsgi_sock->fd = fd;
				uwsgi_sock->family = AF_UNIX;
				uwsgi_sock->bound = 1;
				uwsgi_log("uwsgi socket %d inherited UNIX address %s fd %d\n", uwsgi_get_socket_num(uwsgi_sock), uwsgi_sock->name, uwsgi_sock->fd);
			}
		}
		else if (gsa.sa->sa_family == AF_INET) {
			char *computed_addr;
			char computed_port[6];
			isa.sa_in = (struct sockaddr_in *) &usa;
			char ipv4a[INET_ADDRSTRLEN + 1];
			memset(ipv4a, 0, INET_ADDRSTRLEN + 1);
			memset(computed_port, 0, 6);


			if (snprintf(computed_port, 6, "%d", ntohs(isa.sa_in->sin_port)) > 0) {
				if (inet_ntop(AF_INET, (const void *) &isa.sa_in->sin_addr.s_addr, ipv4a, INET_ADDRSTRLEN)) {

					if (!strcmp("0.0.0.0", ipv4a)) {
						computed_addr = uwsgi_concat2(":", computed_port);
					}
					else {
						computed_addr = uwsgi_concat3(ipv4a, ":", computed_port);
					}

					// is it a zerg ?
                        		if (uwsgi_sock->name == NULL) {
						uwsgi_sock->fd = fd;
						uwsgi_sock->family = AF_INET;
						uwsgi_sock->bound = 1;
						uwsgi_sock->name = uwsgi_concat2(computed_addr, "");
						if (uwsgi.zerg) {
							uwsgi_log("uwsgi zerg socket %d attached to INET address %s fd %d\n", uwsgi_get_socket_num(uwsgi_sock), computed_addr, uwsgi_sock->fd);
						}
						else {
							uwsgi_log("uwsgi socket %d attached to INET address %s fd %d\n", uwsgi_get_socket_num(uwsgi_sock), computed_addr, uwsgi_sock->fd);
						}
						free(computed_addr);
						return;
					}
					char *asterisk = strchr(uwsgi_sock->name, '*');
					int match = 1;
					if (asterisk) {
						asterisk[0] = 0;
						match = strncmp(computed_addr, uwsgi_sock->name, strlen(uwsgi_sock->name));
						asterisk[0] = '*';
					}
					else {
						match = strcmp(computed_addr, uwsgi_sock->name);
					}
					if (!match) {
						uwsgi_sock->fd = fd;
						uwsgi_sock->family = AF_INET;
						uwsgi_sock->bound = 1;
						uwsgi_log("uwsgi socket %d inherited INET address %s fd %d\n", uwsgi_get_socket_num(uwsgi_sock), uwsgi_sock->name, uwsgi_sock->fd);
					}
					free(computed_addr);
				}
			}
		}
	}

}

void uwsgi_close_all_sockets() {
	struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;

	while(uwsgi_sock) {
		close(uwsgi_sock->fd);
		uwsgi_sock = uwsgi_sock->next;
	}
}

struct uwsgi_socket *uwsgi_del_socket(struct uwsgi_socket *uwsgi_sock) {

        struct uwsgi_socket *uwsgi_current_sock = uwsgi.sockets, *old_sock = NULL;

        while(uwsgi_current_sock) {
                if (uwsgi_current_sock == uwsgi_sock) {
                        // parent instance ?
                        if (old_sock == NULL) {
                                uwsgi.sockets = uwsgi_current_sock->next;
                        	free(uwsgi_current_sock);
                        	return uwsgi.sockets;
                        }
                        else {
                                old_sock->next = uwsgi_current_sock->next;
                        	free(uwsgi_current_sock);
                        	return old_sock->next;
                        }

                }

                old_sock = uwsgi_current_sock;
                uwsgi_current_sock = uwsgi_current_sock->next;
        }
	
	return NULL;
}


int uwsgi_get_shared_socket_fd_by_num(int num) {

	int counter = 0;
	
	struct uwsgi_socket *found_sock = NULL, *uwsgi_sock = uwsgi.shared_sockets;	

	while(uwsgi_sock) {
		if (counter == num) {
			found_sock = uwsgi_sock;
			break;
		}
		counter++;
		uwsgi_sock = uwsgi_sock->next;
	}

	if (found_sock) {
		return found_sock->fd;
	}
	
	return -1;
}

void uwsgi_add_sockets_to_queue(int queue) {

	struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;
                while(uwsgi_sock) {
                        event_queue_add_fd_read(queue, uwsgi_sock->fd);
                        uwsgi_sock = uwsgi_sock->next;
                }

}

void uwsgi_del_sockets_from_queue(int queue) {

        struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;
                while(uwsgi_sock) {
                        event_queue_del_fd(queue, uwsgi_sock->fd, event_queue_read());
                        uwsgi_sock = uwsgi_sock->next;
                }

}

