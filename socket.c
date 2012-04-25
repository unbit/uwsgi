#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

char *uwsgi_getsockname(int fd) {

	socklen_t socket_type_len = sizeof(struct sockaddr_un);
	union uwsgi_sockaddr usa;
	union uwsgi_sockaddr_ptr gsa;
	char computed_port[6];
	char ipv4a[INET_ADDRSTRLEN + 1];

	gsa.sa = (struct sockaddr *) &usa;

	if (!getsockname(fd, gsa.sa, &socket_type_len)) {
		if (gsa.sa->sa_family == AF_UNIX) {
			if (usa.sa_un.sun_path[0] == 0) {
				return uwsgi_concat2("@", usa.sa_un.sun_path + 1);
			}
			else {
				return uwsgi_str(usa.sa_un.sun_path);
			}
		}
		else {
			memset(ipv4a, 0, INET_ADDRSTRLEN + 1);
			memset(computed_port, 0, 6);
			if (snprintf(computed_port, 6, "%d", ntohs(gsa.sa_in->sin_port)) > 0) {
				if (inet_ntop(AF_INET, (const void *) &gsa.sa_in->sin_addr.s_addr, ipv4a, INET_ADDRSTRLEN)) {
					if (!strcmp("0.0.0.0", ipv4a)) {
						return uwsgi_concat2(":", computed_port);
					}
					else {
						return uwsgi_concat3(ipv4a, ":", computed_port);
					}
				}
			}
		}
	}
	return NULL;
}

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
		memcpy(uws_addr->sun_path + abstract_socket, socket_name + 1, UMIN(strlen(socket_name + 1), 101));
		len = strlen(socket_name) + 1;
	}
	else if (strlen(socket_name) > 1 && socket_name[0] == '\\' && socket_name[1] == '0') {
		memcpy(uws_addr->sun_path + abstract_socket, socket_name + 2, UMIN(strlen(socket_name + 2), 101));
		len = strlen(socket_name + 1) + 1;

	}
	else if (abstract_socket) {
		memcpy(uws_addr->sun_path + 1, socket_name, UMIN(strlen(socket_name), 101));
		len = strlen(socket_name) + 1;
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

int connect_to_sctp(char *socket_names, int queue) {

	char *peers = uwsgi_str(socket_names);
	int addresses = 0;
	
	struct sockaddr_in *sins;
	
	// first step: count required addresses;
	char *p = strtok(peers, ",");
	while(p) {
#ifdef UWSGI_DEBUG
		uwsgi_log("p = %s\n", p);
#endif
		addresses++;	
		p = strtok(NULL, ",");
	}

	free(peers);
	peers = uwsgi_str(socket_names);

	sins = uwsgi_calloc(sizeof(struct sockaddr_in) * addresses);

	addresses = 0;
	p = strtok(peers, ",");
	while(p) {
		char *port = strchr(p, ':');
		if (!port) {
			uwsgi_log("invalid SCTP address/port, please fix it and restart\n");
			goto clear;
		}
		sins[addresses].sin_family = AF_INET;
		*port = 0;
		sins[addresses].sin_addr.s_addr = inet_addr(p);
		sins[addresses].sin_port = htons( atoi(port+1) );
		addresses++;	
		p = strtok(NULL, ",");
	}

	int serverfd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
	if (serverfd < 0) {
		uwsgi_error("socket()");
		goto clear;
	}

	struct sctp_event_subscribe events;
        struct sctp_initmsg initmsg;

	memset(&initmsg, 0, sizeof(initmsg));
        initmsg.sinit_max_instreams = 0xffff;
        initmsg.sinit_num_ostreams = 0xffff;

	if (setsockopt(serverfd, IPPROTO_SCTP,
                       SCTP_INITMSG, &initmsg, sizeof(initmsg))) {
		uwsgi_error("setsockopt()");
		close(serverfd);
		goto clear;
        }

	memset( (void *)&events, 0, sizeof(events) );
        events.sctp_data_io_event = 1;
	/*
	events.sctp_peer_error_event = 1;
	events.sctp_shutdown_event = 1;
	*/
        
        if (setsockopt( serverfd, SOL_SCTP, SCTP_EVENTS,
               (const void *)&events, sizeof(events) )) {
		uwsgi_error("setsockopt()");
		close(serverfd);
		goto clear;
	}

	int sctp_nodelay = 1;
	if (setsockopt( serverfd, SOL_SCTP, SCTP_NODELAY, &sctp_nodelay, sizeof(sctp_nodelay))) {
		uwsgi_error("setsockopt()");
		close(serverfd);
		goto clear;
	}

// solaris has no sctp_connectx support
#ifdef __sun__
	if (addresses > 1) {
		uwsgi_log("*** You will only connect to the first specified SCTP address !!! ***\n");
	}
	if (connect(serverfd, (struct sockaddr *) sins, sizeof(struct sockaddr_in))) {
#else
	if (sctp_connectx(serverfd, (struct sockaddr *) sins, addresses, NULL)) {
#endif
		uwsgi_error("sctp_connectx()");
		close(serverfd);
		goto clear;
	}

	

	free(sins);
	free(peers);

	event_queue_add_fd_read(queue, serverfd);

	uwsgi_log("connected to SCTP server %s\n", socket_names);

	return serverfd;

clear:
	free(sins);
	free(peers);
	sleep(1);
	return connect_to_sctp(socket_names, queue);
}

/* sctp address format 127.0.0.1:3031,192.168.0.17:3031 */
int bind_to_sctp(char *socket_names) {

	int serverfd;
	struct sockaddr_in *sins;
	int addresses = 0;

	char *peers = uwsgi_str(socket_names);

	// first step: count required addresses;
        char *p = strtok(peers, ",");
        while(p) {
#ifdef UWSGI_DEBUG
                uwsgi_log("p = %s\n", p);
#endif
                addresses++;
                p = strtok(NULL, ",");
        }

        free(peers);
        peers = uwsgi_str(socket_names);

        sins = uwsgi_calloc(sizeof(struct sockaddr_in) * addresses);

        addresses = 0;
        p = strtok(peers, ",");
        while(p) {
                char *port = strchr(p, ':');
                if (!port) {
                        uwsgi_log("invalid SCTP address/port, please fix it and restart\n");
			uwsgi_nuclear_blast();
                }
                sins[addresses].sin_family = AF_INET;
                *port = 0;
                sins[addresses].sin_addr.s_addr = inet_addr(p);
                sins[addresses].sin_port = htons( atoi(port+1) );
                addresses++;
                p = strtok(NULL, ",");
        }

	serverfd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
	if (serverfd < 0) {
		uwsgi_error("socket()");
		uwsgi_nuclear_blast();
	}

	struct sctp_event_subscribe events;
        struct sctp_initmsg initmsg;

        memset(&initmsg, 0, sizeof(initmsg));
        initmsg.sinit_max_instreams = 0xffff;
        initmsg.sinit_num_ostreams = 0xffff;

        if (setsockopt(serverfd, IPPROTO_SCTP,
                       SCTP_INITMSG, &initmsg, sizeof(initmsg))) {
                uwsgi_error("setsockopt()");
		uwsgi_nuclear_blast();
        }

        memset( (void *)&events, 0, sizeof(events) );
        events.sctp_data_io_event = 1;
	/*
        events.sctp_peer_error_event = 1;
        events.sctp_shutdown_event = 1;
	*/

        if (setsockopt( serverfd, SOL_SCTP, SCTP_EVENTS,
               (const void *)&events, sizeof(events) )) {
                uwsgi_error("setsockopt()");
		uwsgi_nuclear_blast();
        }


	if (sctp_bindx(serverfd, (struct sockaddr *) sins, addresses, SCTP_BINDX_ADD_ADDR) < 0) {
		uwsgi_error("sctp_bindx()");
		uwsgi_nuclear_blast();
	}


	if (listen(serverfd, uwsgi.listen_queue) != 0) {
		uwsgi_error("listen()");
		uwsgi_nuclear_blast();
	}

	free(peers);
	free(sins);

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

	if (socket_name[0] == '@') {
		un_size = sizeof(uws_addr.sun_family) + strlen(socket_name) + 1;
		memcpy(uws_addr.sun_path + 1, socket_name + 1, UMIN(strlen(socket_name + 1), 101));
	}
	else if (strlen(socket_name) > 1 && socket_name[0] == '\\' && socket_name[1] == '0') {
		un_size = sizeof(uws_addr.sun_family) + strlen(socket_name + 1) + 1;
		memcpy(uws_addr.sun_path + 1, socket_name + 2, UMIN(strlen(socket_name + 2), 101));
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
		// avoid error storm
		//uwsgi_error("connect()");
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
					uwsgi_log("[uwsgi-autoip] found %s for %s on interface %s\n", new_socket, socket_name, ifa->ifa_name);
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

socklen_t socket_to_un_addr(char *socket_name, struct sockaddr_un * sun_addr) {

	size_t len = strlen(socket_name);

	if (len > 102) {
		uwsgi_log("invalid UNIX socket address: %s\n", socket_name);
		uwsgi_nuclear_blast();
	}

	memset(sun_addr, 0, sizeof(struct sockaddr_un));

	sun_addr->sun_family = AF_UNIX;

	// abstract socket
	if (socket_name[0] == '@') {
		memcpy(sun_addr->sun_path + 1, socket_name + 1, UMIN(len - 1, 101));
		len = strlen(socket_name) + 1;
	}
	else if (len > 1 && socket_name[0] == '\\' && socket_name[1] == '0') {
		memcpy(sun_addr->sun_path + 1, socket_name + 2, UMIN(len - 2, 101));
		len = strlen(socket_name + 1) + 1;
	}
	else {
		memcpy(sun_addr->sun_path, socket_name, UMIN(len, 102));
	}

	return sizeof(sun_addr->sun_family) + len;
}

socklen_t socket_to_in_addr(char *socket_name, char *port, int portn, struct sockaddr_in *sin_addr) {

	memset(sin_addr, 0, sizeof(struct sockaddr_in));

	sin_addr->sin_family = AF_INET;
	if (port) {
		*port = 0;
		sin_addr->sin_port = htons(atoi(port + 1));
	}
	else {
		sin_addr->sin_port = htons(portn);
	}

	if (socket_name[0] == 0) {
		sin_addr->sin_addr.s_addr = INADDR_ANY;
	}
	else {
		char *resolved = uwsgi_resolve_ip(socket_name);
		if (resolved) {
			sin_addr->sin_addr.s_addr = inet_addr(resolved);
		}
		else {
			sin_addr->sin_addr.s_addr = inet_addr(socket_name);
		}
	}

	if (port) {
		*port = ':';
	}

	return sizeof(struct sockaddr_in);

}

int bind_to_tcp(char *socket_name, int listen_queue, char *tcp_port) {

	int serverfd;
	struct sockaddr_in uws_addr;
	int reuse = 1;

	socket_to_in_addr(socket_name, tcp_port, 0, &uws_addr);

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

// set non-blocking socket
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

// set blocking socket
void uwsgi_socket_b(int fd) {
        int arg;

        arg = fcntl(fd, F_GETFL, NULL);
        if (arg < 0) {
                uwsgi_error("fcntl()");
                return;
        }
	arg &= (~O_NONBLOCK);
        if (fcntl(fd, F_SETFL, arg) < 0) {
                uwsgi_error("fcntl()");
                return;
        }

}


int timed_connect(struct pollfd *fdpoll, const struct sockaddr *addr, int addr_size, int timeout, int async) {

	int arg, ret;
	int soopt = 0;
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
	while (uwsgi_sock) {
		count++;
		uwsgi_sock = uwsgi_sock->next;
	}

	return count;
}

int uwsgi_get_socket_num(struct uwsgi_socket *uwsgi_sock) {

	int count = 0;
	struct uwsgi_socket *current_sock = uwsgi.sockets;

	while (current_sock) {
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

	while (current_sock) {
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
		while (uwsgi_sock) {
			old_uwsgi_sock = uwsgi_sock;
			uwsgi_sock = uwsgi_sock->next;
		}

		uwsgi_sock = uwsgi_malloc(sizeof(struct uwsgi_socket));
		old_uwsgi_sock->next = uwsgi_sock;
	}

	memset(uwsgi_sock, 0, sizeof(struct uwsgi_socket));
	uwsgi_sock->name = name;
	uwsgi_sock->fd = -1;

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
		while (uwsgi_sock) {
			old_uwsgi_sock = uwsgi_sock;
			uwsgi_sock = uwsgi_sock->next;
		}

		uwsgi_sock = uwsgi_malloc(sizeof(struct uwsgi_socket));
		old_uwsgi_sock->next = uwsgi_sock;
	}

	memset(uwsgi_sock, 0, sizeof(struct uwsgi_socket));
	uwsgi_sock->name = name;
	uwsgi_sock->fd = -1;

	if (!name)
		return uwsgi_sock;

	if (name[0] == '=') {
		int shared_socket = atoi(uwsgi_sock->name + 1);
		if (shared_socket >= 0) {
			struct uwsgi_socket *uss = uwsgi_get_shared_socket_by_num(shared_socket);
			if (!uss) {
				uwsgi_log("unable to use shared socket %d\n", shared_socket);
				exit(1);
			}
			uwsgi_sock->bound = 1;
			uwsgi_sock->shared = 1;
			uwsgi_sock->from_shared = shared_socket;
			return uwsgi_sock;
		}
	}
	char *tcp_port = strchr(name, ':');
	if (tcp_port) {
		// INET socket, check for 0 port
		if (tcp_port[1] == 0 || tcp_port[1] == '0') {
			uwsgi_sock->fd = bind_to_tcp(name, uwsgi.listen_queue, tcp_port);
			uwsgi_sock->family = AF_INET;
			uwsgi_sock->bound = 1;

			uwsgi_sock->auto_port = 1;

			socket_type_len = sizeof(struct sockaddr_in);

			if (getsockname(uwsgi_sock->fd, (struct sockaddr *) &sin, &socket_type_len)) {
				uwsgi_error("getsockname()");
				exit(1);
			}


			char *auto_port = uwsgi_num2str(ntohs(sin.sin_port));
			uwsgi_sock->name = uwsgi_concat3n(name, tcp_port - name, ":", 1, auto_port, strlen(auto_port));
		}
		// is it fd 0 ?
		else if (tcp_port[1] == ':') {
			uwsgi_sock->fd = 0;
			uwsgi_sock->family = AF_INET;
			uwsgi_sock->bound = 1;

			socket_type_len = sizeof(struct sockaddr_in);

			if (getsockname(0, (struct sockaddr *) &sin, &socket_type_len)) {
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

	socket_type_len = sizeof(struct sockaddr_un);
	gsa.sa = &usa.sa;
	if (!getsockname(fd, gsa.sa, &socket_type_len)) {
		if (socket_type_len <= 2) {
			// unbound socket
			return;
		}
		if (gsa.sa->sa_family == AF_UNIX) {
			if (usa.sa_un.sun_path[0] == 0)
				abstract = 1;
			// is it a zerg ?
			if (uwsgi_sock->name == NULL) {
				uwsgi_sock->fd = fd;
				uwsgi_sock->family = AF_UNIX;
				uwsgi_sock->bound = 1;
				uwsgi_sock->name = uwsgi_concat2(usa.sa_un.sun_path + abstract, "");
				if (uwsgi.zerg) {
					uwsgi_log("uwsgi zerg socket %d attached to UNIX address %s fd %d\n", uwsgi_get_socket_num(uwsgi_sock), usa.sa_un.sun_path + abstract, uwsgi_sock->fd);
				}
				else {
					uwsgi_log("uwsgi socket %d attached to UNIX address %s fd %d\n", uwsgi_get_socket_num(uwsgi_sock), usa.sa_un.sun_path + abstract, uwsgi_sock->fd);
				}
				return;
			}
			if (!strcmp(usa.sa_un.sun_path + abstract, uwsgi_sock->name + abstract)) {
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

	while (uwsgi_sock) {
		if (uwsgi_sock->bound)
			close(uwsgi_sock->fd);
		uwsgi_sock = uwsgi_sock->next;
	}
}

struct uwsgi_socket *uwsgi_del_socket(struct uwsgi_socket *uwsgi_sock) {

	struct uwsgi_socket *uwsgi_current_sock = uwsgi.sockets, *old_sock = NULL;

	while (uwsgi_current_sock) {
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

	while (uwsgi_sock) {
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

struct uwsgi_socket *uwsgi_get_shared_socket_by_num(int num) {

	int counter = 0;

	struct uwsgi_socket *found_sock = NULL, *uwsgi_sock = uwsgi.shared_sockets;

	while (uwsgi_sock) {
		if (counter == num) {
			found_sock = uwsgi_sock;
			break;
		}
		counter++;
		uwsgi_sock = uwsgi_sock->next;
	}

	if (found_sock) {
		return found_sock;
	}

	return NULL;
}

struct uwsgi_socket *uwsgi_get_socket_by_num(int num) {

	int counter = 0;

	struct uwsgi_socket *found_sock = NULL, *uwsgi_sock = uwsgi.sockets;

	while (uwsgi_sock) {
		if (counter == num) {
			found_sock = uwsgi_sock;
			break;
		}
		counter++;
		uwsgi_sock = uwsgi_sock->next;
	}

	if (found_sock) {
		return found_sock;
	}

	return NULL;
}



void uwsgi_add_sockets_to_queue(int queue) {

	struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;
	while (uwsgi_sock) {
#ifdef UWSGI_SCTP
		if (uwsgi_sock->fd == -1 && uwsgi_sock->proto_name && !strcmp(uwsgi_sock->proto_name, "sctp")) {
			// continue until a connection is ready
			uwsgi_sock->fd = connect_to_sctp(uwsgi_sock->name, queue);
			uwsgi_sock->queue = queue;
		}
		else
#endif
		if (uwsgi_sock->fd > -1) {
			event_queue_add_fd_read(queue, uwsgi_sock->fd);
		}
		uwsgi_sock = uwsgi_sock->next;
	}

}

void uwsgi_del_sockets_from_queue(int queue) {

	struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;
	while (uwsgi_sock) {
		if (uwsgi_sock->fd == -1) goto nextsock;
		event_queue_del_fd(queue, uwsgi_sock->fd, event_queue_read());
nextsock:
		uwsgi_sock = uwsgi_sock->next;
	}

}

int uwsgi_is_bad_connection(int fd) {

	int soopt = 0;
	socklen_t solen = sizeof(int);

	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *) (&soopt), &solen) < 0) {
		return -1;
	}

	// will be 0 if all ok
	return soopt;
}

int uwsgi_socket_is_already_bound(char *name) {
	struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;
	while(uwsgi_sock) {
		if (uwsgi_sock->name && !strcmp(uwsgi_sock->name, name) && uwsgi_sock->bound) {
			return 1;
		}
		uwsgi_sock = uwsgi_sock->next;
	}
	return 0;
}

int uwsgi_socket_uniq(struct uwsgi_socket *list, struct uwsgi_socket *item) {
	int found = 0;

	if (list == item) return 0;
	struct uwsgi_socket *uwsgi_sock = list;
	while(uwsgi_sock && uwsgi_sock != item) {
		if (uwsgi_sock->fd == -1) goto nextsock;
		if (!strcmp(uwsgi_sock->name, item->name)) {
			found = 1;
			break;
		}
nextsock:
		uwsgi_sock = uwsgi_sock->next;	
	}
	return found;
}

void uwsgi_manage_zerg(int fd, int num_sockets, int *sockets) {
	struct sockaddr_un zsun;
	socklen_t zsun_len = sizeof(struct sockaddr_un);

	int zerg_client = accept(fd, (struct sockaddr *) &zsun, &zsun_len);
	if (zerg_client < 0) {
		uwsgi_error("zerg: accept()");
		return;
	}

	if (!num_sockets) {
		num_sockets = uwsgi_count_sockets(uwsgi.sockets);
	}

	struct msghdr zerg_msg;
	void *zerg_msg_control = uwsgi_malloc(CMSG_SPACE(sizeof(int) * num_sockets));
	struct iovec zerg_iov[2];
	struct cmsghdr *cmsg;

	zerg_iov[0].iov_base = "uwsgi-zerg";
	zerg_iov[0].iov_len = 10;
	zerg_iov[1].iov_base = &num_sockets;
	zerg_iov[1].iov_len = sizeof(int);

	zerg_msg.msg_name = NULL;
	zerg_msg.msg_namelen = 0;

	zerg_msg.msg_iov = zerg_iov;
	zerg_msg.msg_iovlen = 2;

	zerg_msg.msg_flags = 0;
	zerg_msg.msg_control = zerg_msg_control;
	zerg_msg.msg_controllen = CMSG_SPACE(sizeof(int) * num_sockets);

	cmsg = CMSG_FIRSTHDR(&zerg_msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(int) * num_sockets);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;

	unsigned char *zerg_fd_ptr = CMSG_DATA(cmsg);

	if (!sockets) {
		struct uwsgi_socket *uwsgi_sock = uwsgi.sockets;
		int uniq_count = 0;
		while (uwsgi_sock) {
			if (uwsgi_sock->fd == -1) goto nextsock;
			if (!uwsgi_socket_uniq(uwsgi.sockets, uwsgi_sock)) {
				memcpy(zerg_fd_ptr, &uwsgi_sock->fd, sizeof(int));
				zerg_fd_ptr += sizeof(int);
				uniq_count++;
			}
nextsock:
			uwsgi_sock = uwsgi_sock->next;
		}
		zerg_iov[1].iov_base = &uniq_count;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int) * uniq_count);
	}
	else {
		memcpy(zerg_fd_ptr, sockets, sizeof(int) * num_sockets);
	}

	if (sendmsg(zerg_client, &zerg_msg, 0) < 0) {
		uwsgi_error("sendmsg()");
	}

	free(zerg_msg_control);

	close(zerg_client);

}
