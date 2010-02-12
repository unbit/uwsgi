#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

int bind_to_unix(char *socket_name, int listen_queue, int chmod_socket, int abstract_socket) {

	int serverfd;
	struct sockaddr_un *uws_addr;

	fprintf(stderr, "binding on UNIX socket: %s\n", socket_name);

        // leave 1 byte for abstract namespace (108 linux -> 104 bsd/mac)
        if (strlen(socket_name) > 102) {
        	fprintf(stderr, "invalid socket name\n");
                	exit(1);
        }

        uws_addr = malloc(sizeof(struct sockaddr_un));
        if (uws_addr == NULL) {
        	perror("malloc()");
                exit(1);
        }

        memset(uws_addr, 0, sizeof(struct sockaddr_un)) ;
        serverfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (serverfd < 0) {
        	perror("socket()");
                exit(1);
        }
        if (abstract_socket == 0) {
        	if (unlink(socket_name) != 0 && errno != ENOENT) {
                	perror("unlink()");
                }
        }

        if (abstract_socket ==1) {
        	fprintf(stderr, "setting abstract socket mode (warning: only Linux supports this)\n");
        }

	uws_addr->sun_family = AF_UNIX;
	strcpy(uws_addr->sun_path+abstract_socket, socket_name);

	if (bind(serverfd, (struct sockaddr *) uws_addr, strlen(socket_name)+ abstract_socket + ( (void *)uws_addr->sun_path - (void *)uws_addr) ) != 0) {
		perror("bind()");
		exit(1);
	}

	if (listen(serverfd, listen_queue) != 0) {
        	perror("listen()");
                exit(1);
	}

	// chmod unix socket for lazy users
	if (chmod_socket == 1 && abstract_socket == 0) {
        	fprintf(stderr, "chmod() socket to 666 for lazy and brave users\n");
                if (chmod(socket_name, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH) != 0) {
                	perror("chmod()");
                }
	}

	return serverfd;
}

#ifdef SCTP

#define MAX_SCTP_ADDRESS 4
/* sctp address format sctp:127.0.0.1,192.168.0.17:3031 */
int bind_to_sctp(char *socket_name, int listen_queue, char *sctp_port) {
	int serverfd;
	struct sockaddr_in uws_addr[MAX_SCTP_ADDRESS];
	int num_ip = 0 ;

	struct sctp_initmsg sctp_im ;
	

	sctp_port[0] = 0 ;
	memset(uws_addr, 0, sizeof(struct sockaddr_in)*MAX_SCTP_ADDRESS);
	memset(&sctp_im, 0, sizeof(struct sctp_initmsg));

	while(socket_name != NULL && num_ip < MAX_SCTP_ADDRESS) {
		char *ap;
		while( (ap = strsep(&socket_name, ",")) != NULL) {
			if (*ap != '\0') {
				uws_addr[num_ip].sin_family = AF_INET;
				uws_addr[num_ip].sin_port = htons(atoi(sctp_port+1));
				uws_addr[num_ip].sin_addr.s_addr = inet_addr(ap);
				num_ip++;
			}	
		}
	}

	serverfd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
        if (serverfd < 0) {
                perror("socket()");
                exit(1);
        }

	fprintf(stderr,"binding on %d SCTP interfaces on port: %d\n", num_ip, ntohs(uws_addr[0].sin_port));


	if(sctp_bindx(serverfd, (struct sockaddr *) uws_addr, num_ip, SCTP_BINDX_ADD_ADDR) != 0) {
		perror("sctp_bindx()");
		exit(1);
	}

	sctp_im.sinit_max_instreams = 0xFFFF ;
        sctp_im.sinit_num_ostreams = 0xFFFF ;

        if (setsockopt(serverfd, IPPROTO_SCTP, SCTP_INITMSG, &sctp_im, sizeof(sctp_im))) {
                perror("setsockopt()");
        }

	if (listen(serverfd, listen_queue) != 0) {
                perror("listen()");
                exit(1);
        }

        return serverfd;
}
#endif

#ifndef ROCK_SOLID
#ifndef UNBIT
int bind_to_udp(char *socket_name) {
	int serverfd ;
	struct sockaddr_in uws_addr;
	char *udp_port ;

	udp_port = strchr(socket_name, ':');
	if (udp_port == NULL) {
		return -1 ;
	}

	udp_port[0] = 0 ;
	memset(&uws_addr, 0, sizeof(struct sockaddr_in));
	uws_addr.sin_family = AF_INET;
	uws_addr.sin_port = htons(atoi(udp_port+1));
	uws_addr.sin_addr.s_addr = inet_addr(socket_name);

	serverfd = socket(AF_INET,SOCK_DGRAM,0);
	if (serverfd < 0) {
		perror("socket()");
		return -1 ;
        }	

	if (bind(serverfd, (struct sockaddr *) &uws_addr, sizeof(uws_addr) ) != 0) {
                perror("bind()");
		close(serverfd);
		return -1 ;
        }

	return serverfd;
	
}
#endif
#endif

int bind_to_tcp(char *socket_name, int listen_queue, char *tcp_port) {

	int serverfd;
	struct sockaddr_in uws_addr;
	int reuse = 1 ;
	
	tcp_port[0] = 0 ;
	memset(&uws_addr, 0, sizeof(struct sockaddr_in));

	uws_addr.sin_family = AF_INET;
	uws_addr.sin_port = htons(atoi(tcp_port+1));


	if (socket_name[0] == 0) {
		uws_addr.sin_addr.s_addr = INADDR_ANY;
	}
	else {
		uws_addr.sin_addr.s_addr = inet_addr(socket_name);
	}

        serverfd = socket(AF_INET, SOCK_STREAM, 0);
        if (serverfd < 0) {
        	perror("socket()");
                exit(1);
        }

	if (setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&reuse , sizeof(int)) < 0) {
		perror("setsockopt()");
		exit(1);
	}

	if (!uwsgi.no_defer_accept) {

#ifdef TCP_DEFER_ACCEPT
		if (setsockopt(serverfd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &uwsgi.options[UWSGI_OPTION_SOCKET_TIMEOUT], sizeof(int))) {
			perror("setsockopt()");
		}
		else {
			fprintf(stderr,"TCP_DEFER_ACCEPT enabled.\n");
		}
#endif

	}


	fprintf(stderr,"binding on TCP port: %d\n", ntohs(uws_addr.sin_port));

	if (bind(serverfd, (struct sockaddr *) &uws_addr, sizeof(uws_addr) ) != 0) {
		perror("bind()");
		exit(1);
	}

	if (listen(serverfd, listen_queue) != 0) {
        	perror("listen()");
                exit(1);
	}


	return serverfd;
}
