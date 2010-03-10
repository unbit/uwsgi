#ifdef UWSGI_PROXY

/* 

	uWSGI proxy

	it needs one of this tecnology to work:

	- epoll (linux 2.6)
	- kqueue (various BSD and Darwin)
	- /dev/poll (Solaris)

*/

#include "uwsgi.h"

#ifdef __linux__
	#include <sys/epoll.h>
	#define UWSGI_PROXY_USE_EPOLL 1
	#define EV_FD eevents[i].data.fd
	#define EV_EV eevents[i].events
	#define EV_IN EPOLLIN
	#define EV_OUT EPOLLOUT
	#define NEV_FD ee.data.fd
	#define NEV_EV ee.events
	#define NEV_ADD epoll_ctl(epfd, EPOLL_CTL_ADD, NEV_FD, &ee)
	#define NEV_MOD epoll_ctl(epfd, EPOLL_CTL_MOD, NEV_FD, &ee)
	#define EV_NAME "epoll_ctl()"
	#define EV_IS_IN EV_EV & EV_IN
	#define EV_IS_OUT EV_EV & EV_OUT
#elif  defined(__sun__)

#else
	#include <sys/event.h>
	#define UWSGI_PROXY_USE_KQUEUE 1
	#define EV_FD krevents[i].ident
	#define EV_EV krevents[i].filter
	#define EV_IN EVFILT_READ
	#define EV_OUT EVFILT_WRITE
	#define NEV_FD kev.ident
	#define NEV_EV kev.filter
	#define NEV_ADD kevent(kq, &kev, 1, NULL, 0, NULL) < 0
	#define NEV_MOD kevent(kq, &kev, 1, NULL, 0, NULL) < 0
	#define EV_NAME "kevent()"
	#define EV_IS_IN EV_EV == EV_IN
	#define EV_IS_OUT EV_EV == EV_OUT
#endif

#include <sys/ioctl.h>


#define UWSGI_PROXY_CONNECTING	1
#define UWSGI_PROXY_WAITING	2

extern struct uwsgi_server uwsgi;

struct uwsgi_proxy_connection {
	
	int dest_fd ;
	int status ;
	int retry ;
	int node;
};

static void end_proxy(void) {
        exit (UWSGI_END_CODE);
}


static void reload_proxy (void) {
        exit (UWSGI_RELOAD_CODE);
}

static void send_http_service_unavailable(int fd) {

	if (write(fd, "HTTP/1.0 503 Service Unavailable\r\n", 34) != 34) {
		perror("write()");
		return ;
	}

	if (write(fd, "Content-type: text/html\r\n\r\n", 27) != 27) {
		perror("write()");
		return ;
	}

	if (write(fd, "<h1>Service Unavailable</h1>", 28) != 28) {
		perror("write()");
		return ;
	}
	
}

static void uwsgi_proxy_close(struct uwsgi_proxy_connection *upcs, int fd) {

	
	if (upcs[fd].dest_fd >=0) {
		close(upcs[fd].dest_fd);
		upcs[upcs[fd].dest_fd].dest_fd = -1 ;
		upcs[upcs[fd].dest_fd].status = 0 ;
		upcs[upcs[fd].dest_fd].retry = 0 ;
		if (upcs[upcs[fd].dest_fd].node > -1) {
			if (uwsgi.shared->nodes[upcs[upcs[fd].dest_fd].node].connections > 0)
				uwsgi.shared->nodes[upcs[upcs[fd].dest_fd].node].connections--;
		}
	}

	if (fd >= 0) {
		close(fd);
		upcs[fd].dest_fd = -1 ;
		upcs[fd].status = 0 ;
		upcs[fd].retry = 0 ;
		if (upcs[fd].node > -1) {
			if (uwsgi.shared->nodes[upcs[fd].node].connections > 0)
				uwsgi.shared->nodes[upcs[fd].node].connections--;
		}
	}
	
}

static int uwsgi_proxy_find_next_node(int current_node) {
	
	int i ;

	current_node++;
	if (current_node >= MAX_CLUSTER_NODES) {
		current_node = 0 ;
	}

	// is it a good node ?
	if (uwsgi.shared->nodes[current_node].name[0] != 0 && uwsgi.shared->nodes[current_node].status == UWSGI_NODE_OK) {
		if (uwsgi.shared->nodes[current_node].connections < uwsgi.shared->nodes[current_node].workers)
			return current_node ;
	}

	// try to find a better one

	for(i=0;i<MAX_CLUSTER_NODES;i++) {
		if (uwsgi.shared->nodes[i].name[0] != 0 && uwsgi.shared->nodes[i].status == UWSGI_NODE_OK) {
			if (uwsgi.shared->nodes[i].connections < uwsgi.shared->nodes[i].workers)
				return i ;
		}
	}

	// ok, it is a very loaded system, fallback to round robin
	if (uwsgi.shared->nodes[current_node].name[0] != 0 && uwsgi.shared->nodes[current_node].status == UWSGI_NODE_OK) {
			return current_node ;
	}

	for(i=0;i<MAX_CLUSTER_NODES;i++) {
		if (uwsgi.shared->nodes[i].name[0] != 0 && uwsgi.shared->nodes[i].status == UWSGI_NODE_OK) {
			return i ;
		}
	}

	return -1 ;
	
}

void uwsgi_proxy(int proxyfd) {

#ifdef __linux__
	int epfd ;
	struct epoll_event ee;
	struct epoll_event *eevents;
#else
	int kq;
	struct kevent *krevents ;
	struct kevent kev ;
#endif

	int max_events = 64 ;
	int nevents, i ;
	const int nonblocking = 1 ;
	const int blocking = 0 ;

	char buffer[4096];
	ssize_t rlen ;
	ssize_t wlen ;
	int max_connections = sysconf (_SC_OPEN_MAX);

	int soopt;
	socklen_t solen = sizeof(int);

	int rc ;

	struct uwsgi_proxy_connection *upcs ;

	struct sockaddr_in upc_addr ;
	socklen_t upc_len = sizeof(struct sockaddr_in);

	int next_node = -1;

	fprintf(stderr,"spawned uWSGI proxy (pid: %d)\n", getpid());

	fprintf(stderr,"allocating space for %d concurrent proxy connections\n", max_connections);

	// allocate memory for connections
	upcs = malloc(sizeof(struct uwsgi_proxy_connection) * max_connections);
	if (!upcs) {
		perror("malloc()");
		exit(1);
	}
	memset(upcs, 0, sizeof(struct uwsgi_proxy_connection) * max_connections);

#ifdef __linux__
	//init epoll
	epfd = epoll_create(256);

	if (epfd < 0) {
		perror("epoll_create()");
		exit(1);
	}

	// allocate memory for events
	eevents = malloc(sizeof(struct epoll_event)*max_events) ;
	if (!eevents) {
		perror("malloc()");
		exit(1);
	}

	// now add the proxyfd to the epoll list

	ee.events = EPOLLIN ;
	ee.data.fd = proxyfd ;

	if (epoll_ctl(epfd, EPOLL_CTL_ADD, proxyfd, &ee)) {
		perror("epoll_ctl()");
		exit(1);
	}
#else
	kq = kqueue();
	if (kq < 0) {
		perror("kqueue()");
		exit(1);
	}

	// allocate memory for events
	krevents = malloc(sizeof(struct kevent)*max_events) ;
	if (!krevents) {
		perror("malloc()");
		exit(1);
	}

	EV_SET(&kev, proxyfd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) < 0){
		perror("kevent()");
		exit(1);
	}
	
#endif
	
	signal(SIGINT, (void *)&end_proxy);
	signal(SIGTERM, (void *)&reload_proxy);
	signal(SIGHUP, (void *)&reload_proxy);
	// and welcome to the loop...

	for(;;) {

#ifdef __linux__
		nevents = epoll_wait(epfd, eevents, max_events, -1);	
		if (nevents < 0) {
			perror("epoll_wait()");
			continue;
		}
#else
		nevents = kevent(kq, NULL, 0, krevents, max_events, NULL);	
		if (nevents < 0) {
			perror("kevent()");
			continue;
		}
#endif

	
		for(i=0;i<nevents;i++) {


			if (EV_FD == proxyfd) {

				if (EV_IS_IN) {
					// new connection, accept it
					NEV_FD = accept(proxyfd, (struct sockaddr *) &upc_addr, &upc_len);
					if (NEV_FD < 0) {
						perror("accept()");
						continue;
					}
					upcs[NEV_FD].node = -1;

					// now connect to the first worker available

					upcs[NEV_FD].dest_fd = socket(AF_INET, SOCK_STREAM, 0);
					if (upcs[NEV_FD].dest_fd < 0) {
						perror("socket()");
						uwsgi_proxy_close(upcs, NEV_FD);
						continue;
					}
					upcs[upcs[NEV_FD].dest_fd].node = -1;

					// set nonblocking
					if (ioctl(upcs[NEV_FD].dest_fd, FIONBIO, &nonblocking)) {
						perror("ioctl()");
						uwsgi_proxy_close(upcs, NEV_FD);
						continue;
					}

					upcs[NEV_FD].status = 0;
					upcs[NEV_FD].retry = 0;
					next_node = uwsgi_proxy_find_next_node(next_node);
					if (next_node == -1) {
						fprintf(stderr,"unable to find an available worker in the cluster !\n");
						send_http_service_unavailable(NEV_FD);
						uwsgi_proxy_close(upcs, NEV_FD);
						continue;
					}
					upcs[upcs[NEV_FD].dest_fd].node = next_node ;
					rc = connect(upcs[NEV_FD].dest_fd, (struct sockaddr *) &uwsgi.shared->nodes[next_node].ucn_addr, sizeof(struct sockaddr_in));
					uwsgi.shared->nodes[next_node].connections++;
			
					if (!rc) {
						// connected to worker, put it in the epoll_list

						NEV_EV = EV_IN ;
						if (NEV_ADD) {
                					perror(EV_NAME);
							uwsgi_proxy_close(upcs, NEV_FD);
                					continue;
        					}

						upcs[upcs[NEV_FD].dest_fd].dest_fd = NEV_FD;
						upcs[upcs[NEV_FD].dest_fd].status = 0;
						upcs[upcs[NEV_FD].dest_fd].retry = 0;

						NEV_FD = upcs[NEV_FD].dest_fd ;

						NEV_EV = EV_IN ;
						if (NEV_ADD) {
                					perror(EV_NAME);
							uwsgi_proxy_close(upcs, NEV_FD);
                					continue;
        					}

						// re-set blocking
						if (ioctl(upcs[upcs[NEV_FD].dest_fd].dest_fd, FIONBIO, &blocking)) {
							perror("ioctl()");
							uwsgi_proxy_close(upcs, NEV_FD);
							continue;
						}

					}
					else if (errno == EINPROGRESS) {
						// the socket is waiting, set status to CONNECTING
						upcs[NEV_FD].status = UWSGI_PROXY_WAITING;
						upcs[upcs[NEV_FD].dest_fd].dest_fd = NEV_FD;
						upcs[upcs[NEV_FD].dest_fd].status = UWSGI_PROXY_CONNECTING;
						upcs[upcs[NEV_FD].dest_fd].retry = 0;

						NEV_FD = upcs[NEV_FD].dest_fd ;
						NEV_EV = EV_OUT ;
						if (NEV_ADD) {
                					perror(EV_NAME);
							uwsgi_proxy_close(upcs, NEV_FD);
                					continue;
        					}
					}
					else {
						// connection failed, retry with the next node ?
						perror("connect()");
						// close only when all node are tried
						uwsgi_proxy_close(upcs, NEV_FD);
						continue;
					}
					
					
				}
				else {
					fprintf(stderr,"!!! something horrible happened to the uWSGI proxy, reloading it !!!\n");
					exit(1);
				}
			}
			else {
				// this is for clients/workers
				if (EV_IS_IN) {
					
					// is this a connected client/worker ?
						//fprintf(stderr,"ready %d\n", upcs[eevents[i].data.fd].status);

					if (!upcs[EV_FD].status) {
						if (upcs[EV_FD].dest_fd >= 0) {

							rlen = read(EV_FD, buffer, 4096);
							if (rlen < 0) {
								perror("read()");
								uwsgi_proxy_close(upcs, EV_FD);
								continue;
							}
							else if (rlen == 0) {
								uwsgi_proxy_close(upcs, EV_FD);
								continue;
							}
							else {
								wlen = write(upcs[EV_FD].dest_fd, buffer, rlen);
								if (wlen != rlen) {
									perror("write()");
									uwsgi_proxy_close(upcs, EV_FD);
									continue;
								}
							}
						}
						else {
							uwsgi_proxy_close(upcs, EV_FD);
							continue;
						}
					}
					else if (upcs[EV_FD].status == UWSGI_PROXY_WAITING) {
						// disconnected node
						continue;
					}
/*
#ifdef UWSGI_PROXY_USE_KQUEUE
					else if (upcs[EV_FD].status == UWSGI_PROXY_CONNECTING) {
						
						fprintf(stderr,"connecting\n");

						NEV_FD = upcs[EV_FD].dest_fd ;
						NEV_EV = EV_IN ;
						upcs[NEV_FD].status = 0;
						if (NEV_ADD) {
                					perror(EV_NAME);
							uwsgi_proxy_close(upcs, NEV_FD);
                					continue;
        					}

						NEV_FD = upcs[NEV_FD].dest_fd ;
						upcs[NEV_FD].status = 0;
						if (NEV_MOD) {
                					perror(EV_NAME);
							uwsgi_proxy_close(upcs, NEV_FD);
                					continue;
        					}

						// re-set blocking
						if (ioctl(NEV_FD, FIONBIO, &blocking)) {
							perror("ioctl()");
							uwsgi_proxy_close(upcs, NEV_FD);
							continue;
						}

						fprintf(stderr,"connesso\n");

					}
#endif
*/
					else {
						fprintf(stderr,"UNKNOWN STATUS %d\n", upcs[EV_FD].status);
						continue;
					}
				}
				else if (EV_IS_OUT) {
					if ( upcs[EV_FD].status == UWSGI_PROXY_CONNECTING ){

						NEV_FD = upcs[EV_FD].dest_fd ;
						NEV_EV = EV_IN ;
						upcs[NEV_FD].status = 0;
						if (NEV_ADD) {
                					perror(EV_NAME);
							uwsgi_proxy_close(upcs, NEV_FD);
                					continue;
        					}

						NEV_FD = upcs[NEV_FD].dest_fd ;
						upcs[NEV_FD].status = 0;

#ifdef UWSGI_PROXY_USE_KQUEUE
						EV_SET(&kev, NEV_FD, EVFILT_WRITE, EV_ADD|EV_DISABLE, 0, 0, NULL);
						if (NEV_MOD) {
                					perror(EV_NAME);
							uwsgi_proxy_close(upcs, NEV_FD);
                					continue;
        					}
						EV_SET(&kev, NEV_FD, EVFILT_READ, EV_ADD, 0, 0, NULL);
#endif
						if (NEV_MOD) {
                					perror(EV_NAME);
							uwsgi_proxy_close(upcs, NEV_FD);
                					continue;
        					}
						// re-set blocking
						if (ioctl(NEV_FD, FIONBIO, &blocking)) {
							perror("ioctl()");
							uwsgi_proxy_close(upcs, NEV_FD);
							continue;
						}
					}
					else {
						fprintf(stderr,"strange event for %d\n", (int) EV_FD);
					}
				}
				else {
					if (upcs[EV_FD].status == UWSGI_PROXY_CONNECTING) {
						if (getsockopt(EV_FD, SOL_SOCKET, SO_ERROR, (void*)(&soopt), &solen) < 0) {
                                        		perror("getsockopt()");
                                		}
                                		/* is something bad ? */
                                		if (soopt) {
                                        		fprintf(stderr,"connect() %s\n", strerror(soopt));
                                		}

						// increase errors on node
						fprintf(stderr,"*** marking cluster node %d/%s as failed ***\n", upcs[EV_FD].node, uwsgi.shared->nodes[upcs[EV_FD].node].name);
						uwsgi.shared->nodes[upcs[EV_FD].node].errors++;	
						uwsgi.shared->nodes[upcs[EV_FD].node].status = UWSGI_NODE_FAILED;	
					}
					else {
						fprintf(stderr,"STRANGE EVENT !!! %d %d %d\n", (int) EV_FD, EV_EV, upcs[EV_FD].status);
					}
					uwsgi_proxy_close(upcs, EV_FD);
					continue;
				}
			}
		}
	}
}
	
#else
#warning "*** PROXY support is disabled ***"
#endif
