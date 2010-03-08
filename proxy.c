#ifdef UWSGI_PROXY

/* 

	uWSGI proxy

	it needs one of this tecnology to work:

	- epoll (linux 2.6)
	- kqueue (various BSD)
	- /dev/poll Solaris

*/

#include "uwsgi.h"

#include <sys/epoll.h>
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

	int epfd ;
	struct epoll_event ee;
	struct epoll_event *eevents;
	int max_events = 64 ;
	int nevents, i ;
	const int nonblocking = 1 ;
	const int blocking = 0 ;

	char buffer[4096];
	int rlen ;
	int wlen ;
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
	
	signal(SIGINT, (void *)&end_proxy);
	signal(SIGTERM, (void *)&reload_proxy);
	signal(SIGHUP, (void *)&reload_proxy);
	// and welcome to the loop...

	for(;;) {
		nevents = epoll_wait(epfd, eevents, max_events, -1);	
		if (nevents < 0) {
			perror("epoll_wait()");
			continue;
		}
	
		for(i=0;i<nevents;i++) {


			if (eevents[i].data.fd == proxyfd) {

				if (eevents[i].events & EPOLLIN) {
					// new connection, accept it
					ee.data.fd = accept(proxyfd, (struct sockaddr *) &upc_addr, &upc_len);
					if (ee.data.fd < 0) {
						perror("accept()");
						continue;
					}
					upcs[ee.data.fd].node = -1;

					// now connect to the first worker available

					upcs[ee.data.fd].dest_fd = socket(AF_INET, SOCK_STREAM, 0);
					if (upcs[ee.data.fd].dest_fd < 0) {
						perror("socket()");
						uwsgi_proxy_close(upcs, ee.data.fd);
						continue;
					}
					upcs[upcs[ee.data.fd].dest_fd].node = -1;

					// set nonblocking
					if (ioctl(upcs[ee.data.fd].dest_fd, FIONBIO, &nonblocking)) {
						perror("ioctl()");
						uwsgi_proxy_close(upcs, ee.data.fd);
						continue;
					}

					upcs[ee.data.fd].status = 0;
					upcs[ee.data.fd].retry = 0;
					next_node = uwsgi_proxy_find_next_node(next_node);
					if (next_node == -1) {
						fprintf(stderr,"unable to find an available worker in the cluster !\n");
						uwsgi_proxy_close(upcs, ee.data.fd);
						continue;
					}
					upcs[upcs[ee.data.fd].dest_fd].node = next_node ;
					rc = connect(upcs[ee.data.fd].dest_fd, (struct sockaddr *) &uwsgi.shared->nodes[next_node].ucn_addr, sizeof(struct sockaddr_in));
					uwsgi.shared->nodes[next_node].connections++;
			
					if (!rc) {
						// connected to worker, put it in the epoll_list

						ee.events = EPOLLIN ;
						if (epoll_ctl(epfd, EPOLL_CTL_ADD, ee.data.fd, &ee)) {
                					perror("epoll_ctl()");
							uwsgi_proxy_close(upcs, ee.data.fd);
                					continue;
        					}

						upcs[upcs[ee.data.fd].dest_fd].dest_fd = ee.data.fd;
						upcs[upcs[ee.data.fd].dest_fd].status = 0;
						upcs[upcs[ee.data.fd].dest_fd].retry = 0;

						ee.data.fd = upcs[ee.data.fd].dest_fd ;

						ee.events = EPOLLIN ;
						if (epoll_ctl(epfd, EPOLL_CTL_ADD, ee.data.fd, &ee)) {
                					perror("epoll_ctl()");
							uwsgi_proxy_close(upcs, ee.data.fd);
                					continue;
        					}

						// re-set blocking
						if (ioctl(upcs[upcs[ee.data.fd].dest_fd].dest_fd, FIONBIO, &blocking)) {
							perror("ioctl()");
							uwsgi_proxy_close(upcs, ee.data.fd);
							continue;
						}

					}
					else if (errno == EINPROGRESS) {
						// the socket is waiting, set status to CONNECTING
						upcs[ee.data.fd].status = UWSGI_PROXY_WAITING;
						upcs[upcs[ee.data.fd].dest_fd].dest_fd = ee.data.fd;
						upcs[upcs[ee.data.fd].dest_fd].status = UWSGI_PROXY_CONNECTING;
						upcs[upcs[ee.data.fd].dest_fd].retry = 0;

						ee.data.fd = upcs[ee.data.fd].dest_fd ;
						ee.events = EPOLLOUT ;
						if (epoll_ctl(epfd, EPOLL_CTL_ADD, ee.data.fd, &ee)) {
                					perror("epoll_ctl()");
							uwsgi_proxy_close(upcs, ee.data.fd);
                					continue;
        					}
					}
					else {
						// connection failed, retry with the next node ?
						perror("connect()");
						// close only when all node are tried
						uwsgi_proxy_close(upcs, ee.data.fd);
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
				if (eevents[i].events & EPOLLIN) {
					
					// is this a connected client/worker ?
						//fprintf(stderr,"ready %d\n", upcs[eevents[i].data.fd].status);

					if (!upcs[eevents[i].data.fd].status) {
						if (upcs[eevents[i].data.fd].dest_fd >= 0) {
							rlen = read(eevents[i].data.fd, buffer, 4096);
							if (rlen < 0) {
								perror("read()");
								uwsgi_proxy_close(upcs, eevents[i].data.fd);
								continue;
							}
							else if (rlen == 0) {
								uwsgi_proxy_close(upcs, eevents[i].data.fd);
								continue;
							}
							else {
								wlen = write(upcs[eevents[i].data.fd].dest_fd, buffer, rlen);
								if (wlen != rlen) {
									perror("write()");
									uwsgi_proxy_close(upcs, eevents[i].data.fd);
									continue;
								}
							}
						}
						else {
							uwsgi_proxy_close(upcs, eevents[i].data.fd);
							continue;
						}
					}
					else if (upcs[eevents[i].data.fd].status == UWSGI_PROXY_WAITING) {
						// disconnected node
						continue;
					}
					else {
						fprintf(stderr,"UNKOWN STATUS %d\n", upcs[eevents[i].data.fd].status);
						continue;
					}
				}
				else if (eevents[i].events & EPOLLOUT) {
					if ( upcs[eevents[i].data.fd].status == UWSGI_PROXY_CONNECTING ){

						ee.data.fd = upcs[eevents[i].data.fd].dest_fd ;
						ee.events = EPOLLIN ;
						upcs[ee.data.fd].status = 0;
						if (epoll_ctl(epfd, EPOLL_CTL_ADD, ee.data.fd, &ee)) {
                					perror("epoll_ctl()");
							uwsgi_proxy_close(upcs, ee.data.fd);
                					continue;
        					}

						ee.data.fd = upcs[ee.data.fd].dest_fd ;
						upcs[ee.data.fd].status = 0;
						if (epoll_ctl(epfd, EPOLL_CTL_MOD, ee.data.fd, &ee)) {
                					perror("epoll_ctl()");
							uwsgi_proxy_close(upcs, ee.data.fd);
                					continue;
        					}
						// re-set blocking
						if (ioctl(ee.data.fd, FIONBIO, &blocking)) {
							perror("ioctl()");
							uwsgi_proxy_close(upcs, ee.data.fd);
							continue;
						}
					}
					else {
						fprintf(stderr,"strange event for %d\n", eevents[i].data.fd);
					}
				}
				else {
					if (upcs[eevents[i].data.fd].status == UWSGI_PROXY_CONNECTING) {
						if (getsockopt(eevents[i].data.fd, SOL_SOCKET, SO_ERROR, (void*)(&soopt), &solen) < 0) {
                                        		perror("getsockopt()");
                                		}
                                		/* is something bad ? */
                                		if (soopt) {
                                        		fprintf(stderr,"connect() %s\n", strerror(soopt));
                                		}

						// increase errors on node
						fprintf(stderr,"*** marking cluster node %d/%s as failed ***\n", upcs[eevents[i].data.fd].node, uwsgi.shared->nodes[upcs[eevents[i].data.fd].node].name);
						uwsgi.shared->nodes[upcs[eevents[i].data.fd].node].errors++;	
						uwsgi.shared->nodes[upcs[eevents[i].data.fd].node].status = UWSGI_NODE_FAILED;	
					}
					else {
						fprintf(stderr,"STRANGE EVENT !!! %d %d %d\n", eevents[i].data.fd, eevents[i].events, upcs[eevents[i].data.fd].status);
					}
					uwsgi_proxy_close(upcs, eevents[i].data.fd);
					continue;
				}
			}
		}
	}
}
	
#else
#warning "*** PROXY support is disabled ***"
#endif
