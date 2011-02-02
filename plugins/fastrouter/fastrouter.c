/*

   uWSGI fastrouter

   requires:

   - async
   - caching
   - pcre (optional)

*/

#include "../../uwsgi.h"

#define LONG_ARGS_FASTROUTER		150001

#define FASTROUTER_STATUS_FREE 0
#define FASTROUTER_STATUS_CONNECTING 1
#define FASTROUTER_STATUS_RECV_HDR 2
#define FASTROUTER_STATUS_RECV_VARS 3
#define FASTROUTER_STATUS_RESPONSE 4

struct uwsgi_fastrouter {
	char *socket_name;
	int use_cache;
} ufr;

struct option fastrouter_options[] = {
	{"fastrouter", required_argument, 0, LONG_ARGS_FASTROUTER},
	{"fastrouter-use-cache", no_argument, &ufr.use_cache, 1},
	{0, 0, 0, 0},	
};

extern struct uwsgi_server uwsgi;

struct fastrouter_session {

	int fd;
	int instance_fd;
	int status;
	struct uwsgi_header uh;
	uint8_t h_pos;
	char buffer[0xffff];
	uint16_t pos;

	char *hostname;
	uint16_t hostname_len;

	char *instance_address;
	uint16_t instance_address_len;

	int pass_fd;
};

void fr_get_hostname(char *key, uint16_t keylen, char *val, uint16_t vallen, void *data) {

	struct fastrouter_session *fr_session = (struct fastrouter_session *) data;

	//uwsgi_log("%.*s = %.*s\n", keylen, key, vallen, val);
	if (!uwsgi_strncmp("SERVER_NAME", 11, key, keylen) && !fr_session->hostname_len) {
		fr_session->hostname = val;
		fr_session->hostname_len = vallen;
		return;
	}

	if (!uwsgi_strncmp("HTTP_HOST", 9, key, keylen)) {
		fr_session->hostname = val;
		fr_session->hostname_len = vallen;
		return;
	}
}

struct fastrouter_session *alloc_fr_session() {
	
	return uwsgi_malloc(sizeof(struct fastrouter_session));
}

void fastrouter_loop() {

	int fr_queue;
	int fr_server;
	int nevents;
	int interesting_fd;
	int new_connection;
	ssize_t len;
	int i;

	struct msghdr msg;
	union {
                struct cmsghdr cmsg;
                char control [CMSG_SPACE (sizeof (int))];
        } msg_control;
        struct cmsghdr *cmsg;

	struct sockaddr_un fr_addr;
        socklen_t fr_addr_len = sizeof(struct sockaddr_un);
	
	struct fastrouter_session *fr_session;

	struct fastrouter_session *fr_table[2048];

	struct iovec iov[2];

	int soopt;
        socklen_t solen = sizeof(int);

	for(i=0;i<2048;i++) {
		fr_table[i] = NULL;
	}

	fr_server = bind_to_tcp(ufr.socket_name, uwsgi.listen_queue, ufr.socket_name);

	fr_queue = event_queue_init();
	event_queue_add_fd_read(fr_queue, fr_server);

	for (;;) {

		nevents = event_queue_wait(fr_queue, -1, &interesting_fd);

		if (nevents > 0) {

			//uwsgi_log("interesting_fd: %d\n", interesting_fd);

			if (interesting_fd == fr_server) {
				new_connection = accept(fr_server, (struct sockaddr *) &fr_addr, &fr_addr_len);
				if (new_connection < 0) {
					continue;
				}

				fr_table[new_connection] = alloc_fr_session();
				fr_table[new_connection]->fd = new_connection;
				fr_table[new_connection]->instance_fd = -1; 
				fr_table[new_connection]->status = FASTROUTER_STATUS_RECV_HDR;
				fr_table[new_connection]->h_pos = 0;
				fr_table[new_connection]->pos = 0;
				fr_table[new_connection]->instance_address_len = 0;

				event_queue_add_fd_read(fr_queue, new_connection);
				
			}	
			else {
				fr_session = fr_table[interesting_fd];

				// something is going wrong...
				if (fr_session == NULL) continue;

				switch(fr_session->status) {

					case FASTROUTER_STATUS_RECV_HDR:
						len = recv(fr_session->fd, (char *)(&fr_session->uh) + fr_session->h_pos, 4-fr_session->h_pos, 0);
						if (len <= 0) {
							uwsgi_error("recv()");
							close(fr_session->fd);
							fr_table[fr_session->fd] = NULL;
							free(fr_session);
							break;
						}
						fr_session->h_pos += len;
						if (fr_session->h_pos == 4) {
#ifdef UWSGI_DEBUG
							uwsgi_log("modifier1: %d pktsize: %d modifier2: %d\n", fr_session->uh.modifier1, fr_session->uh.pktsize, fr_session->uh.modifier2);
#endif
							fr_session->status = FASTROUTER_STATUS_RECV_VARS;
						}
						break;


					case FASTROUTER_STATUS_RECV_VARS:
                                                len = recv(fr_session->fd, fr_session->buffer + fr_session->pos, fr_session->uh.pktsize - fr_session->pos, 0);
                                                if (len <= 0) {
                                                        uwsgi_error("recv()");
							close(fr_session->fd);
							fr_table[fr_session->fd] = NULL;
							free(fr_session);
                                                        break;
                                                }
                                                fr_session->pos += len;
                                                if (fr_session->pos == fr_session->uh.pktsize) {
							if (uwsgi_hooked_parse(fr_session->buffer, fr_session->uh.pktsize, fr_get_hostname, (void *) fr_session)) {
								close(fr_session->fd);
								fr_table[fr_session->fd] = NULL;
								free(fr_session);
                                                        	break;
							}

							if (fr_session->hostname_len == 0) {
								close(fr_session->fd);
								fr_table[fr_session->fd] = NULL;
								free(fr_session);
                                                        	break;
							}

							//uwsgi_log("requested domain %.*s\n", fr_session->hostname_len, fr_session->hostname);
							if (ufr.use_cache) {
								fr_session->instance_address = uwsgi_cache_get(fr_session->hostname, fr_session->hostname_len, &fr_session->instance_address_len);
							}

							// no address found
							if (!fr_session->instance_address_len) {
								close(fr_session->fd);
								fr_table[fr_session->fd] = NULL;
								free(fr_session);
                                                        	break;
							}


							fr_session->pass_fd = is_unix(fr_session->instance_address, fr_session->instance_address_len);

							fr_session->instance_fd = uwsgi_connectn(fr_session->instance_address, fr_session->instance_address_len, 0, 1);
							if (fr_session->instance_fd < 0) {
								close(fr_session->fd);
								fr_table[fr_session->fd] = NULL;
								free(fr_session);
                                                        	break;
							}


							fr_session->status = FASTROUTER_STATUS_CONNECTING;
							fr_table[fr_session->instance_fd] = fr_session;
							event_queue_add_fd_write(fr_queue, fr_session->instance_fd);
                                                }
                                                break;



					case FASTROUTER_STATUS_CONNECTING:
						
						if (interesting_fd == fr_session->instance_fd) {

							if (getsockopt(fr_session->instance_fd, SOL_SOCKET, SO_ERROR, (void *) (&soopt), &solen) < 0) {
                                                		uwsgi_error("getsockopt()");
								close(fr_session->fd);
								close(fr_session->instance_fd);
								fr_table[fr_session->fd] = NULL;
								fr_table[fr_session->instance_fd] = NULL;
								free(fr_session);
                                                        	break;
                                        		}

							if (soopt) {
								uwsgi_log("unable to connect() to uwsgi instance: %s\n", strerror(soopt));
								close(fr_session->fd);
								close(fr_session->instance_fd);
								fr_table[fr_session->fd] = NULL;
								fr_table[fr_session->instance_fd] = NULL;
								free(fr_session);
                                                        	break;
							}

							iov[0].iov_base = &fr_session->uh;
							iov[0].iov_len = 4;
							iov[1].iov_base = fr_session->buffer;
							iov[1].iov_len = fr_session->uh.pktsize;

							// fd passing: PERFORMANCE EXTREME BOOST !!!
							if (fr_session->pass_fd) {
								msg.msg_name    = NULL;
                						msg.msg_namelen = 0;
                						msg.msg_iov     = iov;
                						msg.msg_iovlen  = 2;
                						msg.msg_flags   = 0;
                						msg.msg_control    = &msg_control;
                						msg.msg_controllen = sizeof (msg_control);

                						cmsg = CMSG_FIRSTHDR (&msg);
                						cmsg->cmsg_len   = CMSG_LEN (sizeof (int));
                						cmsg->cmsg_level = SOL_SOCKET;
                						cmsg->cmsg_type  = SCM_RIGHTS;

                						*((int *) CMSG_DATA (cmsg)) = fr_session->fd;

                						if (sendmsg(fr_session->instance_fd, &msg, 0) < 0) {
									uwsgi_error("sendmsg()");
								}

								close(fr_session->fd);
                                                                close(fr_session->instance_fd);
                                                                fr_table[fr_session->fd] = NULL;
                                                                fr_table[fr_session->instance_fd] = NULL;
                                                                free(fr_session);
                                                                break;
							}

							if (writev(fr_session->instance_fd, iov, 2) < 0) {
								uwsgi_error("writev()");
								close(fr_session->fd);
								close(fr_session->instance_fd);
								fr_table[fr_session->fd] = NULL;
								fr_table[fr_session->instance_fd] = NULL;
								free(fr_session);
                                                        	break;
							}

							event_queue_del_fd(fr_queue, fr_session->instance_fd);
							event_queue_add_fd_read(fr_queue, fr_session->instance_fd);
							fr_session->status = FASTROUTER_STATUS_RESPONSE;
						}

						break;

					case FASTROUTER_STATUS_RESPONSE:
						
						// data from instance
						if (interesting_fd == fr_session->instance_fd) {
							len = recv(fr_session->instance_fd, fr_session->buffer, 0xffff, 0);
							if (len <= 0) {
								if (len < 0) uwsgi_error("recv()");
								close(fr_session->fd);
								close(fr_session->instance_fd);
								fr_table[fr_session->fd] = NULL;
								fr_table[fr_session->instance_fd] = NULL;
								free(fr_session);
                                                        	break;
							}

							len = send(fr_session->fd, fr_session->buffer, len, 0);
							
							if (len <= 0) {
								if (len < 0) uwsgi_error("send()");
								close(fr_session->fd);
								close(fr_session->instance_fd);
								fr_table[fr_session->fd] = NULL;
								fr_table[fr_session->instance_fd] = NULL;
								free(fr_session);
                                                        	break;
							}
						}
						// body from client
						else if (interesting_fd == fr_session->fd) {

							//uwsgi_log("receiving body...\n");
							len = recv(fr_session->fd, fr_session->buffer, 0xffff, 0);
							if (len <= 0) {
								if (len < 0) uwsgi_error("recv()");
								close(fr_session->fd);
								close(fr_session->instance_fd);
								fr_table[fr_session->fd] = NULL;
								fr_table[fr_session->instance_fd] = NULL;
								free(fr_session);
                                                        	break;
							}


							len = send(fr_session->instance_fd, fr_session->buffer, len, 0);
							
							if (len <= 0) {
								if (len < 0) uwsgi_error("send()");
								close(fr_session->fd);
								close(fr_session->instance_fd);
								fr_table[fr_session->fd] = NULL;
								fr_table[fr_session->instance_fd] = NULL;
								free(fr_session);
                                                        	break;
							}
						}

						break;



					// fallback to destroy !!!
					default:
						uwsgi_log("default action\n");
						close(fr_session->fd);
						fr_table[fr_session->fd] = NULL;
						if (fr_session->instance_fd != -1) {
							close(fr_session->instance_fd);
							fr_table[fr_session->instance_fd] = NULL;
						}
						free(fr_session);
						break;
					
				}
			}

		}
	}
}

int fastrouter_init() {

	if (ufr.socket_name) {

		if (ufr.use_cache && !uwsgi.cache_max_items) {
			uwsgi_log("you need to create a uwsgi cache to use the fastrouter (add --cache <n>)\n");
			exit(1);
		}

		if (register_gateway("fastrouter", fastrouter_loop) == NULL) {
			uwsgi_log("unable to register the fastrouter gateway\n");
			exit(1);
		}
	}

	return 0;
}
	
int fastrouter_opt(int i, char *optarg) {

	switch(i) {
		case LONG_ARGS_FASTROUTER:
			ufr.socket_name = optarg;
			return 1;
	}
	return 0;
}


struct uwsgi_plugin fastrouter_plugin = {

        .options = fastrouter_options,
        .manage_opt = fastrouter_opt,
        .init = fastrouter_init,
};

