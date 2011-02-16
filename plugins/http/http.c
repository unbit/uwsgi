/*

   uWSGI http

   requires:

   - async
   - caching
   - pcre (optional)

*/

#include "../../uwsgi.h"

#define MAX_HTTP_VEC 128
#define MAX_HTTP_EXTRA_VARS 64

#define LONG_ARGS_HTTP_EVENTS		300001
#define LONG_ARGS_HTTP_USE_PATTERN	300002
#define LONG_ARGS_HTTP_USE_BASE		300003
#define LONG_ARGS_HTTP_USE_TO		300004

#define HTTP_STATUS_FREE 0
#define HTTP_STATUS_CONNECTING 1
#define HTTP_STATUS_RECV 2
#define HTTP_STATUS_RESPONSE 4

struct uwsgi_http {
	char *socket_name;
	int use_cache;
	int nevents;

	char *pattern;
	int pattern_len;

	char *base;
	int base_len;

	char *to;
	int to_len;

	char *http_vars[MAX_HTTP_EXTRA_VARS];
	int http_vars_cnt;

	uint8_t modifier1;
	int load;
} uhttp;

struct option http_options[] = {
	{"http", required_argument, 0, LONG_ARGS_HTTP},
        {"http-var", required_argument, 0, LONG_ARGS_HTTP_VAR},
        {"http-to", required_argument, 0, LONG_ARGS_HTTP_USE_TO},
        {"http-modifier1", required_argument, 0, LONG_ARGS_HTTP_MODIFIER1},
	{"http-use-cache", no_argument, &uhttp.use_cache, 1},
	{"http-use-pattern", required_argument, 0, LONG_ARGS_HTTP_USE_PATTERN},
	{"http-use-base", required_argument, 0, LONG_ARGS_HTTP_USE_BASE},
	{"http-events", required_argument, 0, LONG_ARGS_HTTP_EVENTS},
	{0, 0, 0, 0},	
};

extern struct uwsgi_server uwsgi;

struct http_session {

	int fd;
	int instance_fd;
	int status;
	struct uwsgi_header uh;
	uint8_t h_pos;
	uint16_t pos;
	uint16_t parse_pos;
	char *ptr;

	int rnrn;

	char *hostname;
	uint16_t hostname_len;

	char *instance_address;
	uint64_t instance_address_len;

	int pass_fd;

	int remains;

	struct iovec iov[MAX_HTTP_VEC];
	int iov_len;

	char uss[MAX_HTTP_VEC*2];

	char buffer[UMAX16];
};

struct http_session *alloc_uhttp_session() {
	
	return uwsgi_malloc(sizeof(struct http_session));
}

uint16_t http_add_uwsgi_header(struct http_session *h_session, struct iovec *iov, char *strsize1, char *strsize2, char *hh, uint16_t hhlen, int *c) {

	int i;
	int status = 0;
	char *val = hh;
	uint16_t keylen = 0, vallen = 0;
	int prefix = 0;

	if (*c >= MAX_HTTP_VEC) return 0;

	for(i=0;i<hhlen;i++) {
		if (!status) {
			hh[i] = toupper(hh[i]);
			if (hh[i] == '-') hh[i] = '_';
			if (hh[i] == ':') {
				status = 1;
				keylen = i;
			}
		}
		else if (status == 1 && hh[i] != ' ') {
			status = 2;
			val += i;
			vallen++;
		}
		else if (status == 2) {
			vallen++;
		}
	}

	if (!keylen) return 0;

	if ((*c) + 4  >= MAX_HTTP_VEC) return 0;

	if (uwsgi_strncmp("CONTENT_TYPE", 12, hh, keylen) && uwsgi_strncmp("CONTENT_LENGTH", 14, hh, keylen)) {
		keylen += 5;	
		prefix = 1;
		if ((*c) + 5  >= MAX_HTTP_VEC) return 0;
	}
	else if (uwsgi_strncmp("HOST", 4, hh, keylen)) {
		h_session->hostname = val;
		h_session->hostname_len = vallen;	
	}

        strsize1[0] = (uint8_t) (keylen & 0xff);
        strsize1[1] = (uint8_t) ((keylen >> 8) & 0xff);

        iov[*c].iov_base = strsize1 ;
        iov[*c].iov_len = 2 ;
        *c+=1;

	if (prefix) {
        	iov[*c].iov_base = "HTTP_" ;
        	iov[*c].iov_len = 5 ;
        	*c+=1;
	}

        iov[*c].iov_base = hh ;
        iov[*c].iov_len = keylen - (prefix*5) ;
        *c+=1;

        strsize2[0] = (uint8_t) (vallen & 0xff);
        strsize2[1] = (uint8_t) ((vallen >> 8) & 0xff);

        iov[*c].iov_base = strsize2 ;
        iov[*c].iov_len = 2 ;
        *c+=1;

        iov[*c].iov_base = val ;
        iov[*c].iov_len = vallen ;
        *c+=1;

        return 2+keylen+2+vallen;
}


uint16_t http_add_uwsgi_var(struct iovec *iov, char *strsize1, char *strsize2, char *key, uint16_t keylen, char *val, uint16_t vallen, int *c) {

	if ((*c) + 4  >= MAX_HTTP_VEC) return 0;

	strsize1[0] = (uint8_t) (keylen & 0xff);
        strsize1[1] = (uint8_t) ((keylen >> 8) & 0xff);

	iov[*c].iov_base = strsize1 ;
        iov[*c].iov_len = 2 ;
        *c+=1;

	iov[*c].iov_base = key ;
        iov[*c].iov_len = keylen ;
        *c+=1;

	strsize2[0] = (uint8_t) (vallen & 0xff);
        strsize2[1] = (uint8_t) ((vallen >> 8) & 0xff);

	iov[*c].iov_base = strsize2 ;
        iov[*c].iov_len = 2 ;
        *c+=1;

	iov[*c].iov_base = val ;
        iov[*c].iov_len = vallen ;
	*c+=1;
	
	return 2+keylen+2+vallen;
}

int http_parse(struct http_session *h_session) {

	char *ptr = h_session->buffer;
	char *watermark = h_session->ptr;
	char *base = ptr;
	// leave a slot for uwsgi header
	int c = 1;
	char *query_string = NULL;

	// REQUEST_METHOD 
	while(ptr < watermark) {
		if (*ptr == ' ') {
			h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss+c, h_session->uss+c+2, "REQUEST_METHOD", 14, base, ptr-base, &c);
			ptr++;
			break;
		}
		ptr++;
	}

	// REQUEST_URI / PATH_INFO / QUERY_STRING
	base = ptr;
	while(ptr < watermark) {
                if (*ptr == '?' && !query_string) {
			h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss+c, h_session->uss+c+2, "PATH_INFO", 9, base, ptr-base, &c);
			query_string = ptr+1;
		}
                else if (*ptr == ' ') {
			h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss+c, h_session->uss+c+2, "REQUEST_URI", 11, base, ptr-base, &c);
			if (!query_string) {
				h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss+c, h_session->uss+c+2, "PATH_INFO", 9, base, ptr-base, &c);
			}	
			else {
				h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss+c, h_session->uss+c+2, "QUERY_STRING", 12, query_string, ptr-query_string, &c);
			}
			ptr++;
                        break;
                }
                ptr++;
        }

	// SERVER_PROTOCOL
	base = ptr;
	while(ptr < watermark) {
		if (*ptr == '\r') {
			if (ptr + 1 >= watermark) return 0;
			if (*(ptr+1) != '\n') return 0;
			h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss+c, h_session->uss+c+2, "SERVER_PROTOCOL", 15, base, ptr-base, &c);
			ptr+=2;
			break;
		}
		ptr++;
	}

	// SCRIPT_NAME
	h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss+c, h_session->uss+c+2, "SCRIPT_NAME", 11, "", 0, &c);

	// SERVER_NAME
	h_session->uh.pktsize += http_add_uwsgi_var(h_session->iov, h_session->uss+c, h_session->uss+c+2, "SERVER_NAME", 11, uwsgi.hostname, uwsgi.hostname_len, &c);
	h_session->hostname = uwsgi.hostname;
	h_session->hostname_len = uwsgi.hostname_len;


	//HEADERS

	base = ptr;

	while(ptr < watermark) {
		if (*ptr == '\r') {
			if (ptr + 1 >= watermark) return 0;
			if (*(ptr+1) != '\n') return 0;
			// multiline header ?
			if (ptr+2 < watermark) {
				if (*(ptr+2) == ' ' || *(ptr+2) == '\t') {
					ptr+=2;
					continue;
				}
			}
			h_session->uh.pktsize += http_add_uwsgi_header(h_session, h_session->iov, h_session->uss+c, h_session->uss+c+2, base, ptr-base, &c);
			ptr++;
			base = ptr+1;
		}
		ptr++;
	}

	uwsgi_log("vec size: %d pkt size: %d load %d\n", c, h_session->uh.pktsize, uhttp.load);

	return c;
	
}

void http_loop() {

	int uhttp_queue;
	int uhttp_server;
	int nevents;
	int interesting_fd;
	int new_connection;
	ssize_t len;
	int i,j;

	char *magic_table[0xff];

	char bbuf[UMAX16];

	void *events;
	struct msghdr msg;
	union {
                struct cmsghdr cmsg;
                char control [CMSG_SPACE (sizeof (int))];
        } msg_control;
        struct cmsghdr *cmsg;

	struct sockaddr_un uhttp_addr;
        socklen_t uhttp_addr_len = sizeof(struct sockaddr_un);
	
	struct http_session *uhttp_session;

	struct http_session *uhttp_table[2048];

	int soopt;
        socklen_t solen = sizeof(int);

	for(i=0;i<2048;i++) {
		uhttp_table[i] = NULL;
	}

	uhttp_server = bind_to_tcp(uhttp.socket_name, uwsgi.listen_queue, strchr(uhttp.socket_name,':'));

	uhttp_queue = event_queue_init();

	events = event_queue_alloc(uhttp.nevents);

	event_queue_add_fd_read(uhttp_queue, uhttp_server);

	if (uhttp.pattern) {
		init_magic_table(magic_table);
	}

	for (;;) {

		nevents = event_queue_wait_multi(uhttp_queue, -1, events, uhttp.nevents);

		for (i=0;i<nevents;i++) {

			interesting_fd = event_queue_interesting_fd(events, i);


			if (interesting_fd == uhttp_server) {
				new_connection = accept(uhttp_server, (struct sockaddr *) &uhttp_addr, &uhttp_addr_len);
				if (new_connection < 0) {
					continue;
				}

				uhttp_table[new_connection] = alloc_uhttp_session();
				uhttp_table[new_connection]->fd = new_connection;
				uhttp_table[new_connection]->instance_fd = -1; 
				uhttp_table[new_connection]->status = HTTP_STATUS_RECV;
				uhttp_table[new_connection]->h_pos = 0;
				uhttp_table[new_connection]->pos = 0;
				uhttp_table[new_connection]->rnrn = 0;
				uhttp_table[new_connection]->parse_pos = 0;
				uhttp_table[new_connection]->pass_fd = 0;
				uhttp_table[new_connection]->ptr = uhttp_table[new_connection]->buffer;
				uhttp_table[new_connection]->instance_address_len = 0;
				uhttp_table[new_connection]->uh.modifier1 = uhttp.modifier1;
				uhttp_table[new_connection]->uh.pktsize = 0;
				uhttp_table[new_connection]->uh.modifier2 = 0;

				uhttp.load++;

				event_queue_add_fd_read(uhttp_queue, new_connection);
				
			}	
			else {
				uhttp_session = uhttp_table[interesting_fd];

				// something is going wrong...
				if (uhttp_session == NULL) continue;

				if (event_queue_interesting_fd_has_error(events, i)) {
					close(uhttp_session->fd);
                                        uhttp_table[uhttp_session->fd] = NULL;
                                        if (uhttp_session->instance_fd != -1) {
                                        	close(uhttp_session->instance_fd);
                                                uhttp_table[uhttp_session->instance_fd] = NULL;
                                        }
					uhttp.load--;
                                        free(uhttp_session);
					continue;
				}

				switch(uhttp_session->status) {

					case HTTP_STATUS_RECV:
						len = recv(uhttp_session->fd, uhttp_session->buffer + uhttp_session->h_pos, UMAX16-uhttp_session->h_pos, 0);
						if (len <= 0) {
							uwsgi_error("recv()");
							close(uhttp_session->fd);
							uhttp_table[uhttp_session->fd] = NULL;
							uhttp.load--;
							free(uhttp_session);
							break;
						}

						uhttp_session->h_pos += len;

						for(j=0;j<len;j++) {
							//uwsgi_log("%d %d %d\n", j, *uhttp_session->ptr, uhttp_session->rnrn);
							if (*uhttp_session->ptr == '\r' && (uhttp_session->rnrn == 0 || uhttp_session->rnrn == 2)) {
								uhttp_session->rnrn++;
							}
							else if (*uhttp_session->ptr == '\r') {
								uhttp_session->rnrn = 1;
							}
							else if (*uhttp_session->ptr == '\n' && uhttp_session->rnrn == 1) {
								uhttp_session->rnrn = 2;
							}
							else if (*uhttp_session->ptr == '\n' && uhttp_session->rnrn == 3) {
								uhttp_session->ptr++;
								uhttp_session->remains = len-(j+1);
								uhttp_session->iov_len = http_parse(uhttp_session);

								if (uhttp_session->iov_len == 0) {
                                                                	close(uhttp_session->fd);
                                                                	uhttp_table[uhttp_session->fd] = NULL;
									uhttp.load--;
                                                                	free(uhttp_session);
                                                                	break;
								}


								if (uhttp.base) {
									uhttp_session->instance_address = uwsgi_cache_get(uhttp_session->hostname, uhttp_session->hostname_len, &uhttp_session->instance_address_len);
								}
								else if (uhttp.pattern) {
									magic_table['s'] = uwsgi_concat2n(uhttp_session->hostname, uhttp_session->hostname_len, "", 0);       
									int tmp_addr_len = 0;
	                                                                uhttp_session->instance_address = magic_sub(uhttp.pattern, uhttp.pattern_len, &tmp_addr_len, magic_table);
									uhttp_session->instance_address_len = tmp_addr_len;
	                                                                free(magic_table['s']);	
								}
								else if (uhttp.to) {
									uhttp_session->instance_address = uhttp.to;
									uhttp_session->instance_address_len = uhttp.to_len;
								}
								else if (uwsgi.sockets_cnt > 0) {
									uhttp_session->instance_address = uwsgi.sockets[0].name;
									uhttp_session->instance_address_len = strlen(uwsgi.sockets[0].name);
								}

								uhttp_session->pass_fd = is_unix(uhttp_session->instance_address, uhttp_session->instance_address_len);

								uhttp_session->instance_fd = uwsgi_connectn(uhttp_session->instance_address, uhttp_session->instance_address_len, 0, 1);

								if (uhttp.pattern) {
									free(uhttp_session->instance_address);
								}

								if (uhttp_session->instance_fd < 0) {
                                                                	close(uhttp_session->fd);
                                                                	uhttp_table[uhttp_session->fd] = NULL;
									uhttp.load--;
                                                                	free(uhttp_session);
                                                                	break;
                                                        	}


                                                        	uhttp_session->status = HTTP_STATUS_CONNECTING;
                                                        	uhttp_table[uhttp_session->instance_fd] = uhttp_session;
                                                        	event_queue_add_fd_write(uhttp_queue, uhttp_session->instance_fd);
								break;
							}
							else {
								uhttp_session->rnrn = 0;
							}
							uhttp_session->ptr++;
						}


						break;


					case HTTP_STATUS_CONNECTING:
						
						if (interesting_fd == uhttp_session->instance_fd) {

							if (getsockopt(uhttp_session->instance_fd, SOL_SOCKET, SO_ERROR, (void *) (&soopt), &solen) < 0) {
                                                		uwsgi_error("getsockopt()");
								close(uhttp_session->fd);
								close(uhttp_session->instance_fd);
								uhttp_table[uhttp_session->fd] = NULL;
								uhttp_table[uhttp_session->instance_fd] = NULL;
								uhttp.load--;
								free(uhttp_session);
                                                        	break;
                                        		}

							if (soopt) {
								uwsgi_log("unable to connect() to uwsgi instance: %s\n", strerror(soopt));
								close(uhttp_session->fd);
								close(uhttp_session->instance_fd);
								uhttp_table[uhttp_session->fd] = NULL;
								uhttp_table[uhttp_session->instance_fd] = NULL;
								uhttp.load--;
								free(uhttp_session);
                                                        	break;
							}

							uhttp_session->iov[0].iov_base = &uhttp_session->uh;
							uhttp_session->iov[0].iov_len = 4;

							if (uhttp_session->remains > 0) {
								uhttp_session->iov[uhttp_session->iov_len].iov_base = uhttp_session->ptr;
								uhttp_session->iov[uhttp_session->iov_len].iov_len = uhttp_session->remains;
								uhttp_session->iov_len++;
							}

							// fd passing: PERFORMANCE EXTREME BOOST !!!
							if (uhttp_session->pass_fd) {
								msg.msg_name    = NULL;
                						msg.msg_namelen = 0;
                						msg.msg_iov     = uhttp_session->iov;
                						msg.msg_iovlen  = uhttp_session->iov_len;
                						msg.msg_flags   = 0;
                						msg.msg_control    = &msg_control;
                						msg.msg_controllen = sizeof (msg_control);

                						cmsg = CMSG_FIRSTHDR (&msg);
                						cmsg->cmsg_len   = CMSG_LEN (sizeof (int));
                						cmsg->cmsg_level = SOL_SOCKET;
                						cmsg->cmsg_type  = SCM_RIGHTS;

								memcpy(CMSG_DATA(cmsg), &uhttp_session->fd, sizeof(int));

                						if (sendmsg(uhttp_session->instance_fd, &msg, 0) < 0) {
									uwsgi_error("sendmsg()");
								}

								close(uhttp_session->fd);
                                                                close(uhttp_session->instance_fd);
                                                                uhttp_table[uhttp_session->fd] = NULL;
                                                                uhttp_table[uhttp_session->instance_fd] = NULL;
								uhttp.load--;
                                                                free(uhttp_session);
                                                                break;
							}

							if (writev(uhttp_session->instance_fd, uhttp_session->iov, uhttp_session->iov_len) <= 0) {
								uwsgi_error("writev()");
								close(uhttp_session->fd);
								close(uhttp_session->instance_fd);
								uhttp_table[uhttp_session->fd] = NULL;
								uhttp_table[uhttp_session->instance_fd] = NULL;
								uhttp.load--;
								free(uhttp_session);
                                                        	break;
							}

							event_queue_fd_write_to_read(uhttp_queue, uhttp_session->instance_fd);
							uhttp_session->status = HTTP_STATUS_RESPONSE;
						}

						break;

					case HTTP_STATUS_RESPONSE:
						
						// data from instance
						if (interesting_fd == uhttp_session->instance_fd) {
							len = recv(uhttp_session->instance_fd, bbuf, UMAX16, 0);
							if (len <= 0) {
								if (len < 0) uwsgi_error("recv()");
								close(uhttp_session->fd);
								close(uhttp_session->instance_fd);
								uhttp_table[uhttp_session->fd] = NULL;
								uhttp_table[uhttp_session->instance_fd] = NULL;
								uhttp.load--;
								free(uhttp_session);
                                                        	break;
							}

							len = send(uhttp_session->fd, bbuf, len, 0);
							
							if (len <= 0) {
								if (len < 0) uwsgi_error("send()");
								close(uhttp_session->fd);
								close(uhttp_session->instance_fd);
								uhttp_table[uhttp_session->fd] = NULL;
								uhttp_table[uhttp_session->instance_fd] = NULL;
								uhttp.load--;
								free(uhttp_session);
                                                        	break;
							}
						}
						// body from client
						else if (interesting_fd == uhttp_session->fd) {

							//uwsgi_log("receiving body...\n");
							len = recv(uhttp_session->fd, bbuf, UMAX16, 0);
							if (len <= 0) {
								if (len < 0) uwsgi_error("recv()");
								close(uhttp_session->fd);
								close(uhttp_session->instance_fd);
								uhttp_table[uhttp_session->fd] = NULL;
								uhttp_table[uhttp_session->instance_fd] = NULL;
								uhttp.load--;
								free(uhttp_session);
                                                        	break;
							}


							len = send(uhttp_session->instance_fd, bbuf, len, 0);
							
							if (len <= 0) {
								if (len < 0) uwsgi_error("send()");
								close(uhttp_session->fd);
								close(uhttp_session->instance_fd);
								uhttp_table[uhttp_session->fd] = NULL;
								uhttp_table[uhttp_session->instance_fd] = NULL;
								uhttp.load--;
								free(uhttp_session);
                                                        	break;
							}
						}

						break;



					// fallback to destroy !!!
					default:
						uwsgi_log("default action\n");
						close(uhttp_session->fd);
						uhttp_table[uhttp_session->fd] = NULL;
						if (uhttp_session->instance_fd != -1) {
							close(uhttp_session->instance_fd);
							uhttp_table[uhttp_session->instance_fd] = NULL;
						}
						uhttp.load--;
						free(uhttp_session);
						break;
					
				}
			}

		}
	}
}

int http_init() {

	if (uhttp.socket_name) {

		if (uhttp.use_cache && !uwsgi.cache_max_items) {
			uwsgi_log("you need to create a uwsgi cache to use the http (add --cache <n>)\n");
			exit(1);
		}

		if (!uhttp.nevents) uhttp.nevents = 64;

		if (!uhttp.base && !uhttp.use_cache && !uhttp.to && !uwsgi.sockets_cnt) {
			uwsgi.sockets[0].name = uwsgi_malloc(64);
			uwsgi.sockets_cnt++;
			snprintf(uwsgi.sockets[0].name, 64, "%d_%d.sock", (int) time(NULL), (int) getpid());
		}

		if (register_gateway("http", http_loop) == NULL) {
			uwsgi_log("unable to register the http gateway\n");
			exit(1);
		}
	}

	return 0;
}
	
int http_opt(int i, char *optarg) {

	switch(i) {
		case LONG_ARGS_HTTP:
			uhttp.socket_name = optarg;
			return 1;
		case LONG_ARGS_HTTP_EVENTS:
			uhttp.nevents = atoi(optarg);
			return 1;
		case LONG_ARGS_HTTP_USE_PATTERN:
			uhttp.pattern = optarg;
			// optimization
			uhttp.pattern_len = strlen(uhttp.pattern);
			return 1;
		case LONG_ARGS_HTTP_USE_BASE:
			uhttp.base = optarg;
			// optimization
			uhttp.base_len = strlen(uhttp.base);
			return 1;
		case LONG_ARGS_HTTP_USE_TO:
			uhttp.to = optarg;
			// optimization
			uhttp.to_len = strlen(uhttp.to);
			return 1;
		case LONG_ARGS_HTTP_VAR:
                        if (uhttp.http_vars_cnt < MAX_HTTP_EXTRA_VARS) {
                                uhttp.http_vars[uhttp.http_vars_cnt] = optarg;
                                uhttp.http_vars_cnt++;
                        } else {
                                uwsgi_log("you can specify at most 64 --http-var options\n");
                        }
                        return 1;
                case LONG_ARGS_HTTP_MODIFIER1:
                        uhttp.modifier1 = (uint8_t) atoi(optarg);
                        return 1;
	}
	return 0;
}



struct uwsgi_plugin http_plugin = {

        .options = http_options,
        .manage_opt = http_opt,
        .init = http_init,
};

