#include "common.h"

extern struct uwsgi_tuntap utt;
extern struct uwsgi_server uwsgi;

int uwsgi_tuntap_peer_rules_check(struct uwsgi_tuntap_router *uttr, struct uwsgi_tuntap_peer *uttp, char *pkt, size_t len, int direction) {
	if (uttp->rules_cnt == 0) return 0;

	// sanity check
        if (len < 20) return -1;
        uint32_t *src_ip = (uint32_t *) &pkt[12];
        uint32_t *dst_ip = (uint32_t *) &pkt[16];

        uint32_t src = ntohl(*src_ip);
        uint32_t dst = ntohl(*dst_ip);

#ifdef UWSGI_DEBUG
	uwsgi_log("%d %X %X\n",direction, src, dst);
#endif

	int i;
	for(i=0;i<uttp->rules_cnt;i++) {
		struct uwsgi_tuntap_peer_rule *rule = &uttp->rules[i];

#ifdef UWSGI_DEBUG
		uwsgi_log("cnt = %i/%d direction = %d action = %d %X %X\n", i, uttp->rules_cnt, rule->direction, rule->action, rule->src_mask, rule->dst_mask);
#endif


		if (rule->direction != direction) continue;

		if (rule->src) {
                        uint32_t src_masked = src & rule->src_mask;
                        if (src_masked != rule->src) continue;
                }

                if (rule->dst) {
                        uint32_t dst_masked = dst & rule->dst_mask;
                        if (dst_masked != rule->dst) continue;
                }


		if (rule->action == 0) return 0;
		if (rule->action == 1) return 1;
		if (rule->action == 2) {
			// if IN do not honour gateway/route
			if (!direction) return -1;
			if (uttr->gateway_fd > -1) {
				struct sockaddr_in sin;
				memset(&sin, 0, sizeof(struct sockaddr_in));
				sin.sin_family = AF_INET;
				sin.sin_port = rule->target_port;
				sin.sin_addr.s_addr = rule->target;
				if (sendto(uttr->gateway_fd, pkt, len, 0, (struct sockaddr *) &sin, sizeof(struct sockaddr_in)) < 0) {
					if (uwsgi_is_again()) {
						// suspend and retry
						struct pollfd pfd;
						memset(&pfd, 0, sizeof(struct pollfd));
						pfd.fd = uttr->gateway_fd;
						pfd.events = POLLOUT;
						int ret = poll(&pfd, 1, uwsgi.socket_timeout * 1000);
						if (ret > 0) {
							if (sendto(uttr->gateway_fd, pkt, len, 0, (struct sockaddr *) &sin, sizeof(struct sockaddr_in)) < 0) {
								uwsgi_tuntap_error(uttp,"uwsgi_tuntap_route_check()/sendto()");
							}
						}
						else {
							uwsgi_tuntap_error(uttp,"uwsgi_tuntap_route_check()/poll()");
						}
					}
					else {
						uwsgi_tuntap_error(uttp,"uwsgi_tuntap_route_check()/sendto()");
					}
				}
			}
			return 2;	
		}
	}
	return 0;
}

int uwsgi_tuntap_firewall_check(struct uwsgi_tuntap_firewall_rule *direction, char *pkt, uint16_t len) {
        // sanity check
        if (len < 20) return -1;
        uint32_t *src_ip = (uint32_t *) &pkt[12];
        uint32_t *dst_ip = (uint32_t *) &pkt[16];

        uint32_t src = ntohl(*src_ip);
        uint32_t dst = ntohl(*dst_ip);

        struct uwsgi_tuntap_firewall_rule *utfr = direction;
        while(utfr) {
                if (utfr->src) {
                        uint32_t src_masked = src & utfr->src_mask;
                        if (src_masked != utfr->src) goto next;
                }

                if (utfr->dst) {
                        uint32_t dst_masked = dst & utfr->dst_mask;
                        if (dst_masked != utfr->dst) goto next;
                }

                return utfr->action;
next:
                utfr = utfr->next;
        }

        return 0;
}

int uwsgi_tuntap_route_check(int fd, char *pkt, uint16_t len) {
        // sanity check
        if (len < 20) return -1;
        uint32_t *src_ip = (uint32_t *) &pkt[12];
        uint32_t *dst_ip = (uint32_t *) &pkt[16];

        uint32_t src = ntohl(*src_ip);
        uint32_t dst = ntohl(*dst_ip);

        struct uwsgi_tuntap_firewall_rule *utrr = utt.routes;
        while(utrr) {
                if (utrr->src) {
                        uint32_t src_masked = src & utrr->src_mask;
                        if (src_masked != utrr->src) goto next;
                }

                if (utrr->dst) {
                        uint32_t dst_masked = dst & utrr->dst_mask;
                        if (dst_masked != utrr->dst) goto next;
                }

		if (sendto(fd, pkt, len, 0, (struct sockaddr *) &utrr->dest_addr, utrr->addrlen) < 0) {
			uwsgi_error("uwsgi_tuntap_route_check()/sendto()");
		}
                return 1;
next:
                utrr = utrr->next;
        }

        return 0;
}


static struct uwsgi_tuntap_firewall_rule *uwsgi_tuntap_firewall_add_rule(struct uwsgi_tuntap_firewall_rule **direction, uint8_t action, uint32_t src, uint32_t src_mask, uint32_t dst, uint32_t dst_mask) {
#ifdef UWSGI_DEBUG
	uwsgi_log("[tuntap-router] firewall action %d %x %x %x %x\n",action, src,src_mask,dst,dst_mask);
#endif

	struct uwsgi_tuntap_firewall_rule *old_uttr = NULL, *uttr = *direction;
	while(uttr) {
		old_uttr = uttr;
		uttr = uttr->next;
	}

	uttr = uwsgi_calloc(sizeof(struct uwsgi_tuntap_firewall_rule));
	uttr->action = action;
	uttr->src = src & src_mask;
	uttr->src_mask = src_mask;
	uttr->dst = dst & dst_mask;
	uttr->dst_mask = dst_mask;

	if (old_uttr) {
		old_uttr->next = uttr;
	}
	else {
		*direction = uttr;
	}

	return uttr;
}

void uwsgi_tuntap_opt_firewall(char *opt, char *value, void *direction) {
	
	char *space = strchr(value, ' ');
	if (!space) {
		if (!strcmp("deny", value)) {
			uwsgi_tuntap_firewall_add_rule((struct uwsgi_tuntap_firewall_rule **) direction, 1, 0, 0, 0, 0);
			return;
		}
		uwsgi_tuntap_firewall_add_rule((struct uwsgi_tuntap_firewall_rule **) direction, 0, 0, 0, 0, 0);
		return;
	}

	*space = 0;

	uint8_t action = 0;
	if (!strcmp(value, "deny")) action = 1;

	char *space2 = strchr(space + 1, ' ');
	if (!space2) {
		uwsgi_log("invalid tuntap firewall rule syntax. must be <action> <src/mask> <dst/mask>");
                return;
	}

	*space2 = 0;

	uint32_t src = 0;
	uint32_t src_mask = 32;
	uint32_t dst = 0;
	uint32_t dst_mask = 32;

	char *slash = strchr(space + 1 , '/');
	if (slash) {
		src_mask = atoi(slash+1);
		*slash = 0;
	}

	if (inet_pton(AF_INET, space + 1, &src) != 1) {
		uwsgi_error("uwsgi_tuntap_opt_firewall()/inet_pton()");
		exit(1);
	}

	if (slash) *slash = '/';
	*space = ' ';

	slash = strchr(space2 + 1 , '/');
        if (slash) {
                dst_mask = atoi(slash+1);
                *slash = 0;
        }

        if (inet_pton(AF_INET, space2 + 1, &dst) != 1) {
                uwsgi_error("uwsgi_tuntap_opt_firewall()/inet_pton()");
                exit(1);
        }

        if (slash) *slash = '/';
        *space2 = ' ';

	uwsgi_tuntap_firewall_add_rule((struct uwsgi_tuntap_firewall_rule **) direction, action, ntohl(src), (0xffffffff << (32-src_mask)), ntohl(dst), (0xffffffff << (32-dst_mask)));
}

void uwsgi_tuntap_opt_route(char *opt, char *value, void *table) {

        char *space = strchr(value, ' ');
        if (!space) {
		uwsgi_log("invalid tuntap routing rule syntax, must be: <src/mask> <dst/mask> <gateway>\n");
		exit(1);
	}
        *space = 0;

        char *space2 = strchr(space + 1, ' ');
        if (!space2) {
		uwsgi_log("invalid tuntap routing rule syntax, must be: <src/mask> <dst/mask> <gateway>\n");
		exit(1);
        }
        *space2 = 0;

        uint32_t src = 0;
        uint32_t src_mask = 32;
        uint32_t dst = 0;
        uint32_t dst_mask = 32;

        char *slash = strchr(value , '/');
        if (slash) {
                src_mask = atoi(slash+1);
                *slash = 0;
        }
        if (inet_pton(AF_INET, value, &src) != 1) {
                uwsgi_error("uwsgi_tuntap_opt_route()/inet_pton()");
                exit(1);
        }
        if (slash) *slash = '/';

	slash = strchr(space+1 , '/');
        if (slash) {
                dst_mask = atoi(slash+1);
                *slash = 0;
        }
        if (inet_pton(AF_INET, space+1, &dst) != 1) {
                uwsgi_error("uwsgi_tuntap_opt_route()/inet_pton()");
                exit(1);
        }
        if (slash) *slash = '/';

	*space = ' ';
        *space2 = ' ';

        struct uwsgi_tuntap_firewall_rule * utfr = uwsgi_tuntap_firewall_add_rule((struct uwsgi_tuntap_firewall_rule **) table, 1, ntohl(src), (0xffffffff << (32-src_mask)), ntohl(dst), (0xffffffff << (32-dst_mask)));
	char *colon = strchr(space2+1, ':');
	if (!colon) {
		uwsgi_log("tuntap routing gateway must be a udp address in the form addr:port\n");
		exit(1);
	}
	utfr->dest_addr.sin_family = AF_INET;
	utfr->dest_addr.sin_port = htons(atoi(colon+1));
	*colon = 0;
	utfr->dest_addr.sin_addr.s_addr = inet_addr(space2+1);
	*colon = ':';
	utfr->addrlen = sizeof(struct sockaddr_in);
}

void uwsgi_tuntap_peer_send_rules(int fd, struct uwsgi_tuntap_peer *peer) {
	struct uwsgi_string_list *usl = NULL;
	if (!utt.device_rules) return;
	struct uwsgi_buffer *ub = uwsgi_buffer_new(sizeof(struct uwsgi_tuntap_peer_rule) + 4);
	// leave space for the uwsgi header
	ub->pos = 4;
	uwsgi_foreach(usl, utt.device_rules) {
		size_t rlen;
		char **argv = uwsgi_split_quoted(usl->value, usl->len, " \t", &rlen); 
		if (rlen < 4) {
			uwsgi_log("invalid tuntap device rule, must be <direction> <src/mask> <dst/mask> <action> [target]\n");
			exit(1);
		}
		struct uwsgi_tuntap_peer_rule utpr;
		memset(&utpr, 0, sizeof(struct uwsgi_tuntap_peer_rule));
		utpr.src_mask = 0xffffffff;
		utpr.dst_mask = 0xffffffff;

		if (!strcmp(argv[0], "in")) {
			utpr.direction = 0;
		}
		else if (!strcmp(argv[0], "out")) {
			utpr.direction = 1;
		}
		else {
			uwsgi_log("invalid tuntap device rule direction, must be 'in' or 'out'\n");
			exit(1);
		}

		char *slash = strchr(argv[1],'/');
		if (slash) {
			utpr.src_mask = (0xffffffff << ((atoi(slash+1))-32));
			*slash = 0;
		}
		if (inet_pton(AF_INET, argv[1], &utpr.src) != 1) {
                	uwsgi_tuntap_error(peer, "uwsgi_tuntap_peer_send_rules()/inet_pton()");
                	exit(1);
		}
		if (slash) *slash = '/';
		utpr.src = ntohl(utpr.src);

		slash = strchr(argv[2],'/');
                if (slash) {
			utpr.dst_mask = (0xffffffff << ((atoi(slash+1))-32));
                        *slash = 0;
                }
                if (inet_pton(AF_INET, argv[2], &utpr.dst) != 1) {
                        uwsgi_tuntap_error(peer, "uwsgi_tuntap_peer_send_rules()/inet_pton()");
                        exit(1);
                }
                if (slash) *slash = '/';
		utpr.dst = ntohl(utpr.dst);

		if (!strcmp(argv[3], "deny")) {
			utpr.action = 1;
		}
		else if (!strcmp(argv[3], "allow")) {
			utpr.action = 0;
		}
		else if (!strcmp(argv[3], "route")) {
			utpr.action = 2;
		}
		else if (!strcmp(argv[3], "gateway")) {
			utpr.action = 2;
		}
		else {
			uwsgi_log("unsupported tuntap rule action: %s\n", argv[3]);
			exit(1);
		}

		if (utpr.action == 2) {
			if (rlen < 4) {
				uwsgi_log("tuntap rule route/gateway requires a target\n");
				exit(1);
			}
			char *colon = strchr(argv[4], ':');
			if (!colon) {
				uwsgi_log("tuntap target must be in the form addr:port\n");
				exit(1);
			}
			*colon = 0;
			if (inet_pton(AF_INET, argv[4], &utpr.target) != 1) {
                        	uwsgi_tuntap_error(peer, "uwsgi_tuntap_peer_send_rules()/inet_pton()");
                        	exit(1);
                	}
			*colon = ':';
			utpr.target = utpr.target;
			utpr.target_port = htons(atoi(colon+1));
		}

		if (uwsgi_buffer_append(ub, (char *) &utpr, sizeof(struct uwsgi_tuntap_peer_rule))) goto error;
		peer->rules_cnt++;
        }
	// we still do not have an official modifier for the tuntap router
	if (uwsgi_buffer_set_uh(ub, 0, 1)) goto error;
	peer->rules = (struct uwsgi_tuntap_peer_rule *)ub->buf;
	ub->buf = NULL;
	size_t len = ub->pos;
	uwsgi_buffer_destroy(ub);
	if (write(fd,peer->rules, len) != (ssize_t)len) {
		uwsgi_tuntap_error(peer, "uwsgi_tuntap_peer_send_rules()/write()");
		exit(1);
	}
	return;
error:
	uwsgi_log("unable to create tuntap device rules packet\n");
	exit(1);
}
