#include "uwsgi.h"

extern struct uwsgi_server uwsgi;


#ifdef UWSGI_UDP

static void cluster_manage_opt(char *key, uint16_t keylen, char *value, uint16_t vallen, void *foobar) {

	add_exported_option(uwsgi_concat2n(key, keylen, "", 0), uwsgi_concat2n(value, vallen, "", 0), 0);

}

void cluster_setup() {

	int rlen;
// get cluster configuration
	if (uwsgi.cluster != NULL) {
		// get multicast socket

		uwsgi.cluster_fd = uwsgi_cluster_join(uwsgi.cluster);

		uwsgi_log("JOINED CLUSTER: %s\n", uwsgi.cluster);

		// ask for cluster options only if bot pre-existent options are set
		if (uwsgi.exported_opts_cnt == 1 && !uwsgi.cluster_nodes) {
			// now wait max 60 seconds and resend multicast request every 10 seconds
			for (;;) {
				uwsgi_log("asking \"%s\" uWSGI cluster for configuration data:\n", uwsgi.cluster);
				if (uwsgi_send_empty_pkt(uwsgi.cluster_fd, uwsgi.cluster, 99, 0) < 0) {
					uwsgi_log("unable to send multicast message to %s\n", uwsgi.cluster);
					continue;
				}
waitfd:
				rlen = uwsgi_waitfd(uwsgi.cluster_fd, 10);
				if (rlen < 0) {
					break;
				}
				else if (rlen > 0) {
					// receive the packet
					char clusterbuf[4096];
					if (!uwsgi_hooked_parse_dict_dgram(uwsgi.cluster_fd, clusterbuf, 4096, 99, 1, cluster_manage_opt, NULL)) {
						uwsgi_configure();
						goto options_parsed;
					}
					else {
						goto waitfd;
					}
				}
			}
		}
options_parsed:

		if (!uwsgi.cluster_nodes)
			uwsgi_cluster_add_me();
	}
}




void uwsgi_cluster_add_node(struct uwsgi_cluster_node *nucn, int type) {

	int i;
	struct uwsgi_cluster_node *ucn;
	char *tcp_port;

#ifdef UWSGI_DEBUG
	uwsgi_log("adding node\n");
#endif

	tcp_port = strchr(nucn->name, ':');
#ifndef UWSGI_ZEROMQ
	if (tcp_port == NULL) {
#else
	char *zmq_dash = strchr(nucn->name, '-');
	if (tcp_port == NULL && zmq_dash == NULL) {
#endif

		fprintf(stdout, "invalid cluster node name %s\n", nucn->name);
		return;
	}

	// first check for already present node
	for (i = 0; i < MAX_CLUSTER_NODES; i++) {
		ucn = &uwsgi.shared->nodes[i];
		if (ucn->name[0] != 0) {
			if (!strcmp(ucn->name, nucn->name)) {
				ucn->status = UWSGI_NODE_OK;
				ucn->last_seen = uwsgi_now();
				// update requests
				ucn->requests = nucn->requests;
				return;
			}
		}
	}

	for (i = 0; i < MAX_CLUSTER_NODES; i++) {
		ucn = &uwsgi.shared->nodes[i];

		if (ucn->name[0] == 0) {
			memcpy(ucn->name, nucn->name, strlen(nucn->name) + 1);
			memcpy(ucn->nodename, nucn->nodename, strlen(nucn->nodename) + 1);
			ucn->workers = nucn->workers;
			ucn->ucn_addr.sin_family = AF_INET;
			if (tcp_port) {
				ucn->ucn_addr.sin_port = htons(atoi(tcp_port + 1));
				tcp_port[0] = 0;
			}
			if (nucn->name[0] == 0) {
				ucn->ucn_addr.sin_addr.s_addr = INADDR_ANY;
			}
			else {
#ifdef UWSGI_DEBUG
				uwsgi_log("%s\n", nucn->name);
#endif
				ucn->ucn_addr.sin_addr.s_addr = inet_addr(nucn->name);
			}

			ucn->type = type;
			// here memory can be freed, as it is allocated by uwsgi_concat2n
			if (type != CLUSTER_NODE_DYNAMIC && tcp_port) {
				tcp_port[0] = ':';
			}
			ucn->last_seen = uwsgi_now();
			ucn->requests = nucn->requests;
			uwsgi_log("[uWSGI cluster] added node %s\n", ucn->name);
			return;
		}
	}

	uwsgi_log("unable to add node %s\n", nucn->name);
}



int uwsgi_cluster_add_me() {

	const char *key1 = "hostname";
	const char *key2 = "address";
	const char *key3 = "workers";
	const char *key4 = "requests";

	char *ptrbuf;
	uint16_t ustrlen;
	char numproc[6];

#ifdef UWSGI_ZEROMQ
	char uuid_zmq_str[37];
	uuid_t uuid_zmq;
	if (!uwsgi.sockets && !uwsgi.zeromq) {
#else
	if (!uwsgi.sockets) {
#endif
		uwsgi_log("you need to specify at least a socket to start a uWSGI cluster\n");
		exit(1);
	}

	snprintf(numproc, 6, "%d", uwsgi.numproc);

	size_t len;

	if (uwsgi.sockets) {
		len = 2 + strlen(key1) + 2 + strlen(uwsgi.hostname) + 2 + strlen(key2) + 2 + strlen(uwsgi.sockets->name) + 2 + strlen(key3) + 2 + strlen(numproc) + 2 + strlen(key4) + 2 + 1;
	}
#ifdef UWSGI_ZEROMQ
	else if (uwsgi.zeromq) {
		uuid_generate(uuid_zmq);
		uuid_unparse(uuid_zmq, uuid_zmq_str);
		len = 2 + strlen(key1) + 2 + strlen(uwsgi.hostname) + 2 + strlen(key2) + 2 + strlen(uuid_zmq_str) + 2 + strlen(key3) + 2 + strlen(numproc) + 2 + strlen(key4) + 2 + 1;
	}
#endif
	else {
		len = 2 + strlen(key1) + 2 + strlen(uwsgi.hostname) + 2 + strlen(key3) + 2 + strlen(numproc) + 2 + strlen(key4) + 2 + 1;
	}
	char *buf = uwsgi_malloc(len);

	ptrbuf = buf;

	ustrlen = strlen(key1);
	*ptrbuf++ = (uint8_t) (ustrlen & 0xff);
	*ptrbuf++ = (uint8_t) ((ustrlen >> 8) & 0xff);
	memcpy(ptrbuf, key1, strlen(key1));
	ptrbuf += strlen(key1);

	ustrlen = strlen(uwsgi.hostname);
	*ptrbuf++ = (uint8_t) (ustrlen & 0xff);
	*ptrbuf++ = (uint8_t) ((ustrlen >> 8) & 0xff);
	memcpy(ptrbuf, uwsgi.hostname, strlen(uwsgi.hostname));
	ptrbuf += strlen(uwsgi.hostname);


	if (uwsgi.sockets && uwsgi.sockets->name) {
		ustrlen = strlen(key2);
		*ptrbuf++ = (uint8_t) (ustrlen & 0xff);
		*ptrbuf++ = (uint8_t) ((ustrlen >> 8) & 0xff);
		memcpy(ptrbuf, key2, strlen(key2));
		ptrbuf += strlen(key2);

		ustrlen = strlen(uwsgi.sockets->name);
		*ptrbuf++ = (uint8_t) (ustrlen & 0xff);
		*ptrbuf++ = (uint8_t) ((ustrlen >> 8) & 0xff);
		memcpy(ptrbuf, uwsgi.sockets->name, strlen(uwsgi.sockets->name));
		ptrbuf += strlen(uwsgi.sockets->name);
	}
#ifdef UWSGI_ZEROMQ
	else if (uwsgi.zeromq) {
		ustrlen = strlen(key2);
		*ptrbuf++ = (uint8_t) (ustrlen & 0xff);
		*ptrbuf++ = (uint8_t) ((ustrlen >> 8) & 0xff);
		memcpy(ptrbuf, key2, strlen(key2));
		ptrbuf += strlen(key2);

		ustrlen = strlen(uuid_zmq_str);
		*ptrbuf++ = (uint8_t) (ustrlen & 0xff);
		*ptrbuf++ = (uint8_t) ((ustrlen >> 8) & 0xff);
		memcpy(ptrbuf, uuid_zmq_str, strlen(uuid_zmq_str));
		ptrbuf += strlen(uuid_zmq_str);
	}
#endif


	ustrlen = strlen(key3);
	*ptrbuf++ = (uint8_t) (ustrlen & 0xff);
	*ptrbuf++ = (uint8_t) ((ustrlen >> 8) & 0xff);
	memcpy(ptrbuf, key3, strlen(key3));
	ptrbuf += strlen(key3);

	ustrlen = strlen(numproc);
	*ptrbuf++ = (uint8_t) (ustrlen & 0xff);
	*ptrbuf++ = (uint8_t) ((ustrlen >> 8) & 0xff);
	memcpy(ptrbuf, numproc, strlen(numproc));
	ptrbuf += strlen(numproc);

	ustrlen = strlen(key4);
	*ptrbuf++ = (uint8_t) (ustrlen & 0xff);
	*ptrbuf++ = (uint8_t) ((ustrlen >> 8) & 0xff);
	memcpy(ptrbuf, key4, strlen(key4));
	ptrbuf += strlen(key4);

	ustrlen = 1;
	*ptrbuf++ = (uint8_t) (ustrlen & 0xff);
	*ptrbuf++ = (uint8_t) ((ustrlen >> 8) & 0xff);
	memcpy(ptrbuf, "0", 1);
	ptrbuf += 1;


	uwsgi_string_sendto(uwsgi.cluster_fd, 95, 0, (struct sockaddr *) &uwsgi.mc_cluster_addr, sizeof(uwsgi.mc_cluster_addr), buf, len);

	free(buf);

#ifdef UWSGI_DEBUG
	uwsgi_log("add_me() successfull\n");
#endif

	return 0;
}


int uwsgi_cluster_join(char *name) {

	int fd;
	char *cp;
	int broadcast = 0;



	if (name[0] == ':') {
		fd = bind_to_udp(name, 0, 1);
		broadcast = 1;
	}
	else {
		fd = bind_to_udp(name, 1, 0);
	}

	if (fd >= 0) {
		cp = strchr(name, ':');
		cp[0] = 0;
		uwsgi.mc_cluster_addr.sin_family = AF_INET;
		if (broadcast) {
			uwsgi.mc_cluster_addr.sin_addr.s_addr = INADDR_BROADCAST;
		}
		else {
			uwsgi.mc_cluster_addr.sin_addr.s_addr = inet_addr(name);
		}
		uwsgi.mc_cluster_addr.sin_port = htons(atoi(cp + 1));
		cp[0] = ':';


		// announce my presence to all the nodes
		uwsgi_string_sendto(fd, 73, 0, (struct sockaddr *) &uwsgi.mc_cluster_addr, sizeof(uwsgi.mc_cluster_addr), uwsgi.hostname, strlen(uwsgi.hostname));
	}
	else {
		exit(1);
	}


	return fd;

}


char *uwsgi_cluster_best_node() {

	int i;
	int best_node = -1;
	struct uwsgi_cluster_node *ucn;

	for (i = 0; i < MAX_CLUSTER_NODES; i++) {
		ucn = &uwsgi.shared->nodes[i];
		if (ucn->name[0] != 0 && ucn->status == UWSGI_NODE_OK) {
			if (best_node == -1) {
				best_node = i;
			}
			else {
				if (ucn->last_choosen < uwsgi.shared->nodes[best_node].last_choosen) {
					best_node = i;
				}
			}
		}
	}

	if (best_node == -1) {
		return NULL;
	}

	uwsgi.shared->nodes[best_node].last_choosen = uwsgi_now();
	return uwsgi.shared->nodes[best_node].name;
}


void manage_cluster_announce(char *key, uint16_t keylen, char *val, uint16_t vallen, void *data) {

	char *tmpstr;
	struct uwsgi_cluster_node *ucn = (struct uwsgi_cluster_node *) data;

#ifdef UWSGI_DEBUG
	uwsgi_log("%.*s = %.*s\n", keylen, key, vallen, val);
#endif

	if (!uwsgi_strncmp("hostname", 8, key, keylen)) {
		strncpy(ucn->nodename, val, UMIN(vallen, 255));
	}

	if (!uwsgi_strncmp("address", 7, key, keylen)) {
		strncpy(ucn->name, val, UMIN(vallen, 100));
	}

	if (!uwsgi_strncmp("workers", 7, key, keylen)) {
		tmpstr = uwsgi_concat2n(val, vallen, "", 0);
		ucn->workers = atoi(tmpstr);
		free(tmpstr);
	}

	if (!uwsgi_strncmp("requests", 8, key, keylen)) {
		tmpstr = uwsgi_concat2n(val, vallen, "", 0);
		ucn->requests = strtoul(tmpstr, NULL, 0);
		free(tmpstr);
	}
}

void manage_cluster_message(char *cluster_opt_buf, int cluster_opt_size) {

	struct uwsgi_cluster_node nucn;

	switch (uwsgi.workers[0].cores[0].req.uh.modifier1) {
	case 95:
		memset(&nucn, 0, sizeof(struct uwsgi_cluster_node));

#ifdef __BIG_ENDIAN__
		uwsgi.workers[0].cores[0].req.uh.pktsize = uwsgi_swap16(uwsgi.workers[0].cores[0].req.uh.pktsize);
#endif
		uwsgi_hooked_parse(uwsgi.workers[0].cores[0].req.buffer, uwsgi.workers[0].cores[0].req.uh.pktsize, manage_cluster_announce, &nucn);
		if (nucn.name[0] != 0) {
			uwsgi_cluster_add_node(&nucn, CLUSTER_NODE_DYNAMIC);
		}
		break;
	case 96:
#ifdef __BIG_ENDIAN__
		uwsgi.workers[0].cores[0].req.uh.pktsize = uwsgi_swap16(uwsgi.workers[0].cores[0].req.uh.pktsize);
#endif
		uwsgi_log_verbose("%.*s\n", uwsgi.workers[0].cores[0].req.uh.pktsize, uwsgi.workers[0].cores[0].req.buffer);
		break;
	case 98:
		if (kill(getpid(), SIGHUP)) {
			uwsgi_error("kill()");
		}
		break;
	case 99:
		if (uwsgi.cluster_nodes)
			break;
		if (uwsgi.workers[0].cores[0].req.uh.modifier2 == 0) {
			uwsgi_log("requested configuration data, sending %d bytes\n", cluster_opt_size);
			sendto(uwsgi.cluster_fd, cluster_opt_buf, cluster_opt_size, 0, (struct sockaddr *) &uwsgi.mc_cluster_addr, sizeof(uwsgi.mc_cluster_addr));
		}
		break;
	case 73:
#ifdef __BIG_ENDIAN__
		uwsgi.workers[0].cores[0].req.uh.pktsize = uwsgi_swap16(uwsgi.workers[0].cores[0].req.uh.pktsize);
#endif
		uwsgi_log_verbose("[uWSGI cluster %s] new node available: %.*s\n", uwsgi.cluster, uwsgi.workers[0].cores[0].req.uh.pktsize, uwsgi.workers[0].cores[0].req.buffer);
		break;
	}
}

#endif


char *uwsgi_setup_clusterbuf(size_t * size) {

	size_t cluster_opt_size = 4;
	int i;

	for (i = 0; i < uwsgi.exported_opts_cnt; i++) {
		//uwsgi_log("%s\n", uwsgi.exported_opts[i]->key);
		cluster_opt_size += 2 + strlen(uwsgi.exported_opts[i]->key);
		if (uwsgi.exported_opts[i]->value) {
			cluster_opt_size += 2 + strlen(uwsgi.exported_opts[i]->value);
		}
		else {
			cluster_opt_size += 2 + 1;
		}
	}

	//uwsgi_log("cluster opts size: %d\n", cluster_opt_size);
	char *cluster_opt_buf = uwsgi_malloc(cluster_opt_size);

	struct uwsgi_header *uh = (struct uwsgi_header *) cluster_opt_buf;

	uh->modifier1 = 99;
	uh->pktsize = cluster_opt_size - 4;
	uh->modifier2 = 1;

#ifdef __BIG_ENDIAN__
	uh->pktsize = uwsgi_swap16(uh->pktsize);
#endif

	char *cptrbuf = cluster_opt_buf + 4;

	for (i = 0; i < uwsgi.exported_opts_cnt; i++) {
		//uwsgi_log("%s\n", uwsgi.exported_opts[i]->key);
		uint16_t ustrlen = strlen(uwsgi.exported_opts[i]->key);
		*cptrbuf++ = (uint8_t) (ustrlen & 0xff);
		*cptrbuf++ = (uint8_t) ((ustrlen >> 8) & 0xff);
		memcpy(cptrbuf, uwsgi.exported_opts[i]->key, ustrlen);
		cptrbuf += ustrlen;

		if (uwsgi.exported_opts[i]->value) {
			ustrlen = strlen(uwsgi.exported_opts[i]->value);
			*cptrbuf++ = (uint8_t) (ustrlen & 0xff);
			*cptrbuf++ = (uint8_t) ((ustrlen >> 8) & 0xff);
			memcpy(cptrbuf, uwsgi.exported_opts[i]->value, ustrlen);
		}
		else {
			ustrlen = 1;
			*cptrbuf++ = (uint8_t) (ustrlen & 0xff);
			*cptrbuf++ = (uint8_t) ((ustrlen >> 8) & 0xff);
			*cptrbuf = '1';
		}
		cptrbuf += ustrlen;
	}

	return cluster_opt_buf;
}
