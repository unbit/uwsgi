#include "../uwsgi.h"

extern struct uwsgi_server uwsgi;
/*

	uWSGI Legions subsystem

	A Legion is a group of uWSGI instances sharing a single object. This single
	object can be owned only by the instance with the higher valor. Such an instance is the
	Lord of the Legion. There can only be one (and only one) Lord for each Legion.
	If a member of a Legion spawns with an higher valor than the current Lord, it became the new Lord.

	If two (or more) member of a legion have the same valor, an error condition will be triggered (TODO fallback to something more useful)

	{ "legion": "legion1", "valor": "100", "unix": "1354533245", "lord": "1354533245", "name": "foobar" }

	Legions options (the legion1 is formed by 4 nodes, only one node will get the ip address, this is an ip takeover implementation)

	// became a member of a legion (each legion uses a shared secret)
	legion = legion1 192.168.0.1:4001 100 algo:mysecret
	// the other members of the legion
	legion-node = legion1 192.168.0.2:4001
	legion-node = legion1 192.168.0.3:4001
	legion-node = legion1 192.168.0.4:4001

	legion-lord = legion1 iptakeover:action=up,addr=192.168.0.100
	legion-unlord = legion1 iptakeover:action=down,addr=192.168.0.100

	legion-lord = legion1 cmd:foobar.sh up
	legion-unlord = legion1 cmd:foobar.sh down

	TODO
	some option could benefit from the legions subsystem, expecially in clustered environments	
	Cron-tasks for example could be run only by the lord and so on...

	

*/

struct uwsgi_legion *uwsgi_legion_get_by_socket(int fd) {
	struct uwsgi_legion *ul = uwsgi.legions;
	while (ul) {
		if (ul->socket == fd) {
			return ul;
		}
		ul = ul->next;
	}

	return NULL;
}

struct uwsgi_legion *uwsgi_legion_get_by_name(char *name) {
	struct uwsgi_legion *ul = uwsgi.legions;
	while (ul) {
		if (!strcmp(name, ul->legion)) {
			return ul;
		}
		ul = ul->next;
	}

	return NULL;
}


void uwsgi_parse_legion(char *key, uint16_t keylen, char *value, uint16_t vallen, void *data) {
	struct uwsgi_legion *ul = (struct uwsgi_legion *) data;

	if (!uwsgi_strncmp(key, keylen, "legion", 6)) {
		ul->legion = value;
		ul->legion_len = vallen;
	}
	else if (!uwsgi_strncmp(key, keylen, "valor", 5)) {
		ul->valor = uwsgi_str_num(value, vallen);
	}
	else if (!uwsgi_strncmp(key, keylen, "name", 4)) {
		ul->name = value;
		ul->name_len = vallen;
	}
	else if (!uwsgi_strncmp(key, keylen, "pid", 3)) {
		ul->pid = uwsgi_str_num(value, vallen);
	}
	else if (!uwsgi_strncmp(key, keylen, "unix", 4)) {
		ul->unix_check = uwsgi_str_num(value, vallen);
	}
	else if (!uwsgi_strncmp(key, keylen, "checksum", 8)) {
		ul->checksum = uwsgi_str_num(value, vallen);
	}
	else if (!uwsgi_strncmp(key, keylen, "uuid", 4)) {
		if (vallen == 36) {
			memcpy(ul->uuid, value, 36);
		}
	}
	else if (!uwsgi_strncmp(key, keylen, "lord_valor", 10)) {
		ul->lord_valor = uwsgi_str_num(value, vallen);
	}
	else if (!uwsgi_strncmp(key, keylen, "lord_uuid", 9)) {
		if (vallen == 36) {
			memcpy(ul->lord_uuid, value, 36);
		}
	}
}

struct uwsgi_legion_node *uwsgi_legion_add_node(struct uwsgi_legion *ul, uint16_t valor, char *name, uint16_t name_len, char *uuid) {

	struct uwsgi_legion_node *node = uwsgi_calloc(sizeof(struct uwsgi_legion_node));
	if (!name_len)
		goto error;
	node->name = uwsgi_calloc(name_len);
	node->name_len = name_len;
	memcpy(node->name, name, name_len);
	node->valor = valor;
	memcpy(node->uuid, uuid, 36);

	if (ul->nodes_tail) {
		node->prev = ul->nodes_tail;
		ul->nodes_tail->next = node;
	}

	ul->nodes_tail = node;

	if (!ul->nodes_head) {
		ul->nodes_head = node;
	}

	return node;


error:
	free(node);
	return NULL;
}

void uwsgi_legion_remove_node(struct uwsgi_legion *ul, struct uwsgi_legion_node *node) {
	// check if the node is the first one
	if (node == ul->nodes_head) {
		ul->nodes_head = node->next;
	}

	// check if the node is the last one
	if (node == ul->nodes_tail) {
		ul->nodes_tail = node->prev;
	}

	if (node->prev) {
		node->prev->next = node->next;
	}

	if (node->next) {
		node->next->prev = node->prev;
	}

	if (node->name_len) {
		free(node->name);
	}

	if (node->scroll_len) {
		free(node->scroll);
	}

	free(node);
}

struct uwsgi_legion_node *uwsgi_legion_get_node(struct uwsgi_legion *ul, uint64_t valor, char *name, uint16_t name_len, char *uuid) {
	struct uwsgi_legion_node *nodes = ul->nodes_head;
	while (nodes) {
		if (valor != nodes->valor)
			goto next;
		if (name_len != nodes->name_len)
			goto next;
		if (memcmp(nodes->name, name, name_len))
			goto next;
		if (memcmp(nodes->uuid, uuid, 36))
			goto next;
		return nodes;
next:
		nodes = nodes->next;
	}
	return NULL;
}

static void legions_check_nodes() {

	struct uwsgi_legion *legion = uwsgi.legions;
	while (legion) {
		time_t now = uwsgi_now();

		struct uwsgi_legion_node *node = legion->nodes_head;
		while (node) {

			if (now - node->last_seen > uwsgi.legion_tolerance) {
				struct uwsgi_legion_node *tmp_node = node;
				node = node->next;
				uwsgi_log("[uwsgi-legion] node: %.*s valor: %llu uuid: %.*s left Legion %s\n", tmp_node->name_len, tmp_node->name, tmp_node->valor, 36, tmp_node->uuid, legion->legion);
				uwsgi_legion_remove_node(legion, tmp_node);
				continue;
			}
			node = node->next;
		}

		legion = legion->next;
	}
}

struct uwsgi_legion_node *uwsgi_legion_get_lord(struct uwsgi_legion *);

static void legions_report_quorum(struct uwsgi_legion *ul, uint64_t best_valor, char *best_uuid) {
	struct uwsgi_legion_node *nodes = ul->nodes_head;
	uwsgi_log("\n[uwsgi-legion] --- WE HAVE QUORUM FOR LEGION %s !!! (valor: %llu uuid: %.*s) ---\n", ul->legion, best_valor, 36, best_uuid);
	while (nodes) {
		uwsgi_log("[uwsgi-legion-node] node: %.*s valor: %llu uuid: %.*s last_seen: %d vote_valor: %llu vote_uuid: %.*s\n", nodes->name_len, nodes->name, nodes->valor, 36, nodes->uuid, nodes->last_seen, nodes->lord_valor, 36, nodes->lord_uuid);
		nodes = nodes->next;
	}
	uwsgi_log("[uwsgi-legion] --- END OF QUORUM REPORT ---\n\n");
}

uint64_t uwsgi_legion_checksum(struct uwsgi_legion *ul) {
	uint16_t i;
	uint64_t checksum = ul->valor;
	for(i=0;i<36;i++) {
		checksum += ul->uuid[i];
	}

	struct uwsgi_legion_node *nodes = ul->nodes_head;
	while (nodes) {
		checksum += nodes->valor;
		for(i=0;i<36;i++) {
			checksum += nodes->uuid[i];
		}
		nodes = nodes->next;
	}

	return checksum;	
	
}

static void legions_check_nodes_step2() {
	struct uwsgi_legion *ul = uwsgi.legions;
	while (ul) {
		// ok now we can check the status of the lord
		int i_am_the_best = 0;
		uint64_t best_valor = 0;
		char best_uuid[36];
		struct uwsgi_legion_node *node = uwsgi_legion_get_lord(ul);
		if (node) {
			// a node is the best candidate
			best_valor = node->valor;
			memcpy(best_uuid, node->uuid, 36);
		}
		else {
			// no potential Lord is available, i will propose myself
			best_valor = ul->valor;
			memcpy(best_uuid, ul->uuid, 36);
			i_am_the_best = 1;
		}

		// calculate the checksum
		ul->checksum = uwsgi_legion_checksum(ul);

		// ... ok let's see if all of the nodes agree on the lord
		// ... but first check if i am not alone...
		int have_quorum = 0;
		if (!ul->nodes_head) {
			have_quorum = 1;
		}
		else {
			struct uwsgi_legion_node *nodes = ul->nodes_head;
			while (nodes) {
				if (nodes->checksum != ul->checksum) {
					have_quorum = 0;
					break;
				}
				if (nodes->lord_valor != best_valor) {
					have_quorum = 0;
					break;
				}
				if (memcmp(nodes->lord_uuid, best_uuid, 36)) {
					have_quorum = 0;
					break;
				}
				have_quorum++;
				nodes = nodes->next;
			}
		}

		if (have_quorum) {
			if (i_am_the_best) {
				if (!ul->i_am_the_lord) {
					legions_report_quorum(ul, best_valor, best_uuid);
					uwsgi_log("[uwsgi-legion] i am now the Lord of the Legion %s\n", ul->legion);
					// triggering lord hooks
					struct uwsgi_string_list *usl = ul->lord_hooks;
					while (usl) {
						int ret = uwsgi_legion_action_call("lord", ul, usl);
						if (ret) {
							uwsgi_log("[uwsgi-legion] ERROR, lord hook returned: %d\n", ret);
						}
						usl = usl->next;
					}
					ul->i_am_the_lord = uwsgi_now();
				}
			}
			else {
				if (ul->i_am_the_lord) {
					legions_report_quorum(ul, best_valor, best_uuid);
					uwsgi_log("[uwsgi-legion] a new Lord (valor: %llu uuid: %.*s) raised for Legion %s...\n", ul->lord_valor, 36, ul->lord_uuid, ul->legion);
					// no more lord, trigger unlord hooks
					struct uwsgi_string_list *usl = ul->unlord_hooks;
					while (usl) {
						int ret = uwsgi_legion_action_call("unlord", ul, usl);
						if (ret) {
							uwsgi_log("[uwsgi-legion] ERROR, unlord hook returned: %d\n", ret);
						}
						usl = usl->next;
					}
					ul->i_am_the_lord = 0;
				}
			}
		}

		ul = ul->next;
	}
}

// check who should be the lord of the legion
struct uwsgi_legion_node *uwsgi_legion_get_lord(struct uwsgi_legion *ul) {

	char best_uuid[36];

	memcpy(best_uuid, ul->uuid, 36);
	uint64_t best_valor = ul->valor;

	struct uwsgi_legion_node *best_node = NULL;

	struct uwsgi_legion_node *nodes = ul->nodes_head;
	while (nodes) {
		if (nodes->valor > best_valor) {
			best_node = nodes;
			best_valor = nodes->valor;
			memcpy(best_uuid, nodes->uuid, 36);
		}
		else if (nodes->valor == best_valor) {
			if (uwsgi_uuid_cmp(nodes->uuid, best_uuid)) {
				best_node = nodes;
				best_valor = nodes->valor;
				memcpy(best_uuid, nodes->uuid, 36);
			}
		}
		nodes = nodes->next;
	}


	ul->lord_valor = best_valor;
	memcpy(ul->lord_uuid, best_uuid, 36);

	return best_node;
}


static void *legion_loop(void *foobar) {

	time_t last_round = uwsgi_now();

	unsigned char *crypted_buf = uwsgi_malloc(UMAX16 - EVP_MAX_BLOCK_LENGTH - 4);
	unsigned char *clear_buf = uwsgi_malloc(UMAX16);

	struct uwsgi_legion legion_msg;

	if (!uwsgi.legion_freq)
		uwsgi.legion_freq = 3;
	if (!uwsgi.legion_tolerance)
		uwsgi.legion_tolerance = 15;

	for (;;) {
		int timeout = uwsgi.legion_freq;
		time_t now = uwsgi_now();
		if (now > last_round) {
			timeout -= (now - last_round);
			if (timeout < 0) {
				timeout = 0;
			}
		}
		last_round = now;
		// wait for event
		int interesting_fd = -1;
		int rlen = event_queue_wait(uwsgi.legion_queue, timeout, &interesting_fd);

		now = uwsgi_now();
		if (timeout == 0 || rlen == 0 || (now - last_round) >= timeout) {
			struct uwsgi_legion *legions = uwsgi.legions;
			while (legions) {
				uwsgi_legion_announce(legions);
				legions = legions->next;
			}
			last_round = now;
		}

		// check the nodes
		legions_check_nodes();

		if (rlen > 0) {
			struct uwsgi_legion *ul = uwsgi_legion_get_by_socket(interesting_fd);
			if (!ul)
				continue;
			// ensure the first 4 bytes are valid
			ssize_t len = read(ul->socket, crypted_buf, (UMAX16 - EVP_MAX_BLOCK_LENGTH - 4));
			if (len < 0) {
				uwsgi_error("[uwsgi-legion] read()");
				continue;
			}
			else if (len < 4) {
				uwsgi_log("[uwsgi-legion] invalid packet size: %d\n", (int) len);
				continue;
			}

			struct uwsgi_header *uh = (struct uwsgi_header *) crypted_buf;

			if (uh->modifier1 != 109) {
				uwsgi_log("[uwsgi-legion] invalid modifier1");
				continue;
			}

			int d_len = 0;
			int d2_len = 0;
			// decrypt packet using the secret
			if (EVP_DecryptInit_ex(ul->decrypt_ctx, NULL, NULL, NULL, NULL) <= 0) {
				uwsgi_error("[uwsgi-legion] EVP_DecryptInit_ex()");
				continue;
			}

			if (EVP_DecryptUpdate(ul->decrypt_ctx, clear_buf, &d_len, crypted_buf + 4, len - 4) <= 0) {
				uwsgi_error("[uwsgi-legion] EVP_DecryptUpdate()");
				continue;
			}

			if (EVP_DecryptFinal_ex(ul->decrypt_ctx, clear_buf + d_len, &d2_len) <= 0) {
				ERR_print_errors_fp(stderr);
				uwsgi_log("[uwsgi-legion] EVP_DecryptFinal_ex()\n");
				continue;
			}

			d_len += d2_len;

			if (d_len != uh->pktsize) {
				uwsgi_log("[uwsgi-legion] invalid packet size\n");
				continue;
			}

			// parse packet
			memset(&legion_msg, 0, sizeof(struct uwsgi_legion));
			if (uwsgi_hooked_parse((char *) clear_buf, d_len, uwsgi_parse_legion, &legion_msg)) {
				uwsgi_log("[uwsgi-legion] invalid packet\n");
				continue;
			}

			if (uwsgi_strncmp(ul->legion, ul->legion_len, legion_msg.legion, legion_msg.legion_len)) {
				uwsgi_log("[uwsgi-legion] invalid legion name\n");
				continue;
			}

			// check for loop packets... (expecially when in multicast mode)
			if (!uwsgi_strncmp(uwsgi.hostname, uwsgi.hostname_len, legion_msg.name, legion_msg.name_len)) {
				if (legion_msg.pid == ul->pid) {
					if (legion_msg.valor == ul->valor) {
						if (!memcmp(legion_msg.uuid, ul->uuid, 36)) {
							continue;
						}
					}
				}
			}

			// check for "tolerable" unix time
			if (legion_msg.unix_check < uwsgi_now() - uwsgi.legion_tolerance) {
				uwsgi_log("[uwsgi-legion] untolerable packet received for Legion %s , check your clock !!!\n", ul->legion);
				continue;
			}

			// check if the node is already accounted
			struct uwsgi_legion_node *node = uwsgi_legion_get_node(ul, legion_msg.valor, legion_msg.name, legion_msg.name_len, legion_msg.uuid);
			if (!node) {
				// add the new node
				node = uwsgi_legion_add_node(ul, legion_msg.valor, legion_msg.name, legion_msg.name_len, legion_msg.uuid);
				uwsgi_log("[uwsgi-legion] node: %.*s valor: %llu uuid: %.*s joined Legion %s\n", node->name_len, node->name, node->valor, 36, node->uuid, ul->legion);
			}

			node->last_seen = uwsgi_now();
			node->lord_valor = legion_msg.lord_valor;
			node->checksum = legion_msg.checksum;
			memcpy(node->lord_uuid, legion_msg.lord_uuid, 36);

		}

		legions_check_nodes_step2();

/*
			if (ul->lord > 0) {
				if (legion_msg.valor > ul->valor) {
					uwsgi_log("[uwsgi-legion] a new Lord (name: %.*s pid: %d) raised for Legion %s...\n", legion_msg.name_len, legion_msg.name, (int) legion_msg.pid, ul->legion);
					// no more lord, trigger unlord hooks
                        		struct uwsgi_string_list *usl = ul->unlord_hooks;
                        		while(usl) {
                                		int ret = uwsgi_legion_action_call("unlord", ul, usl);
                                		if (ret) {
                                        		uwsgi_log("[uwsgi-legion] ERROR, unlord hook returned: %d\n", ret);
                                		}
                                		usl = usl->next;
                        		}
					ul->last_seen_lord = uwsgi_now();
					ul->lord = 0;
					continue;
				}
			}

			if (legion_msg.valor > ul->valor) {
				// a lord
				ul->last_seen_lord = uwsgi_now();
			}
			else if (legion_msg.valor == ul->valor) {
				uwsgi_log("[uwsgi-legion] a node with the same valor announced itself !!!\n");
			}
*/
	}

	return NULL;
}

int uwsgi_legion_action_call(char *phase, struct uwsgi_legion *ul, struct uwsgi_string_list *usl) {
	struct uwsgi_legion_action *ula = uwsgi_legion_action_get(usl->custom_ptr);
	if (!ula) {
		uwsgi_log("[uwsgi-legion] ERROR unable to find legion_action \"%s\"\n", (char *) usl->custom_ptr);
		return -1;
	}

	uwsgi_log("[uwsgi-legion] (phase: %s legion: %s) calling %s\n", phase, ul->legion, usl->value);
	return ula->func(ul, usl->value + usl->custom);
}

static int legion_action_cmd(struct uwsgi_legion *ul, char *arg) {
	return uwsgi_run_command_and_wait(NULL, arg);
}

void uwsgi_start_legions() {
	pthread_t legion_loop_t;

	if (!uwsgi.legions)
		return;

	// register embedded actions
	uwsgi_legion_action_register("cmd", legion_action_cmd);

	uwsgi.legion_queue = event_queue_init();
	struct uwsgi_legion *legion = uwsgi.legions;
	while (legion) {
		char *colon = strchr(legion->addr, ':');
		if (colon) {
			legion->socket = bind_to_udp(legion->addr, 0, 0);
		}
		else {
			legion->socket = bind_to_unix_dgram(legion->addr);
		}
		if (legion->socket < 0 || event_queue_add_fd_read(uwsgi.legion_queue, legion->socket)) {
			uwsgi_log("[uwsgi-legion] unable to activate legion %s\n", legion->legion);
			exit(1);
		}
		uwsgi_socket_nb(legion->socket);
		legion->pid = uwsgi.mypid;
		uwsgi_uuid(legion->uuid);
		struct uwsgi_string_list *usl = legion->setup_hooks;
		while (usl) {
			int ret = uwsgi_legion_action_call("setup", legion, usl);
			if (ret) {
				uwsgi_log("[uwsgi-legion] ERROR, setup hook returned: %d\n", ret);
			}
			usl = usl->next;
		}
		legion = legion->next;
	}

	if (pthread_create(&legion_loop_t, NULL, legion_loop, NULL)) {
		uwsgi_error("pthread_create()");
		uwsgi_log("unable to run the legion server !!!\n");
	}
	else {
		uwsgi_log("legion manager thread enabled\n");
	}

}

void uwsgi_legion_add(struct uwsgi_legion *ul) {
	struct uwsgi_legion *old_legion = NULL, *legion = uwsgi.legions;
	while (legion) {
		old_legion = legion;
		legion = legion->next;
	}

	if (old_legion) {
		old_legion->next = ul;
	}
	else {
		uwsgi.legions = ul;
	}
}

int uwsgi_legion_announce(struct uwsgi_legion *ul) {
	struct uwsgi_buffer *ub = uwsgi_buffer_new(4096);

	if (uwsgi_buffer_append_keyval(ub, "legion", 6, ul->legion, ul->legion_len))
		goto err;
	if (uwsgi_buffer_append_keynum(ub, "valor", 5, ul->valor))
		goto err;
	if (uwsgi_buffer_append_keynum(ub, "unix", 4, uwsgi_now()))
		goto err;
	if (uwsgi_buffer_append_keynum(ub, "lord", 4, ul->i_am_the_lord ? ul->i_am_the_lord : 0))
		goto err;
	if (uwsgi_buffer_append_keyval(ub, "name", 4, uwsgi.hostname, uwsgi.hostname_len))
		goto err;
	if (uwsgi_buffer_append_keynum(ub, "pid", 3, ul->pid))
		goto err;
	if (uwsgi_buffer_append_keyval(ub, "uuid", 4, ul->uuid, 36))
		goto err;
	if (uwsgi_buffer_append_keynum(ub, "checksum", 8, ul->checksum))
		goto err;
	if (uwsgi_buffer_append_keynum(ub, "lord_valor", 10, ul->lord_valor))
		goto err;
	if (uwsgi_buffer_append_keyval(ub, "lord_uuid", 9, ul->lord_uuid, 36))
		goto err;
#ifdef UWSGI_UUID
#endif

	unsigned char *encrypted = uwsgi_malloc(ub->pos + 4 + EVP_MAX_BLOCK_LENGTH);
	if (EVP_EncryptInit_ex(ul->encrypt_ctx, NULL, NULL, NULL, NULL) <= 0) {
		uwsgi_error("[uwsgi-legion] EVP_EncryptInit_ex()");
		goto err;
	}

	int e_len = 0;

	if (EVP_EncryptUpdate(ul->encrypt_ctx, encrypted + 4, &e_len, (unsigned char *) ub->buf, ub->pos) <= 0) {
		uwsgi_error("[uwsgi-legion] EVP_EncryptUpdate()");
		goto err;
	}

	int tmplen = 0;
	if (EVP_EncryptFinal_ex(ul->encrypt_ctx, encrypted + 4 + e_len, &tmplen) <= 0) {
		uwsgi_error("[uwsgi-legion] EVP_EncryptFinal_ex()");
		goto err;
	}

	e_len += tmplen;
	uint16_t pktsize = ub->pos;
	encrypted[0] = 109;
	encrypted[1] = (unsigned char) (pktsize & 0xff);
	encrypted[2] = (unsigned char) ((pktsize >> 8) & 0xff);
	encrypted[3] = 0;

	struct uwsgi_string_list *usl = ul->nodes;
	while (usl) {
		if (sendto(ul->socket, encrypted, e_len + 4, 0, usl->custom_ptr, usl->custom) != e_len + 4) {
			uwsgi_error("[uwsgi-legion] sendto()");
		}
		usl = usl->next;
	}

	uwsgi_buffer_destroy(ub);
	free(encrypted);
	return 0;
err:
	uwsgi_buffer_destroy(ub);
	return -1;
}

void uwsgi_opt_legion_node(char *opt, char *value, void *foobar) {

	char *legion = uwsgi_str(value);

	char *space = strchr(legion, ' ');
	if (!space) {
		uwsgi_log("invalid legion-node syntax, must be <legion> <addr>\n");
		exit(1);
	}
	*space = 0;

	struct uwsgi_legion *ul = uwsgi_legion_get_by_name(legion);
	if (!ul) {
		uwsgi_log("unknown legion: %s\n", legion);
		exit(1);
	}

	struct uwsgi_string_list *usl = uwsgi_string_new_list(&ul->nodes, space + 1);
	char *port = strchr(usl->value, ':');
	if (!port) {
		uwsgi_log("[uwsgi-legion] invalid udp address: %s\n", usl->value);
		exit(1);
	}
	// no need to zero the memory, socket_to_in_addr will do that
	struct sockaddr_in *sin = uwsgi_malloc(sizeof(struct sockaddr_in));
	usl->custom = socket_to_in_addr(usl->value, port, 0, sin);
	usl->custom_ptr = sin;
}

void uwsgi_opt_legion_hook(char *opt, char *value, void *foobar) {

	char *legion = uwsgi_str(value);

	char *space = strchr(legion, ' ');
	if (!space) {
		uwsgi_log("invalid %s syntax, must be <legion> <action>\n", opt);
		exit(1);
	}
	*space = 0;

	struct uwsgi_legion *ul = uwsgi_legion_get_by_name(legion);
	if (!ul) {
		uwsgi_log("unknown legion: %s\n", legion);
		exit(1);
	}

	struct uwsgi_string_list *usl = NULL;

	if (!strcmp(opt, "legion-lord")) {
		usl = uwsgi_string_new_list(&ul->lord_hooks, space + 1);
	}
	else if (!strcmp(opt, "legion-unlord")) {
		usl = uwsgi_string_new_list(&ul->unlord_hooks, space + 1);
	}
	else if (!strcmp(opt, "legion-setup")) {
		usl = uwsgi_string_new_list(&ul->setup_hooks, space + 1);
	}
	else if (!strcmp(opt, "legion-death")) {
		usl = uwsgi_string_new_list(&ul->death_hooks, space + 1);
	}

	if (!usl)
		return;

	char *port = strchr(usl->value, ':');
	if (!port) {
		uwsgi_log("[uwsgi-legion] invalid %s action: %s\n", opt, usl->value);
		exit(1);
	}

	// pointer to action plugin
	usl->custom_ptr = uwsgi_concat2n(usl->value, port - usl->value, "", 0);
	// add that to check the plugin value
	usl->custom = port - usl->value + 1;
}


void uwsgi_opt_legion(char *opt, char *value, void *foobar) {

	// legion addr valor algo:secret
	char *legion = uwsgi_str(value);
	char *space = strchr(legion, ' ');
	if (!space) {
		uwsgi_log("invalid legion syntax, must be <legion> <addr> <valor> <algo:secret>\n");
		exit(1);
	}
	*space = 0;
	char *addr = space + 1;

	space = strchr(addr, ' ');
	if (!space) {
		uwsgi_log("invalid legion syntax, must be <legion> <addr> <valor> <algo:secret>\n");
		exit(1);
	}
	*space = 0;
	char *valor = space + 1;

	space = strchr(valor, ' ');
	if (!space) {
		uwsgi_log("invalid legion syntax, must be <legion> <addr> <valor> <algo:secret>\n");
		exit(1);
	}
	*space = 0;
	char *algo_secret = space + 1;

	char *colon = strchr(algo_secret, ':');
	if (!colon) {
		uwsgi_log("invalid legion syntax, must be <legion> <addr> <valor> <algo:secret>\n");
		exit(1);
	}
	*colon = 0;
	char *secret = colon + 1;

	if (!uwsgi.ssl_initialized) {
		uwsgi_ssl_init();
	}

	EVP_CIPHER_CTX *ctx = uwsgi_malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx);

	const EVP_CIPHER *cipher = EVP_get_cipherbyname(algo_secret);
	if (!cipher) {
		uwsgi_log("[uwsgi-legion] unable to find algorithm/cipher %s\n", algo_secret);
		exit(1);
	}

	int cipher_len = EVP_CIPHER_key_length(cipher);
	size_t s_len = strlen(secret);
	if ((unsigned int) cipher_len > s_len) {
		char *secret_tmp = uwsgi_malloc(cipher_len);
		memcpy(secret_tmp, secret, s_len);
		memset(secret_tmp + s_len, 0, cipher_len - s_len);
		secret = secret_tmp;
	}

/*
	TODO find a wat to manage iv
	char *iv = uwsgi_ssl_rand(strlen(secret));
	if (!iv) {
		uwsgi_log("[uwsgi-legion] unable to generate iv for legion %s\n", legion); 
		exit(1);
	}
*/

	if (EVP_EncryptInit_ex(ctx, cipher, NULL, (const unsigned char *) secret, (const unsigned char *) "12345678") <= 0) {	// (const unsigned char *) iv) <= 0) {
		uwsgi_error("EVP_EncryptInit_ex()");
		exit(1);
	}

	EVP_CIPHER_CTX *ctx2 = uwsgi_malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx2);

	if (EVP_DecryptInit_ex(ctx2, cipher, NULL, (const unsigned char *) secret, (const unsigned char *) "12345678") <= 0) {
		uwsgi_error("EVP_DecryptInit_ex()");
		exit(1);
	}

	// we use shared memory, as we want to export legion status to the api
	struct uwsgi_legion *ul = uwsgi_calloc_shared(sizeof(struct uwsgi_legion));
	ul->legion = legion;
	ul->legion_len = strlen(ul->legion);

	ul->valor = strtol(valor, (char **) NULL, 10);
	ul->addr = addr;

	ul->encrypt_ctx = ctx;
	ul->decrypt_ctx = ctx2;

	uwsgi_legion_add(ul);
}

struct uwsgi_legion_action *uwsgi_legion_action_get(char *name) {
	struct uwsgi_legion_action *ula = uwsgi.legion_actions;
	while (ula) {
		if (!strcmp(name, ula->name)) {
			return ula;
		}
		ula = ula->next;
	}
	return NULL;
}

void uwsgi_legion_action_register(char *name, int (*func) (struct uwsgi_legion *, char *)) {
	if (uwsgi_legion_action_get(name)) {
		uwsgi_log("[uwsgi-legion] action \"%s\" is already registered !!!\n", name);
		return;
	}

	struct uwsgi_legion_action *old_ula = NULL, *ula = uwsgi.legion_actions;
	while (ula) {
		old_ula = ula;
		ula = ula->next;
	}

	ula = uwsgi_calloc(sizeof(struct uwsgi_legion_action));
	ula->name = name;
	ula->func = func;

	if (old_ula) {
		old_ula->next = ula;
	}
	else {
		uwsgi.legion_actions = ula;
	}
}


void uwsgi_legion_atexit(void) {
	struct uwsgi_legion *legion = uwsgi.legions;
	while (legion) {
		if (getpid() != legion->pid)
			goto next;
		struct uwsgi_string_list *usl = legion->death_hooks;
		while (usl) {
			int ret = uwsgi_legion_action_call("death", legion, usl);
			if (ret) {
				uwsgi_log("[uwsgi-legion] ERROR, death hook returned: %d\n", ret);
			}
			usl = usl->next;
		}
next:
		legion = legion->next;
	}

}
