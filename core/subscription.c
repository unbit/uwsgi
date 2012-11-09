#include "uwsgi.h"

/*

	subscription subsystem

	each subscription slot is as an hashed item in a dictionary

	each slot has a circular linked list containing the nodes names

	the structure and system is very similar to uwsgi_dyn_dict already used by the mime type parser

	This system is not mean to run on shared memory. If you have multiple processes for the same app, you have to create
	a new subscriptions slot list.

	To avoid removal of already using nodes, a reference count system has been implemented

*/


extern struct uwsgi_server uwsgi;

struct uwsgi_subscribe_slot *uwsgi_get_subscribe_slot(struct uwsgi_subscribe_slot **slot, char *key, uint16_t keylen) {

	if (keylen > 0xff)
		return NULL;

	uint32_t hash = djb33x_hash(key, keylen);
	int hash_key = hash % 0xffff;

	struct uwsgi_subscribe_slot *current_slot = slot[hash_key];


#ifdef UWSGI_DEBUG
	uwsgi_log("****************************\n");
	while (current_slot) {
		uwsgi_log("slot %.*s %d\n", current_slot->keylen, current_slot->key, current_slot->hits);
		current_slot = current_slot->next;
	}
	uwsgi_log("****************************\n");
	current_slot = slot[hash_key];
#endif

	while (current_slot) {
		if (!uwsgi_strncmp(key, keylen, current_slot->key, current_slot->keylen)) {
			// auto optimization
			if (current_slot->prev) {
				if (current_slot->hits > current_slot->prev->hits) {
					struct uwsgi_subscribe_slot *slot_parent = current_slot->prev->prev, *slot_prev = current_slot->prev;
					if (slot_parent) {
						slot_parent->next = current_slot;
					}
					else {
						slot[hash_key] = current_slot;
					}

					if (current_slot->next) {
						current_slot->next->prev = slot_prev;
					}

					slot_prev->prev = current_slot;
					slot_prev->next = current_slot->next;

					current_slot->next = slot_prev;
					current_slot->prev = slot_parent;

				}
			}
			return current_slot;
		}
		current_slot = current_slot->next;
		// check for loopy optimization
		if (current_slot == slot[hash_key])
			break;
	}

	return NULL;
}

// least reference count
static struct uwsgi_subscribe_node *uwsgi_subscription_algo_lrc(struct uwsgi_subscribe_slot *current_slot, struct uwsgi_subscribe_node *node) {
	// if node is NULL we are in the second step (in lrc mode we do not use the first step)
	if (node)
		return NULL;

	struct uwsgi_subscribe_node *choosen_node = NULL;
	node = current_slot->nodes;
	uint64_t min_rc = 0;
	while (node) {
		if (!node->death_mark) {
			if (min_rc == 0 || node->reference < min_rc) {
				min_rc = node->reference;
				choosen_node = node;
				if (min_rc == 0 && !(node->next && node->next->reference <= node->reference && node->next->requests <= node->requests))
					break;
			}
		}
		node = node->next;
	}

	if (choosen_node) {
		choosen_node->reference++;
	}

	return choosen_node;
}

// weighted least reference count
static struct uwsgi_subscribe_node *uwsgi_subscription_algo_wlrc(struct uwsgi_subscribe_slot *current_slot, struct uwsgi_subscribe_node *node) {
	// if node is NULL we are in the second step (in wlrc mode we do not use the first step)
	if (node)
		return NULL;

	struct uwsgi_subscribe_node *choosen_node = NULL;
	node = current_slot->nodes;
	double min_rc = 0;
	while (node) {
		if (!node->death_mark) {
			// node->weight is always >= 1, we can safely use it as divider
			double ref = (double) node->reference / (double) node->weight;
			double next_node_ref = 0;
			if (node->next)
				next_node_ref = (double) node->next->reference / (double) node->next->weight;

			if (min_rc == 0 || ref < min_rc) {
				min_rc = ref;
				choosen_node = node;
				if (min_rc == 0 && !(node->next && next_node_ref <= ref && node->next->requests <= node->requests))
					break;
			}
		}
		node = node->next;
	}

	if (choosen_node) {
		choosen_node->reference++;
	}

	return choosen_node;
}

// weighted round robin algo
static struct uwsgi_subscribe_node *uwsgi_subscription_algo_wrr(struct uwsgi_subscribe_slot *current_slot, struct uwsgi_subscribe_node *node) {
	// if node is NULL we are in the second step
	if (node) {
		if (node->death_mark == 0 && node->wrr > 0) {
			node->wrr--;
			node->reference++;
			return node;
		}
		return NULL;
	}

	// no wrr > 0 node found, reset them
	node = current_slot->nodes;
	uint64_t min_weight = 0;
	while (node) {
		if (!node->death_mark) {
			if (min_weight == 0 || node->weight < min_weight)
				min_weight = node->weight;
		}
		node = node->next;
	}

	// now set wrr
	node = current_slot->nodes;
	struct uwsgi_subscribe_node *choosen_node = NULL;
	while (node) {
		if (!node->death_mark) {
			node->wrr = node->weight / min_weight;
			choosen_node = node;
		}
		node = node->next;
	}
	if (choosen_node) {
		choosen_node->wrr--;
		choosen_node->reference++;
	}
	return choosen_node;
}

void uwsgi_subscription_set_algo(char *algo) {

	if (!algo)
		goto wrr;

	if (!strcmp(algo, "wrr")) {
		uwsgi.subscription_algo = uwsgi_subscription_algo_wrr;
		return;
	}

	if (!strcmp(algo, "lrc")) {
		uwsgi.subscription_algo = uwsgi_subscription_algo_lrc;
		return;
	}

	if (!strcmp(algo, "wlrc")) {
		uwsgi.subscription_algo = uwsgi_subscription_algo_wlrc;
		return;
	}

wrr:
	uwsgi.subscription_algo = uwsgi_subscription_algo_wrr;
}

struct uwsgi_subscribe_node *uwsgi_get_subscribe_node(struct uwsgi_subscribe_slot **slot, char *key, uint16_t keylen) {

	if (keylen > 0xff)
		return NULL;

	struct uwsgi_subscribe_slot *current_slot = uwsgi_get_subscribe_slot(slot, key, keylen);
	if (!current_slot)
		return NULL;

	// slot found, move up in the list increasing hits
	current_slot->hits++;
	time_t now = uwsgi_now();
	struct uwsgi_subscribe_node *node = current_slot->nodes;
	while (node) {
		// is the node alive ?
		if (now - node->last_check > uwsgi.subscription_tolerance) {
			if (node->death_mark == 0)
				uwsgi_log("[uwsgi-subscription for pid %d] %.*s => marking %.*s as failed (no announce received in %d seconds)\n", (int) uwsgi.mypid, (int) keylen, key, (int) node->len, node->name, uwsgi.subscription_tolerance);
			node->failcnt++;
			node->death_mark = 1;
		}
		// do i need to remove the node ?
		if (node->death_mark && node->reference == 0) {
			// remove the node and move to next
			struct uwsgi_subscribe_node *dead_node = node;
			node = node->next;
			// if the slot has been removed, return NULL;
			if (uwsgi_remove_subscribe_node(slot, dead_node) == 1) {
				return NULL;
			}
			continue;
		}

		struct uwsgi_subscribe_node *choosen_node = uwsgi.subscription_algo(current_slot, node);
		if (choosen_node)
			return choosen_node;

		node = node->next;
	}

	return uwsgi.subscription_algo(current_slot, node);
}

struct uwsgi_subscribe_node *uwsgi_get_subscribe_node_by_name(struct uwsgi_subscribe_slot **slot, char *key, uint16_t keylen, char *val, uint16_t vallen) {

	if (keylen > 0xff)
		return NULL;
	struct uwsgi_subscribe_slot *current_slot = uwsgi_get_subscribe_slot(slot, key, keylen);
	if (current_slot) {
		struct uwsgi_subscribe_node *node = current_slot->nodes;
		while (node) {
			if (!uwsgi_strncmp(val, vallen, node->name, node->len)) {
				return node;
			}
			node = node->next;
		}
	}

	return NULL;
}

int uwsgi_remove_subscribe_node(struct uwsgi_subscribe_slot **slot, struct uwsgi_subscribe_node *node) {

	int ret = 0;

	struct uwsgi_subscribe_node *a_node;
	struct uwsgi_subscribe_slot *node_slot = node->slot;
	struct uwsgi_subscribe_slot *prev_slot = node_slot->prev;
	struct uwsgi_subscribe_slot *next_slot = node_slot->next;

	int hash_key = node_slot->hash;

	// over-engineering to avoid race conditions
	node->len = 0;

	if (node == node_slot->nodes) {
		node_slot->nodes = node->next;
	}
	else {
		a_node = node_slot->nodes;
		while (a_node) {
			if (a_node->next == node) {
				a_node->next = node->next;
				break;
			}
			a_node = a_node->next;
		}
	}

	free(node);
	// no more nodes, remove the slot too
	if (node_slot->nodes == NULL) {

		ret = 1;

		// first check if i am the only node
		if ((!prev_slot && !next_slot) || next_slot == node_slot) {
#ifdef UWSGI_SSL
			if (uwsgi.subscriptions_sign_check_dir) {
				EVP_PKEY_free(node_slot->sign_public_key);
				EVP_MD_CTX_destroy(node_slot->sign_ctx);
			}
#endif
			free(node_slot);
			slot[hash_key] = NULL;
			goto end;
		}

		// if i am the main entry point, set the next value
		if (node_slot == slot[hash_key]) {
			slot[hash_key] = next_slot;
		}

		if (prev_slot) {
			prev_slot->next = next_slot;
		}
		if (next_slot) {
			next_slot->prev = prev_slot;
		}

#ifdef UWSGI_SSL
		if (uwsgi.subscriptions_sign_check_dir) {
			EVP_PKEY_free(node_slot->sign_public_key);
			EVP_MD_CTX_destroy(node_slot->sign_ctx);
		}
#endif
		free(node_slot);
	}

end:

	return ret;
}

struct uwsgi_subscribe_node *uwsgi_add_subscribe_node(struct uwsgi_subscribe_slot **slot, struct uwsgi_subscribe_req *usr) {

	struct uwsgi_subscribe_slot *current_slot = uwsgi_get_subscribe_slot(slot, usr->key, usr->keylen), *old_slot = NULL, *a_slot;
	struct uwsgi_subscribe_node *node, *old_node = NULL;

	if (usr->address_len > 0xff || usr->address_len == 0)
		return NULL;

#ifdef UWSGI_SSL
	if (uwsgi.subscriptions_sign_check_dir) {
		if (usr->sign_len == 0 || usr->base_len == 0)
			return NULL;
	}
#endif

	if (current_slot) {
#ifdef UWSGI_SSL
		if (uwsgi.subscriptions_sign_check_dir && !uwsgi_subscription_sign_check(current_slot, usr)) {
			return NULL;
		}
#endif
		node = current_slot->nodes;
		while (node) {
			if (!uwsgi_strncmp(node->name, node->len, usr->address, usr->address_len)) {
#ifdef UWSGI_SSL
				// this should avoid sending sniffed packets...
				if (uwsgi.subscriptions_sign_check_dir && usr->unix_check <= node->unix_check) {
					uwsgi_log("[uwsgi-subscription for pid %d] invalid (sniffed ?) packet sent for slot: %.*s node: %.*s unix_check: %lu\n", (int) uwsgi.mypid, usr->keylen, usr->key, usr->address_len, usr->address, (unsigned long) usr->unix_check);
					return NULL;
				}
#endif
				// remove death mark and update cores and load
				node->death_mark = 0;
				node->last_check = uwsgi_now();
				node->cores = usr->cores;
				node->load = usr->load;
				node->weight = usr->weight;
				if (!node->weight)
					node->weight = 1;
				return node;
			}
			old_node = node;
			node = node->next;
		}

#ifdef UWSGI_SSL
		if (uwsgi.subscriptions_sign_check_dir && usr->unix_check < (uwsgi_now() - (time_t) uwsgi.subscriptions_sign_check_tolerance)) {
			uwsgi_log("[uwsgi-subscription for pid %d] invalid (sniffed ?) packet sent for slot: %.*s node: %.*s unix_check: %lu\n", (int) uwsgi.mypid, usr->keylen, usr->key, usr->address_len, usr->address, (unsigned long) usr->unix_check);
			return NULL;
		}
#endif

		node = uwsgi_malloc(sizeof(struct uwsgi_subscribe_node));
		node->len = usr->address_len;
		node->modifier1 = usr->modifier1;
		node->modifier2 = usr->modifier2;
		node->requests = 0;
		node->transferred = 0;
		node->reference = 0;
		node->death_mark = 0;
		node->failcnt = 0;
		node->cores = usr->cores;
		node->load = usr->load;
		node->weight = usr->weight;
		node->unix_check = usr->unix_check;
		if (!node->weight)
			node->weight = 1;
		node->wrr = 0;
		node->last_check = uwsgi_now();
		node->slot = current_slot;
		memcpy(node->name, usr->address, usr->address_len);
		if (old_node) {
			old_node->next = node;
		}
		node->next = NULL;
		uwsgi_log("[uwsgi-subscription for pid %d] %.*s => new node: %.*s\n", (int) uwsgi.mypid, usr->keylen, usr->key, usr->address_len, usr->address);
		return node;
	}
	else {
#ifdef UWSGI_SSL
		FILE *kf = NULL;
		if (uwsgi.subscriptions_sign_check_dir) {
			if (usr->unix_check < (uwsgi_now() - (time_t) uwsgi.subscriptions_sign_check_tolerance)) {
				uwsgi_log("[uwsgi-subscription for pid %d] invalid (sniffed ?) packet sent for slot: %.*s node: %.*s unix_check: %lu\n", (int) uwsgi.mypid, usr->keylen, usr->key, usr->address_len, usr->address, (unsigned long) usr->unix_check);
				return NULL;
			}
			char *keyfile = uwsgi_sanitize_cert_filename(uwsgi.subscriptions_sign_check_dir, usr->key, usr->keylen);
			kf = fopen(keyfile, "r");
			free(keyfile);
			if (!kf)
				return NULL;

		}
#endif
		current_slot = uwsgi_malloc(sizeof(struct uwsgi_subscribe_slot));
		uint32_t hash = djb33x_hash(usr->key, usr->keylen);
		int hash_key = hash % 0xffff;
		current_slot->hash = hash_key;
#ifdef UWSGI_SSL
		if (uwsgi.subscriptions_sign_check_dir) {
			current_slot->sign_public_key = PEM_read_PUBKEY(kf, NULL, NULL, NULL);
			fclose(kf);
			if (!current_slot->sign_public_key) {
				uwsgi_log("unable to load public key for %.*s\n", usr->keylen, usr->key);
				free(current_slot);
				return NULL;
			}
			current_slot->sign_ctx = EVP_MD_CTX_create();
			if (!current_slot->sign_ctx) {
				uwsgi_log("unable to initialize EVP context for %.*s\n", usr->keylen, usr->key);
				EVP_PKEY_free(current_slot->sign_public_key);
				free(current_slot);
				return NULL;
			}

			if (!uwsgi_subscription_sign_check(current_slot, usr)) {
				EVP_PKEY_free(current_slot->sign_public_key);
				EVP_MD_CTX_destroy(current_slot->sign_ctx);
				free(current_slot);
				return NULL;
			}
		}
#endif
		current_slot->keylen = usr->keylen;
		memcpy(current_slot->key, usr->key, usr->keylen);
		current_slot->key[usr->keylen] = 0;
		current_slot->hits = 0;

		current_slot->nodes = uwsgi_malloc(sizeof(struct uwsgi_subscribe_node));
		current_slot->nodes->slot = current_slot;
		current_slot->nodes->len = usr->address_len;
		current_slot->nodes->reference = 0;
		current_slot->nodes->requests = 0;
		current_slot->nodes->transferred = 0;
		current_slot->nodes->death_mark = 0;
		current_slot->nodes->failcnt = 0;
		current_slot->nodes->modifier1 = usr->modifier1;
		current_slot->nodes->modifier2 = usr->modifier2;
		current_slot->nodes->cores = usr->cores;
		current_slot->nodes->load = usr->load;
		current_slot->nodes->weight = usr->weight;
		current_slot->nodes->unix_check = usr->unix_check;
		if (!current_slot->nodes->weight)
			current_slot->nodes->weight = 1;
		current_slot->nodes->wrr = 0;
		memcpy(current_slot->nodes->name, usr->address, usr->address_len);
		current_slot->nodes->last_check = uwsgi_now();

		current_slot->nodes->next = NULL;

		a_slot = slot[hash_key];
		while (a_slot) {
			old_slot = a_slot;
			a_slot = a_slot->next;
		}


		if (old_slot) {
			old_slot->next = current_slot;
		}

		current_slot->prev = old_slot;
		current_slot->next = NULL;


		if (!slot[hash_key] || current_slot->prev == NULL) {
			slot[hash_key] = current_slot;
		}

		uwsgi_log("[uwsgi-subscription for pid %d] new pool: %.*s (hash key: %d)\n", (int) uwsgi.mypid, usr->keylen, usr->key, current_slot->hash);
		uwsgi_log("[uwsgi-subscription for pid %d] %.*s => new node: %.*s\n", (int) uwsgi.mypid, usr->keylen, usr->key, usr->address_len, usr->address);
		return current_slot->nodes;
	}

}


// TODO rewrite it using uwsgi buffers
void uwsgi_send_subscription(char *udp_address, char *key, size_t keysize, uint8_t modifier1, uint8_t modifier2, uint8_t cmd, char *socket_name, char *sign) {

	char value_cores[sizeof(UMAX64_STR) + 1];
	char value_load[sizeof(UMAX64_STR) + 1];
	char value_weight[sizeof(UMAX64_STR) + 1];


	int value_cores_size = uwsgi_long2str2n(uwsgi.numproc * uwsgi.cores, value_cores, sizeof(UMAX64_STR));
	int value_load_size = uwsgi_long2str2n(uwsgi.shared->load, value_load, sizeof(UMAX64_STR));

	int value_weight_size = 0;

	if (uwsgi.auto_weight) {
		value_weight_size = uwsgi_long2str2n(uwsgi.numproc * uwsgi.cores, value_weight, sizeof(UMAX64_STR));
	}
	else {
		value_weight_size = uwsgi_long2str2n(uwsgi.weight, value_weight, sizeof(UMAX64_STR));
	}

	char value_modifier1[4];
	char value_modifier2[4];
	int value_modifier1_size = uwsgi_long2str2n(modifier1, value_modifier1, 3);
	int value_modifier2_size = uwsgi_long2str2n(modifier2, value_modifier2, 3);

	if (socket_name == NULL && !uwsgi.sockets)
		return;

	if (!socket_name) {
		socket_name = uwsgi.sockets->name;
	}

	size_t ssb_size = 4 + (2 + 3) + (2 + keysize) + (2 + 7) + (2 + strlen(socket_name)) + (2 + 9 + 2 + value_modifier1_size) + (2 + 9 + 2 + value_modifier2_size) + (2 + 5 + 2 + value_cores_size) + (2 + 4 + 2 + value_load_size) + (2 + 6 + 2 + value_weight_size);

	char *subscrbuf = uwsgi_malloc(ssb_size);
	// leave space for uwsgi header
	char *ssb = subscrbuf + 4;

	// key = "domain"
	uint16_t ustrlen = 3;
	*ssb++ = (uint8_t) (ustrlen & 0xff);
	*ssb++ = (uint8_t) ((ustrlen >> 8) & 0xff);
	memcpy(ssb, "key", ustrlen);
	ssb += ustrlen;

	ustrlen = keysize;
	*ssb++ = (uint8_t) (ustrlen & 0xff);
	*ssb++ = (uint8_t) ((ustrlen >> 8) & 0xff);
	memcpy(ssb, key, ustrlen);
	ssb += ustrlen;

	// address = "first uwsgi socket"
	ustrlen = 7;
	*ssb++ = (uint8_t) (ustrlen & 0xff);
	*ssb++ = (uint8_t) ((ustrlen >> 8) & 0xff);
	memcpy(ssb, "address", ustrlen);
	ssb += ustrlen;

	ustrlen = strlen(socket_name);
	*ssb++ = (uint8_t) (ustrlen & 0xff);
	*ssb++ = (uint8_t) ((ustrlen >> 8) & 0xff);
	memcpy(ssb, socket_name, ustrlen);
	ssb += ustrlen;

	// modifier1 = "modifier1"
	ustrlen = 9;
	*ssb++ = (uint8_t) (ustrlen & 0xff);
	*ssb++ = (uint8_t) ((ustrlen >> 8) & 0xff);
	memcpy(ssb, "modifier1", ustrlen);
	ssb += ustrlen;

	ustrlen = value_modifier1_size;
	*ssb++ = (uint8_t) (ustrlen & 0xff);
	*ssb++ = (uint8_t) ((ustrlen >> 8) & 0xff);
	memcpy(ssb, value_modifier1, value_modifier1_size);
	ssb += ustrlen;

	// modifier2 = "modifier2"
	ustrlen = 9;
	*ssb++ = (uint8_t) (ustrlen & 0xff);
	*ssb++ = (uint8_t) ((ustrlen >> 8) & 0xff);
	memcpy(ssb, "modifier2", ustrlen);
	ssb += ustrlen;

	ustrlen = value_modifier2_size;
	*ssb++ = (uint8_t) (ustrlen & 0xff);
	*ssb++ = (uint8_t) ((ustrlen >> 8) & 0xff);
	memcpy(ssb, value_modifier2, value_modifier2_size);
	ssb += ustrlen;

	// cores = uwsgi.numproc * uwsgi.cores
	ustrlen = 5;
	*ssb++ = (uint8_t) (ustrlen & 0xff);
	*ssb++ = (uint8_t) ((ustrlen >> 8) & 0xff);
	memcpy(ssb, "cores", ustrlen);
	ssb += ustrlen;

	ustrlen = value_cores_size;
	*ssb++ = (uint8_t) (ustrlen & 0xff);
	*ssb++ = (uint8_t) ((ustrlen >> 8) & 0xff);
	memcpy(ssb, value_cores, value_cores_size);
	ssb += ustrlen;

	// load
	ustrlen = 4;
	*ssb++ = (uint8_t) (ustrlen & 0xff);
	*ssb++ = (uint8_t) ((ustrlen >> 8) & 0xff);
	memcpy(ssb, "load", ustrlen);
	ssb += ustrlen;

	ustrlen = value_load_size;
	*ssb++ = (uint8_t) (ustrlen & 0xff);
	*ssb++ = (uint8_t) ((ustrlen >> 8) & 0xff);
	memcpy(ssb, value_load, value_load_size);
	ssb += ustrlen;

	// weight
	ustrlen = 6;
	*ssb++ = (uint8_t) (ustrlen & 0xff);
	*ssb++ = (uint8_t) ((ustrlen >> 8) & 0xff);
	memcpy(ssb, "weight", ustrlen);
	ssb += ustrlen;

	ustrlen = value_weight_size;
	*ssb++ = (uint8_t) (ustrlen & 0xff);
	*ssb++ = (uint8_t) ((ustrlen >> 8) & 0xff);
	memcpy(ssb, value_weight, value_weight_size);
	ssb += ustrlen;

#ifdef UWSGI_SSL
	if (sign) {
		// add space for "unix" item
		char unix_dst[sizeof(UMAX64_STR) + 1];
		if (snprintf(unix_dst, sizeof(UMAX64_STR) + 1, "%lu", (unsigned long) (uwsgi_now() + (time_t) cmd)) < 1) {
			uwsgi_error("unable to generate unix time for subscription !!!\n");
			free(subscrbuf);
			return;
		}
		ssb_size += 2 + 4 + 2 + strlen(unix_dst);
		char *new_buf = realloc(subscrbuf, ssb_size);
		if (!new_buf) {
			uwsgi_error("realloc()");
			free(subscrbuf);
			return;
		}

		// fix ssb (new_buf base could be changed)
		ssb = (new_buf + (ssb - subscrbuf));
		subscrbuf = new_buf;

		ustrlen = 4;
		*ssb++ = (uint8_t) (ustrlen & 0xff);
		*ssb++ = (uint8_t) ((ustrlen >> 8) & 0xff);
		memcpy(ssb, "unix", ustrlen);
		ssb += ustrlen;

		ustrlen = strlen(unix_dst);
		*ssb++ = (uint8_t) (ustrlen & 0xff);
		*ssb++ = (uint8_t) ((ustrlen >> 8) & 0xff);
		memcpy(ssb, unix_dst, strlen(unix_dst));
		ssb += ustrlen;

		unsigned int signature_len = 0;
		char *signature = uwsgi_rsa_sign(sign, subscrbuf + 4, ssb_size - 4, &signature_len);
		if (signature && signature_len > 0) {
			// add space for "sign" item
			ssb_size += 2 + 4 + 2 + signature_len;
			char *new_buf = realloc(subscrbuf, ssb_size);
			if (!new_buf) {
				uwsgi_error("realloc()");
				free(signature);
				free(subscrbuf);
				return;
			}

			// fix ssb (new_buf base could be changed)
			ssb = (new_buf + (ssb - subscrbuf));
			subscrbuf = new_buf;

			ustrlen = 4;
			*ssb++ = (uint8_t) (ustrlen & 0xff);
			*ssb++ = (uint8_t) ((ustrlen >> 8) & 0xff);
			memcpy(ssb, "sign", ustrlen);
			ssb += ustrlen;

			ustrlen = signature_len;
			*ssb++ = (uint8_t) (ustrlen & 0xff);
			*ssb++ = (uint8_t) ((ustrlen >> 8) & 0xff);
			memcpy(ssb, signature, signature_len);
			ssb += ustrlen;

			free(signature);
		}
	}
#endif


	send_udp_message(224, cmd, udp_address, subscrbuf, ssb_size - 4);
	free(subscrbuf);
}


#ifdef UWSGI_SSL
int uwsgi_subscription_sign_check(struct uwsgi_subscribe_slot *slot, struct uwsgi_subscribe_req *usr) {

	if (EVP_VerifyInit_ex(slot->sign_ctx, uwsgi.subscriptions_sign_check_md, NULL) == 0) {
		ERR_print_errors_fp(stderr);
		return 0;
	}

	if (EVP_VerifyUpdate(slot->sign_ctx, usr->base, usr->base_len) == 0) {
		ERR_print_errors_fp(stderr);
		return 0;
	}

	if (EVP_VerifyFinal(slot->sign_ctx, (unsigned char *) usr->sign, usr->sign_len, slot->sign_public_key) != 1) {
#ifdef UWSGI_DEBUG
		ERR_print_errors_fp(stderr);
#endif
		return 0;
	}


	return 1;
}
#endif

int uwsgi_no_subscriptions(struct uwsgi_subscribe_slot **slot) {
	int i;
	for (i = 0; i < UMAX16; i++) {
		if (slot[i])
			return 0;
	}
	return 1;
}

struct uwsgi_subscribe_slot **uwsgi_subscription_init_ht() {
	if (!uwsgi.subscription_algo) {
		uwsgi_subscription_set_algo(NULL);
	}
	return uwsgi_calloc(sizeof(struct uwsgi_subscription_slot *) * UMAX16);
}
