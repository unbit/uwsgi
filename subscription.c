#include "uwsgi.h"

/*

	subscription subsystem

	each subscription slot is as an auto-optmizing linked list. Originally it was a uwsgi_dict (now removed from uWSGI) but this
	would have not be able to support regexp as keys.

	each slot has another circular linked list containing the nodes names

	the structure and system is very similar to uwsgi_dyn_dict already used by the mime type parser

	This system is not mean to run on shared memory. If you have multiple processes for the same app, you have to create
	a new subscriptions slot list.

	To avoid removal of already using nodes, a reference count system has been implemented

*/

extern struct uwsgi_server uwsgi;

struct uwsgi_subscribe_slot *uwsgi_get_subscribe_slot(struct uwsgi_subscribe_slot **slot, char *key, uint16_t keylen, int regexp) {

	struct uwsgi_subscribe_slot *current_slot = *slot;

	if (keylen > 0xff) return NULL;
	
#ifdef UWSGI_DEBUG
	uwsgi_log("****************************\n");
	while(current_slot) {
		uwsgi_log("slot %.*s %d\n", current_slot->keylen, current_slot->key, current_slot->hits);
		current_slot = current_slot->next;
	}
	uwsgi_log("****************************\n");
#endif

	current_slot = *slot;

	while(current_slot) {
#ifdef UWSGI_PCRE
		if (regexp) {
			if (uwsgi_regexp_match(current_slot->pattern, current_slot->pattern_extra, key, keylen) >= 0) {
				return current_slot;
			}
		}
		else {
#endif
			if (!uwsgi_strncmp(key, keylen, current_slot->key, current_slot->keylen)) {
                		// auto optimization
                        	if (current_slot->prev) {
                                        if (current_slot->hits > current_slot->prev->hits) {
                                                struct uwsgi_subscribe_slot *slot_parent = current_slot->prev->prev, *slot_prev = current_slot->prev;
                                                if (slot_parent) {
                                                       slot_parent->next = current_slot;
                                                }
						else {
							*slot = current_slot;
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
#ifdef UWSGI_PCRE
		}
#endif
		current_slot = current_slot->next;
		// check for loopy optimization
		if (current_slot == *slot) break;
	}

        return NULL;
}

struct uwsgi_subscribe_node *uwsgi_get_subscribe_node(struct uwsgi_subscribe_slot **slot, char *key, uint16_t keylen, int regexp) {

	if (keylen > 0xff) return NULL;

	struct uwsgi_subscribe_slot *current_slot = uwsgi_get_subscribe_slot(slot, key, keylen, regexp);
	uint64_t rr_pos = 0;

	if (current_slot) {
		// node found, move up in the list increasing hits
		current_slot->hits++;
		time_t current = time(NULL);
		struct uwsgi_subscribe_node *node = current_slot->nodes;
		while(node) {
			// is the node alive ?
			if (current - node->last_check > uwsgi.subscription_tolerance) {
				if (node->death_mark == 0)
					uwsgi_log("[uwsgi-subscription for pid %d] %.*s => marking %.*s as failed (no announce received in %d seconds)\n", (int) uwsgi.mypid, (int) keylen, key, (int) node->len, node->name, uwsgi.subscription_tolerance);
				node->failcnt++;
				node->death_mark = 1;
			}
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

			if (node->death_mark == 0 && rr_pos == current_slot->rr && node->wrr > 0) {
				node->wrr--;
				if (node->wrr == 0) {
					current_slot->rr++;
					// if this is the last node, recalculate wrr
					if (node->next == NULL) {
						struct uwsgi_subscribe_node *r_node = current_slot->nodes;
						while(r_node) {
							r_node->wrr = r_node->weight;
							r_node = r_node->next;
						}
					}
				}
				node->reference++;
				return node;
			}
			node = node->next;
			rr_pos++;
		}
		current_slot->rr = 1;
		if (current_slot->nodes) {
			if (current_slot->nodes->death_mark)
				return NULL;
			if (current_slot->nodes->wrr == 0) current_slot->nodes->wrr = current_slot->nodes->weight;
			current_slot->nodes->wrr--;
			if (current_slot->nodes->wrr > 0) {
				// reset rr counter
				current_slot->rr = 0;
			}
			current_slot->nodes->reference++;
		}
		return current_slot->nodes;
	}

	return NULL;
}

struct uwsgi_subscribe_node *uwsgi_get_subscribe_node_by_name(struct uwsgi_subscribe_slot **slot, char *key, uint16_t keylen, char *val, uint16_t vallen, int regexp) {

	if (keylen > 0xff) return NULL;
	struct uwsgi_subscribe_slot *current_slot = uwsgi_get_subscribe_slot(slot, key, keylen, regexp);
	if (current_slot) {
		struct uwsgi_subscribe_node *node = current_slot->nodes;
		while(node) {
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

	// over-engineering to avoid race conditions
	node->len = 0;

	if (node == node_slot->nodes) {
		node_slot->nodes = node->next;
	}
	else {
		a_node = node_slot->nodes;
		while(a_node) {
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
			free(node_slot);
			*slot = NULL;
			goto end;
		}

		// if i am the main entry point, set the next value
		if (node_slot == *slot) {
			*slot = next_slot;
		}
			
		if (prev_slot) {	
			prev_slot->next = next_slot;	
		}
		if (next_slot) {
			next_slot->prev = prev_slot;
		}

#ifdef UWSGI_PCRE
		if (node_slot->pattern) {
			pcre_free(node_slot->pattern);
		}
		if (node_slot->pattern_extra) {
			pcre_free(node_slot->pattern_extra);
		}
#endif

		free(node_slot);
	}

end:

	return ret;
}

struct uwsgi_subscribe_node *uwsgi_add_subscribe_node(struct uwsgi_subscribe_slot **slot, struct uwsgi_subscribe_req *usr, int regexp) {

	struct uwsgi_subscribe_slot *current_slot = uwsgi_get_subscribe_slot(slot, usr->key, usr->keylen, 0), *old_slot = NULL, *a_slot;
	struct uwsgi_subscribe_node *node, *old_node = NULL;

	if (usr->address_len > 0xff) return NULL;

        if (current_slot) {
		node = current_slot->nodes;
		while(node) {
                        if (!uwsgi_strncmp(node->name, node->len, usr->address, usr->address_len)) {
				// remove death mark and update cores and load
				node->death_mark = 0;
                                node->last_check = time(NULL);
				node->cores = usr->cores;
				node->load = usr->load;
				node->weight = usr->weight;
				if (!node->weight) node->weight = 1;
                                return node;
                        }
			old_node = node;
			node = node->next;
                }

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
		if (!node->weight) node->weight = 1;
		node->wrr = node->weight;
		node->last_check = time(NULL);
		node->slot = current_slot;
                memcpy(node->name, usr->address, usr->address_len);
		if (old_node) {
			old_node->next = node;
		}
		node->next = NULL;
                uwsgi_log("[uwsgi-subscription for pid %d] %.*s => new node: %.*s\n",(int) uwsgi.mypid, usr->keylen, usr->key, usr->address_len, usr->address);
                return node;
        }
        else {

		current_slot = uwsgi_malloc(sizeof(struct uwsgi_subscribe_slot));
		current_slot->keylen = usr->keylen;
		memcpy(current_slot->key, usr->key, usr->keylen);
		current_slot->key[usr->keylen] = 0;
		current_slot->hits = 0;
		current_slot->rr = 0;

#ifdef UWSGI_PCRE
		current_slot->pattern = NULL;
		current_slot->pattern_extra = NULL;
		if (regexp) {
			if (uwsgi_regexp_build(current_slot->key, &current_slot->pattern, &current_slot->pattern_extra)) {
				free(current_slot);
				return NULL;
			}
		}
#endif

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
		if (!current_slot->nodes->weight) current_slot->nodes->weight = 1;
		current_slot->nodes->wrr = current_slot->nodes->weight;
		memcpy(current_slot->nodes->name, usr->address, usr->address_len);
		current_slot->nodes->last_check = time(NULL);

		current_slot->nodes->next = NULL;

#ifdef UWSGI_PCRE
		// if key is a regexp, order it by keylen
		if (regexp) {
			old_slot = NULL;
			a_slot = *slot;
			while(a_slot) {
				if (a_slot->keylen > current_slot->keylen) {
					old_slot = a_slot;
					break;
				}	
				a_slot = a_slot->next;
			}

			if (old_slot) {
				current_slot->prev = old_slot->prev;
				old_slot->prev = current_slot;
				if (current_slot->prev) {
					old_slot->prev->next = current_slot;
				}
	
				current_slot->next = old_slot;
			}
			else {
				a_slot = *slot;
                        	while(a_slot) {
                                	old_slot = a_slot;
                                	a_slot = a_slot->next;
                        	}


                        	if (old_slot) {
                                	old_slot->next = current_slot;
                        	}

                        	current_slot->prev = old_slot;
                        	current_slot->next = NULL;
			}
		}
		else {
#endif
			a_slot = *slot;
			while(a_slot) {
				old_slot = a_slot;
				a_slot = a_slot->next;
			}


			if (old_slot) {
				old_slot->next = current_slot;
			}

			current_slot->prev = old_slot;
			current_slot->next = NULL;

#ifdef UWSGI_PCRE
		}
#endif

		if (!*slot || current_slot->prev == NULL) {
			*slot = current_slot;
		}

		uwsgi_log("[uwsgi-subscription for pid %d] new pool: %.*s\n",(int) uwsgi.mypid, usr->keylen, usr->key);
		uwsgi_log("[uwsgi-subscription for pid %d] %.*s => new node: %.*s\n",(int) uwsgi.mypid, usr->keylen, usr->key, usr->address_len, usr->address);
                return current_slot->nodes;
        }

}


void uwsgi_send_subscription(char *udp_address, char *key, size_t keysize, uint8_t modifier1, uint8_t modifier2, uint8_t cmd) {

	char value_cores[sizeof(UMAX64_STR)+1];
	char value_load[sizeof(UMAX64_STR)+1];
	char value_weight[sizeof(UMAX64_STR)+1];


	int value_cores_size = uwsgi_long2str2n(uwsgi.numproc*uwsgi.cores, value_cores, sizeof(UMAX64_STR));
	int value_load_size = uwsgi_long2str2n(uwsgi.shared->load, value_load, sizeof(UMAX64_STR));

	int value_weight_size = 0;
	
	if (uwsgi.auto_weight) {
		value_weight_size = uwsgi_long2str2n(uwsgi.numproc*uwsgi.cores, value_weight, sizeof(UMAX64_STR));
	}
	else {
		value_weight_size = uwsgi_long2str2n(uwsgi.weight, value_weight, sizeof(UMAX64_STR));
	}

	char value_modifier1[4];
	char value_modifier2[4];
	int value_modifier1_size = uwsgi_long2str2n(modifier1, value_modifier1, 3);
	int value_modifier2_size = uwsgi_long2str2n(modifier2, value_modifier2, 3);

	if (!uwsgi.sockets) return;

	size_t ssb_size = 4 + (2 + 3) + (2 + keysize) + (2 + 7) + (2 + strlen(uwsgi.sockets->name)) + (2+9 + 2+value_modifier1_size) +
		(2+9 + 2+value_modifier2_size) + (2+5 + 2+value_cores_size) + (2+4 + 2+value_load_size) + (2+5 + 2+value_weight_size);

        char *subscrbuf = uwsgi_malloc(ssb_size);
	// leave space for uwsgi header
        char *ssb = subscrbuf+4;

	// key = "domain"
        uint16_t ustrlen = 3;
        *ssb++ = (uint8_t) (ustrlen  & 0xff);
        *ssb++ = (uint8_t) ((ustrlen >>8) & 0xff);
        memcpy(ssb, "key", ustrlen);
        ssb+=ustrlen;

        ustrlen = keysize;
        *ssb++ = (uint8_t) (ustrlen  & 0xff);
        *ssb++ = (uint8_t) ((ustrlen >>8) & 0xff);
        memcpy(ssb, key, ustrlen);
        ssb+=ustrlen;

	// address = "first uwsgi socket"
        ustrlen = 7;
        *ssb++ = (uint8_t) (ustrlen  & 0xff);
        *ssb++ = (uint8_t) ((ustrlen >>8) & 0xff);
        memcpy(ssb, "address", ustrlen);
        ssb+=ustrlen;

        ustrlen = strlen(uwsgi.sockets->name);
        *ssb++ = (uint8_t) (ustrlen  & 0xff);
        *ssb++ = (uint8_t) ((ustrlen >>8) & 0xff);
        memcpy(ssb, uwsgi.sockets->name, ustrlen);
        ssb+=ustrlen;

	// modifier1 = "modifier1"
        ustrlen = 9;
        *ssb++ = (uint8_t) (ustrlen  & 0xff);
        *ssb++ = (uint8_t) ((ustrlen >>8) & 0xff);
        memcpy(ssb, "modifier1", ustrlen);
        ssb+=ustrlen;

        ustrlen = value_modifier1_size;
        *ssb++ = (uint8_t) (ustrlen  & 0xff);
        *ssb++ = (uint8_t) ((ustrlen >>8) & 0xff);
        memcpy(ssb, value_modifier1, value_modifier1_size);
        ssb+=ustrlen;

	// modifier2 = "modifier2"
        ustrlen = 9;
        *ssb++ = (uint8_t) (ustrlen  & 0xff);
        *ssb++ = (uint8_t) ((ustrlen >>8) & 0xff);
        memcpy(ssb, "modifier2", ustrlen);
        ssb+=ustrlen;

        ustrlen = value_modifier2_size;
        *ssb++ = (uint8_t) (ustrlen  & 0xff);
        *ssb++ = (uint8_t) ((ustrlen >>8) & 0xff);
        memcpy(ssb, value_modifier2, value_modifier2_size);
        ssb+=ustrlen;

	// cores = uwsgi.numproc * uwsgi.cores
        ustrlen = 5;
        *ssb++ = (uint8_t) (ustrlen  & 0xff);
        *ssb++ = (uint8_t) ((ustrlen >>8) & 0xff);
        memcpy(ssb, "cores", ustrlen);
        ssb+=ustrlen;

        ustrlen = value_cores_size;
        *ssb++ = (uint8_t) (ustrlen  & 0xff);
        *ssb++ = (uint8_t) ((ustrlen >>8) & 0xff);
        memcpy(ssb, value_cores, value_cores_size);
        ssb+=ustrlen;

	// load
        ustrlen = 4;
        *ssb++ = (uint8_t) (ustrlen  & 0xff);
        *ssb++ = (uint8_t) ((ustrlen >>8) & 0xff);
        memcpy(ssb, "load", ustrlen);
        ssb+=ustrlen;

        ustrlen = value_load_size;
        *ssb++ = (uint8_t) (ustrlen  & 0xff);
        *ssb++ = (uint8_t) ((ustrlen >>8) & 0xff);
        memcpy(ssb, value_load, value_load_size);
        ssb+=ustrlen;

	// weight
        ustrlen = 5;
        *ssb++ = (uint8_t) (ustrlen  & 0xff);
        *ssb++ = (uint8_t) ((ustrlen >>8) & 0xff);
        memcpy(ssb, "weight", ustrlen);
        ssb+=ustrlen;

        ustrlen = value_weight_size;
        *ssb++ = (uint8_t) (ustrlen  & 0xff);
        *ssb++ = (uint8_t) ((ustrlen >>8) & 0xff);
        memcpy(ssb, value_weight, value_weight_size);
        ssb+=ustrlen;
	

        send_udp_message(224, cmd, udp_address, subscrbuf, ssb_size-4);
	free(subscrbuf);
}

