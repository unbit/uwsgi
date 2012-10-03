#include "../../uwsgi.h"

#include "cr.h"

extern struct uwsgi_server uwsgi;

int uwsgi_cr_map_use_void(struct uwsgi_corerouter *ucr, struct corerouter_session *cr_session) {
	return 0;
}

int uwsgi_cr_map_use_cache(struct uwsgi_corerouter *ucr, struct corerouter_session *cr_session) {
	cr_session->instance_address = uwsgi_cache_get(cr_session->hostname, cr_session->hostname_len, &cr_session->instance_address_len);
	char *cs_mod = uwsgi_str_contains(cr_session->instance_address, cr_session->instance_address_len, ',');
	if (cs_mod) {
		cr_session->modifier1 = uwsgi_str_num(cs_mod + 1, (cr_session->instance_address_len - (cs_mod - cr_session->instance_address)) - 1);
		cr_session->instance_address_len = (cs_mod - cr_session->instance_address);
	}
	return 0;
}

int uwsgi_cr_map_use_pattern(struct uwsgi_corerouter *ucr, struct corerouter_session *cr_session) {
	int tmp_socket_name_len = 0;
	ucr->magic_table['s'] = uwsgi_concat2n(cr_session->hostname, cr_session->hostname_len, "", 0);
	cr_session->tmp_socket_name = magic_sub(ucr->pattern, ucr->pattern_len, &tmp_socket_name_len, ucr->magic_table);
	free(ucr->magic_table['s']);
	cr_session->instance_address_len = tmp_socket_name_len;
	cr_session->instance_address = cr_session->tmp_socket_name;
	return 0;
}


int uwsgi_cr_map_use_subscription(struct uwsgi_corerouter *ucr, struct corerouter_session *cr_session) {

	cr_session->un = uwsgi_get_subscribe_node(ucr->subscriptions, cr_session->hostname, cr_session->hostname_len);
	if (cr_session->un && cr_session->un->len) {
		cr_session->instance_address = cr_session->un->name;
		cr_session->instance_address_len = cr_session->un->len;
		cr_session->modifier1 = cr_session->un->modifier1;
	}
	else if (ucr->cheap && !ucr->i_am_cheap && uwsgi_no_subscriptions(ucr->subscriptions)) {
		uwsgi_gateway_go_cheap(ucr->name, ucr->queue, &ucr->i_am_cheap);
	}

	return 0;
}

int uwsgi_cr_map_use_subscription_dotsplit(struct uwsgi_corerouter *ucr, struct corerouter_session *cr_session) {

	char *name = cr_session->hostname;
	uint16_t name_len = cr_session->hostname_len;

split:
#ifdef UWSGI_DEBUG
	uwsgi_log("trying with %.*s\n", name_len, name);
#endif
        cr_session->un = uwsgi_get_subscribe_node(ucr->subscriptions, name, name_len);
	if (!cr_session->un) {
		char *next = memchr(name+1, '.', name_len-1);
		if (next) {
			name_len -= next - name;
			name = next;
			goto split;
		}
	}

        if (cr_session->un && cr_session->un->len) {
                cr_session->instance_address = cr_session->un->name;
                cr_session->instance_address_len = cr_session->un->len;
                cr_session->modifier1 = cr_session->un->modifier1;
        }
        else if (ucr->cheap && !ucr->i_am_cheap && uwsgi_no_subscriptions(ucr->subscriptions)) {
                uwsgi_gateway_go_cheap(ucr->name, ucr->queue, &ucr->i_am_cheap);
        }

        return 0;
}


int uwsgi_cr_map_use_base(struct uwsgi_corerouter *ucr, struct corerouter_session *cr_session) {

	int tmp_socket_name_len = 0;

	cr_session->tmp_socket_name = uwsgi_concat2nn(ucr->base, ucr->base_len, cr_session->hostname, cr_session->hostname_len, &tmp_socket_name_len);
	cr_session->instance_address_len = tmp_socket_name_len;
	cr_session->instance_address = cr_session->tmp_socket_name;
	
	return 0;
}


int uwsgi_cr_map_use_cs(struct uwsgi_corerouter *ucr, struct corerouter_session *cr_session) {
	if (uwsgi.p[ucr->code_string_modifier1]->code_string) {
		char *name = uwsgi_concat2("uwsgi_", ucr->short_name);
		cr_session->instance_address = uwsgi.p[ucr->code_string_modifier1]->code_string(name, ucr->code_string_code, ucr->code_string_function, cr_session->hostname, cr_session->hostname_len);
		free(name);
		if (cr_session->instance_address) {
			cr_session->instance_address_len = strlen(cr_session->instance_address);
			char *cs_mod = uwsgi_str_contains(cr_session->instance_address, cr_session->instance_address_len, ',');
			if (cs_mod) {
				cr_session->modifier1 = uwsgi_str_num(cs_mod + 1, (cr_session->instance_address_len - (cs_mod - cr_session->instance_address)) - 1);
				cr_session->instance_address_len = (cs_mod - cr_session->instance_address);
			}
		}
	}
	return 0;
}

int uwsgi_cr_map_use_to(struct uwsgi_corerouter *ucr, struct corerouter_session *cr_session) {
	cr_session->instance_address = ucr->to_socket->name;
	cr_session->instance_address_len = ucr->to_socket->name_len;
	return 0;
}

int uwsgi_cr_map_use_cluster(struct uwsgi_corerouter *ucr, struct corerouter_session *cr_session) {
#ifdef UWSGI_MULTICAST
        cr_session->instance_address = uwsgi_cluster_best_node();
	if (cr_session->instance_address) {
        	cr_session->instance_address_len = strlen(cr_session->instance_address);
	}
#else
	uwsgi_log("uWSGI has been built without multicast/clustering support !!!\n");
#endif
        return 0;
}


int uwsgi_cr_map_use_static_nodes(struct uwsgi_corerouter *ucr, struct corerouter_session *cr_session) {
		if (!ucr->current_static_node) {
			ucr->current_static_node = ucr->static_nodes;
		}

		cr_session->static_node = ucr->current_static_node;

		// is it a dead node ?
		if (cr_session->static_node->custom > 0) {

			// gracetime passed ?
			if (cr_session->static_node->custom + ucr->static_node_gracetime <= (uint64_t) uwsgi_now()) {
				cr_session->static_node->custom = 0;
			}
			else {
				struct uwsgi_string_list *tmp_node = cr_session->static_node;
				struct uwsgi_string_list *next_node = cr_session->static_node->next;
				cr_session->static_node = NULL;
				// needed for 1-node only setups
				if (!next_node)
					next_node = ucr->static_nodes;

					while (tmp_node != next_node) {
						if (!next_node) {
							next_node = ucr->static_nodes;
						}

						if (tmp_node == next_node)
							break;

						if (next_node->custom == 0) {
							cr_session->static_node = next_node;
							break;
						}
						next_node = next_node->next;
					}
				}
			}

			if (cr_session->static_node) {

				cr_session->instance_address = cr_session->static_node->value;
				cr_session->instance_address_len = cr_session->static_node->len;
				// set the next one
				ucr->current_static_node = cr_session->static_node->next;
			}
			else {
				// set the next one
				ucr->current_static_node = ucr->current_static_node->next;
			}
	
	return 0;

}
