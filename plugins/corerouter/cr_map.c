#include "../../uwsgi.h"

#include "cr.h"

extern struct uwsgi_server uwsgi;

#ifdef UWSGI_SCTP
extern struct uwsgi_fr_sctp_node **uwsgi_fastrouter_sctp_nodes;
extern struct uwsgi_fr_sctp_node **uwsgi_fastrouter_sctp_nodes_current;
#endif


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

	cr_session->un = uwsgi_get_subscribe_node(&ucr->subscriptions, cr_session->hostname, cr_session->hostname_len, ucr->subscription_regexp);
	if (cr_session->un && cr_session->un->len) {
		cr_session->instance_address = cr_session->un->name;
		cr_session->instance_address_len = cr_session->un->len;
		cr_session->modifier1 = cr_session->un->modifier1;
	}
	else if (ucr->subscriptions == NULL && ucr->cheap && !ucr->i_am_cheap) {
		uwsgi_gateway_go_cheap("uWSGI fastrouter", ucr->queue, &ucr->i_am_cheap);
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
		cr_session->instance_address = uwsgi.p[ucr->code_string_modifier1]->code_string("uwsgi_fastrouter", ucr->code_string_code, ucr->code_string_function, cr_session->hostname, cr_session->hostname_len);
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

#ifdef UWSGI_SCTP

int uwsgi_fr_map_use_sctp(struct fastrouter_session *cr_session, char **magic_table) {	

	if (!*uwsgi_fastrouter_sctp_nodes_current)
		*uwsgi_fastrouter_sctp_nodes_current = *uwsgi_fastrouter_sctp_nodes;

	struct uwsgi_fr_sctp_node *ufsn = *uwsgi_fastrouter_sctp_nodes_current;
	int choosen_fd = -1;
	// find the first available server
	while (ufsn) {
		if (ucr->fr_table[ufsn->fd]->status == FASTROUTER_STATUS_SCTP_NODE_FREE) {
			ufsn->requests++;
			choosen_fd = ufsn->fd;
			break;
		}
		if (ufsn->next == *uwsgi_fastrouter_sctp_nodes_current) {
			break;
		}

		ufsn = ufsn->next;
	}

	// no nodes available
	if (choosen_fd == -1) {
		cr_session->retry = 1;
		del_timeout(cr_session);
		cr_session->timeout = add_fake_timeout(cr_session);
		return -1;
	}

	struct sctp_sndrcvinfo sinfo;
	memset(&sinfo, 0, sizeof(struct sctp_sndrcvinfo));
	memcpy(&sinfo.sinfo_ppid, &cr_session->uh, sizeof(uint32_t));
	sinfo.sinfo_stream = cr_session->fd;
	ssize_t len = sctp_send(choosen_fd, cr_session->buffer, cr_session->uh.pktsize, &sinfo, 0);
	if (len < 0)
		uwsgi_error("sctp_send()");

	cr_session->instance_fd = choosen_fd;
	cr_session->status = FASTROUTER_STATUS_SCTP_RESPONSE;
	ucr->fr_table[cr_session->instance_fd]->status = FASTROUTER_STATUS_SCTP_RESPONSE;
	ucr->fr_table[cr_session->instance_fd]->fd = cr_session->fd;

	// round robin
	*uwsgi_fastrouter_sctp_nodes_current = (*uwsgi_fastrouter_sctp_nodes_current)->next;
	return -1;
}
#endif
