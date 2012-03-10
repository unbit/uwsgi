#include "../../uwsgi.h"

#include "fr.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_fastrouter ufr;

#ifdef UWSGI_SCTP
extern struct uwsgi_fr_sctp_node **uwsgi_fastrouter_sctp_nodes;
extern struct uwsgi_fr_sctp_node **uwsgi_fastrouter_sctp_nodes_current;
#endif


int uwsgi_fr_map_use_void(struct fastrouter_session *fr_session, char **magic_table) {
	return 0;
}

int uwsgi_fr_map_use_cache(struct fastrouter_session *fr_session, char **magic_table) {
	fr_session->instance_address = uwsgi_cache_get(fr_session->hostname, fr_session->hostname_len, &fr_session->instance_address_len);
	char *cs_mod = uwsgi_str_contains(fr_session->instance_address, fr_session->instance_address_len, ',');
	if (cs_mod) {
		fr_session->modifier1 = uwsgi_str_num(cs_mod + 1, (fr_session->instance_address_len - (cs_mod - fr_session->instance_address)) - 1);
		fr_session->instance_address_len = (cs_mod - fr_session->instance_address);
	}
	return 0;
}

int uwsgi_fr_map_use_pattern(struct fastrouter_session *fr_session, char **magic_table) {
	int tmp_socket_name_len = 0;
	magic_table['s'] = uwsgi_concat2n(fr_session->hostname, fr_session->hostname_len, "", 0);
	fr_session->tmp_socket_name = magic_sub(ufr.pattern, ufr.pattern_len, &tmp_socket_name_len, magic_table);
	free(magic_table['s']);
	fr_session->instance_address_len = tmp_socket_name_len;
	fr_session->instance_address = fr_session->tmp_socket_name;
	return 0;
}


int uwsgi_fr_map_use_subscription(struct fastrouter_session *fr_session, char **magic_table) {

	fr_session->un = uwsgi_get_subscribe_node(&ufr.subscriptions, fr_session->hostname, fr_session->hostname_len, ufr.subscription_regexp);
	if (fr_session->un && fr_session->un->len) {
		fr_session->instance_address = fr_session->un->name;
		fr_session->instance_address_len = fr_session->un->len;
		fr_session->modifier1 = fr_session->un->modifier1;
	}
	else if (ufr.subscriptions == NULL && ufr.cheap && !ufr.i_am_cheap) {
		uwsgi_gateway_go_cheap("uWSGI fastrouter", ufr.queue, &ufr.i_am_cheap);
	}

	return 0;
}

int uwsgi_fr_map_use_base(struct fastrouter_session *fr_session, char **magic_table) {

	int tmp_socket_name_len = 0;

	fr_session->tmp_socket_name = uwsgi_concat2nn(ufr.base, ufr.base_len, fr_session->hostname, fr_session->hostname_len, &tmp_socket_name_len);
	fr_session->instance_address_len = tmp_socket_name_len;
	fr_session->instance_address = fr_session->tmp_socket_name;
	
	return 0;
}


int uwsgi_fr_map_use_cs(struct fastrouter_session *fr_session, char **magic_table) {
	if (uwsgi.p[ufr.code_string_modifier1]->code_string) {
		fr_session->instance_address = uwsgi.p[ufr.code_string_modifier1]->code_string("uwsgi_fastrouter", ufr.code_string_code, ufr.code_string_function, fr_session->hostname, fr_session->hostname_len);
		if (fr_session->instance_address) {
			fr_session->instance_address_len = strlen(fr_session->instance_address);
			char *cs_mod = uwsgi_str_contains(fr_session->instance_address, fr_session->instance_address_len, ',');
			if (cs_mod) {
				fr_session->modifier1 = uwsgi_str_num(cs_mod + 1, (fr_session->instance_address_len - (cs_mod - fr_session->instance_address)) - 1);
				fr_session->instance_address_len = (cs_mod - fr_session->instance_address);
			}
		}
	}
	return 0;
}

int uwsgi_fr_map_use_to(struct fastrouter_session *fr_session, char **magic_table) {
	fr_session->instance_address = ufr.to_socket->name;
	fr_session->instance_address_len = ufr.to_socket->name_len;
	return 0;
}

int uwsgi_fr_map_use_static_nodes(struct fastrouter_session *fr_session, char **magic_table) {
		if (!ufr.current_static_node) {
			ufr.current_static_node = ufr.static_nodes;
		}

		fr_session->static_node = ufr.current_static_node;

		// is it a dead node ?
		if (fr_session->static_node->custom > 0) {

			// gracetime passed ?
			if (fr_session->static_node->custom + ufr.static_node_gracetime <= (uint64_t) uwsgi_now()) {
				fr_session->static_node->custom = 0;
			}
			else {
				struct uwsgi_string_list *tmp_node = fr_session->static_node;
				struct uwsgi_string_list *next_node = fr_session->static_node->next;
				fr_session->static_node = NULL;
				// needed for 1-node only setups
				if (!next_node)
					next_node = ufr.static_nodes;

					while (tmp_node != next_node) {
						if (!next_node) {
							next_node = ufr.static_nodes;
						}

						if (tmp_node == next_node)
							break;

						if (next_node->custom == 0) {
							fr_session->static_node = next_node;
							break;
						}
						next_node = next_node->next;
					}
				}
			}

			if (fr_session->static_node) {

				fr_session->instance_address = fr_session->static_node->value;
				fr_session->instance_address_len = fr_session->static_node->len;
				// set the next one
				ufr.current_static_node = fr_session->static_node->next;
			}
			else {
				// set the next one
				ufr.current_static_node = ufr.current_static_node->next;
			}
	
	return 0;

}

#ifdef UWSGI_SCTP

int uwsgi_fr_map_use_sctp(struct fastrouter_session *fr_session, char **magic_table) {	

	if (!*uwsgi_fastrouter_sctp_nodes_current)
		*uwsgi_fastrouter_sctp_nodes_current = *uwsgi_fastrouter_sctp_nodes;

	struct uwsgi_fr_sctp_node *ufsn = *uwsgi_fastrouter_sctp_nodes_current;
	int choosen_fd = -1;
	// find the first available server
	while (ufsn) {
		if (ufr.fr_table[ufsn->fd]->status == FASTROUTER_STATUS_SCTP_NODE_FREE) {
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
		fr_session->retry = 1;
		del_timeout(fr_session);
		fr_session->timeout = add_fake_timeout(fr_session);
		return -1;
	}

	struct sctp_sndrcvinfo sinfo;
	memset(&sinfo, 0, sizeof(struct sctp_sndrcvinfo));
	memcpy(&sinfo.sinfo_ppid, &fr_session->uh, sizeof(uint32_t));
	sinfo.sinfo_stream = fr_session->fd;
	ssize_t len = sctp_send(choosen_fd, fr_session->buffer, fr_session->uh.pktsize, &sinfo, 0);
	if (len < 0)
		uwsgi_error("sctp_send()");

	fr_session->instance_fd = choosen_fd;
	fr_session->status = FASTROUTER_STATUS_SCTP_RESPONSE;
	ufr.fr_table[fr_session->instance_fd]->status = FASTROUTER_STATUS_SCTP_RESPONSE;
	ufr.fr_table[fr_session->instance_fd]->fd = fr_session->fd;

	// round robin
	*uwsgi_fastrouter_sctp_nodes_current = (*uwsgi_fastrouter_sctp_nodes_current)->next;
	return -1;
}
#endif
