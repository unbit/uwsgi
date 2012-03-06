#ifdef UWSGI_SCTP

#include "../../uwsgi.h"

#include "fr.h"

extern struct uwsgi_fastrouter ufr;

struct uwsgi_fr_sctp_node **uwsgi_fastrouter_sctp_nodes;
struct uwsgi_fr_sctp_node **uwsgi_fastrouter_sctp_nodes_current;

struct uwsgi_fr_sctp_node *uwsgi_fr_sctp_add_node(int fd) {

        struct uwsgi_fr_sctp_node *ufsn = *uwsgi_fastrouter_sctp_nodes;

        if (!ufsn) {
                *uwsgi_fastrouter_sctp_nodes = uwsgi_malloc(sizeof(struct uwsgi_fr_sctp_node));
                (*uwsgi_fastrouter_sctp_nodes)->next = *uwsgi_fastrouter_sctp_nodes;
                (*uwsgi_fastrouter_sctp_nodes)->prev = *uwsgi_fastrouter_sctp_nodes;
                (*uwsgi_fastrouter_sctp_nodes)->requests = 0;
                (*uwsgi_fastrouter_sctp_nodes)->fd = fd;

		*uwsgi_fastrouter_sctp_nodes_current = *uwsgi_fastrouter_sctp_nodes;

        }
        else {
                while(ufsn) {
                        if (ufsn->next == *uwsgi_fastrouter_sctp_nodes) {
                                break;
                        }
                        ufsn = ufsn->next;
                }

                ufsn->next = uwsgi_malloc(sizeof(struct uwsgi_fr_sctp_node));
                ufsn->next->next = *uwsgi_fastrouter_sctp_nodes;
                ufsn->next->prev = ufsn;
                ufsn->next->requests = 0;
                ufsn->next->fd = fd;

		(*uwsgi_fastrouter_sctp_nodes)->prev = ufsn->next;
		*uwsgi_fastrouter_sctp_nodes_current = ufsn->next;

        }

        return *uwsgi_fastrouter_sctp_nodes_current;

}

void uwsgi_fr_sctp_del_node(int fd) {

	struct uwsgi_fr_sctp_node *ufsn = *uwsgi_fastrouter_sctp_nodes;
	while(ufsn) {
	
		if (ufsn->fd == fd) {

			struct uwsgi_fr_sctp_node *prev = ufsn->prev;
			struct uwsgi_fr_sctp_node *next = ufsn->next;

			// am i the only node ?
			if (prev == ufsn) {
				free(ufsn);	
				*uwsgi_fastrouter_sctp_nodes = NULL;
				*uwsgi_fastrouter_sctp_nodes_current = NULL;
				break;
			}

			prev->next = next;
			next->prev = prev;

			// am i the first node ?
			if (ufsn == *uwsgi_fastrouter_sctp_nodes) {
				*uwsgi_fastrouter_sctp_nodes = next;
				*uwsgi_fastrouter_sctp_nodes_current = next;
				free(ufsn);
				break;
			}

			if (*uwsgi_fastrouter_sctp_nodes_current == ufsn) {
				*uwsgi_fastrouter_sctp_nodes_current = *uwsgi_fastrouter_sctp_nodes;
			}

			free(ufsn);
			break;
		}

		if (ufsn->next == *uwsgi_fastrouter_sctp_nodes) {
			break;
		}

		ufsn = ufsn->next;
	}

}

void uwsgi_opt_fastrouter_sctp(char *opt, char *value, void *foobar) {

        struct uwsgi_gateway_socket *ugs = uwsgi_new_gateway_socket(value, "uWSGI fastrouter");
        ugs->sctp = 1;
        ufr.has_sctp_sockets++;

}
#endif

