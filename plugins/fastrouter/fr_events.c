#include "../../uwsgi.h"

#include "fr.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_fastrouter ufr;

void fr_get_hostname(char *key, uint16_t keylen, char *val, uint16_t vallen, void *data) {
	
		// here i use directly corerouter_session
	        struct corerouter_session *fr_session = (struct corerouter_session *) data;
	
	        //uwsgi_log("%.*s = %.*s\n", keylen, key, vallen, val);
	        if (!uwsgi_strncmp("SERVER_NAME", 11, key, keylen) && !fr_session->hostname_len) {
	                fr_session->hostname = val;
	                fr_session->hostname_len = vallen;
	                return;
	        }

	        if (!uwsgi_strncmp("HTTP_HOST", 9, key, keylen) && !fr_session->has_key) {
	                fr_session->hostname = val;
	                fr_session->hostname_len = vallen;
	                return;
	        }
	
	        if (!uwsgi_strncmp("UWSGI_FASTROUTER_KEY", 20, key, keylen)) {
	                fr_session->has_key = 1;
	                fr_session->hostname = val;
	                fr_session->hostname_len = vallen;
	                return;
	        }

	        if (ufr.cr.post_buffering > 0) {
	                if (!uwsgi_strncmp("CONTENT_LENGTH", 14, key, keylen)) {
	                        fr_session->post_cl = uwsgi_str_num(val, vallen);
	                        return;
	                }
	        }
	}

void uwsgi_fastrouter_switch_events(struct uwsgi_corerouter *ucr, struct corerouter_session *cs, int interesting_fd) {

	struct fastrouter_session *fr_session = (struct fastrouter_session *) cs;

	socklen_t solen = sizeof(int);
	struct iovec iov[2];

	struct msghdr msg;
	union {
		struct cmsghdr cmsg;
		char control[CMSG_SPACE(sizeof(int))];
	} msg_control;
	struct cmsghdr *cmsg;

	ssize_t len;
	char *post_tmp_buf[UMAX16];

	switch (cs->status) {

	case COREROUTER_STATUS_RECV_HDR:
		len = recv(cs->fd, (char *) (&fr_session->uh) + cs->h_pos, 4 - cs->h_pos, 0);
#ifdef UWSGI_EVENT_USE_PORT
                event_queue_add_fd_read(ucr->queue, cs->fd);
#endif
		if (len <= 0) {
			if (len < 0)
				uwsgi_error("recv()");
			corerouter_close_session(ucr, cs);
			break;
		}
		cs->h_pos += len;
		if (cs->h_pos == 4) {
#ifdef UWSGI_DEBUG
			uwsgi_log("modifier1: %d pktsize: %d modifier2: %d\n", fr_session->uh.modifier1, fr_session->uh.pktsize, fr_session->uh.modifier2);
#endif
			cs->status = FASTROUTER_STATUS_RECV_VARS;
		}
		break;


	case FASTROUTER_STATUS_RECV_VARS:

		if (interesting_fd == -1) {
			goto choose_node;
		}

		len = recv(cs->fd, fr_session->buffer + cs->pos, fr_session->uh.pktsize - cs->pos, 0);
#ifdef UWSGI_EVENT_USE_PORT
                event_queue_add_fd_read(ucr->queue, cs->fd);
#endif
		if (len <= 0) {
			uwsgi_error("recv()");
			corerouter_close_session(ucr, cs);
			break;
		}
		cs->pos += len;
		if (cs->pos == fr_session->uh.pktsize) {
			if (uwsgi_hooked_parse(fr_session->buffer, fr_session->uh.pktsize, fr_get_hostname, (void *) fr_session)) {
				corerouter_close_session(ucr, cs);
				break;
			}

			if (cs->hostname_len == 0) {
				corerouter_close_session(ucr, cs);
				break;
			}


			// the mapper hook
choose_node:
			if (ucr->mapper(ucr, cs))
				break;

			// no address found
			if (!cs->instance_address_len) {
				// if fallback nodes are configured, trigger them
				if (ucr->fallback) {
					cs->instance_failed = 1;
				}
				corerouter_close_session(ucr, cs);
				break;
			}

			if (ucr->post_buffering > 0 && cs->post_cl > ucr->post_buffering) {
				cs->status = FASTROUTER_STATUS_BUFFERING;
				cs->buf_file_name = uwsgi_tmpname(ucr->pb_base_dir, "uwsgiXXXXX");
				if (!cs->buf_file_name) {
					uwsgi_error("tempnam()");
					corerouter_close_session(ucr, cs);
					break;
				}
				cs->post_remains = cs->post_cl;

				// 2 + UWSGI_POSTFILE + 2 + cs->buf_file_name
				if (fr_session->uh.pktsize + (2 + 14 + 2 + strlen(cs->buf_file_name)) > UMAX16) {
					uwsgi_log("unable to buffer request body to file %s: not enough space\n", cs->buf_file_name);
					corerouter_close_session(ucr, cs);
					break;
				}

				char *ptr = fr_session->buffer + fr_session->uh.pktsize;
				uint16_t bfn_len = strlen(cs->buf_file_name);
				*ptr++ = 14;
				*ptr++ = 0;
				memcpy(ptr, "UWSGI_POSTFILE", 14);
				ptr += 14;
				*ptr++ = (char) (bfn_len & 0xff);
				*ptr++ = (char) ((bfn_len >> 8) & 0xff);
				memcpy(ptr, cs->buf_file_name, bfn_len);
				fr_session->uh.pktsize += 2 + 14 + 2 + bfn_len;


				cs->buf_file = fopen(cs->buf_file_name, "w");
				if (!cs->buf_file) {
					uwsgi_error_open(cs->buf_file_name);
					corerouter_close_session(ucr, cs);
					break;
				}

			}

			else {

				cs->pass_fd = is_unix(cs->instance_address, cs->instance_address_len);

				cs->instance_fd = uwsgi_connectn(cs->instance_address, cs->instance_address_len, 0, 1);

				if (cs->instance_fd < 0) {
					cs->instance_failed = 1;
					cs->soopt = errno;
					corerouter_close_session(ucr, cs);
					break;
				}


				cs->status = COREROUTER_STATUS_CONNECTING;
				ucr->cr_table[cs->instance_fd] = cs;
				event_queue_add_fd_write(ucr->queue, cs->instance_fd);
			}
		}
		break;



	case COREROUTER_STATUS_CONNECTING:

		if (interesting_fd == cs->instance_fd) {

			if (getsockopt(cs->instance_fd, SOL_SOCKET, SO_ERROR, (void *) (&cs->soopt), &solen) < 0) {
				uwsgi_error("getsockopt()");
				cs->instance_failed = 1;
				corerouter_close_session(ucr, cs);
				break;
			}

			if (cs->soopt) {
				cs->instance_failed = 1;
				corerouter_close_session(ucr, cs);
				break;
			}

			fr_session->uh.modifier1 = cs->modifier1;

			iov[0].iov_base = &fr_session->uh;
			iov[0].iov_len = 4;
			iov[1].iov_base = fr_session->buffer;
			iov[1].iov_len = fr_session->uh.pktsize;

			// increment node requests counter
			if (cs->un)
				cs->un->requests++;

			// fd passing: PERFORMANCE EXTREME BOOST !!!
			if (cs->pass_fd && !uwsgi.no_fd_passing) {
				msg.msg_name = NULL;
				msg.msg_namelen = 0;
				msg.msg_iov = iov;
				msg.msg_iovlen = 2;
				msg.msg_flags = 0;
				msg.msg_control = &msg_control;
				msg.msg_controllen = sizeof(msg_control);

				cmsg = CMSG_FIRSTHDR(&msg);
				cmsg->cmsg_len = CMSG_LEN(sizeof(int));
				cmsg->cmsg_level = SOL_SOCKET;
				cmsg->cmsg_type = SCM_RIGHTS;

				memcpy(CMSG_DATA(cmsg), &cs->fd, sizeof(int));

				if (sendmsg(cs->instance_fd, &msg, 0) < 0) {
					uwsgi_error("sendmsg()");
				}

				corerouter_close_session(ucr, cs);
				break;
			}

			if (writev(cs->instance_fd, iov, 2) < 0) {
				uwsgi_error("writev()");
				corerouter_close_session(ucr, cs);
				break;
			}

			event_queue_fd_write_to_read(ucr->queue, cs->instance_fd);
			cs->status = COREROUTER_STATUS_RESPONSE;
		}

		break;
	case COREROUTER_STATUS_RESPONSE:

		// data from instance
		if (interesting_fd == cs->instance_fd) {
			len = recv(cs->instance_fd, fr_session->buffer, UMAX16, 0);
#ifdef UWSGI_EVENT_USE_PORT
                        event_queue_add_fd_read(ucr->queue, cs->instance_fd);
#endif
			if (len <= 0) {
				if (len < 0)
					uwsgi_error("recv()");
				corerouter_close_session(ucr, cs);
				break;
			}

			len = send(cs->fd, fr_session->buffer, len, 0);

			if (len <= 0) {
				if (len < 0)
					uwsgi_error("send()");
				corerouter_close_session(ucr, cs);
				break;
			}

			if (cs->un) {
				// update transfer statistics
				cs->un->transferred += len;

				// update node rpm
				time_t now = uwsgi_now();
				time_t target_ts = now / 60;

				// first check for clock jumps
				if (cs->un->rpm_timecheck == 0 || cs->un->rpm_timecheck > target_ts || (target_ts - cs->un->rpm_timecheck) > 1) {
					// if clock go back or jumps to the future than just reset everything
					cs->un->rpm_timecheck = target_ts;
					cs->un->last_minute_requests = 1;
				} else if (cs->un->rpm_timecheck != target_ts) {
					// clock did not jumped, this is next minute
					cs->un->requests_per_minute = cs->un->last_minute_requests;
					cs->un->rpm_timecheck = target_ts;
					cs->un->last_minute_requests = 1;
				} else {
					cs->un->last_minute_requests++;
				}
			}

		}
		// body from client
		else if (interesting_fd == cs->fd) {

			//uwsgi_log("receiving body...\n");
			len = recv(cs->fd, fr_session->buffer, UMAX16, 0);
#ifdef UWSGI_EVENT_USE_PORT
                        event_queue_add_fd_read(ucr->queue, cs->fd);
#endif
			if (len <= 0) {
				if (len < 0)
					uwsgi_error("recv()");
				corerouter_close_session(ucr, cs);
				break;
			}


			len = send(cs->instance_fd, fr_session->buffer, len, 0);

			if (len <= 0) {
				if (len < 0)
					uwsgi_error("send()");
				corerouter_close_session(ucr, cs);
				break;
			}
		}

		break;

	case FASTROUTER_STATUS_BUFFERING:
		len = recv(cs->fd, post_tmp_buf, UMIN(UMAX16, cs->post_remains), 0);
#ifdef UWSGI_EVENT_USE_PORT
                event_queue_add_fd_read(ucr->queue, cs->fd);
#endif
		if (len <= 0) {
			if (len < 0)
				uwsgi_error("recv()");
			corerouter_close_session(ucr, cs);
			break;
		}

		if (fwrite(post_tmp_buf, len, 1, cs->buf_file) != 1) {
			uwsgi_error("fwrite()");
			corerouter_close_session(ucr, cs);
			break;
		}

		cs->post_remains -= len;

		if (cs->post_remains == 0) {
			// close the buf_file ASAP
			fclose(cs->buf_file);
			cs->buf_file = NULL;

			cs->pass_fd = is_unix(cs->instance_address, cs->instance_address_len);

			cs->instance_fd = uwsgi_connectn(cs->instance_address, cs->instance_address_len, 0, 1);

			if (cs->instance_fd < 0) {
				cs->instance_failed = 1;
				corerouter_close_session(ucr, cs);
				break;
			}

			cs->status = COREROUTER_STATUS_CONNECTING;
			ucr->cr_table[cs->instance_fd] = cs;
			event_queue_add_fd_write(ucr->queue, cs->instance_fd);
		}
		break;




		// fallback to destroy !!!
	default:
		uwsgi_log("unknown event: closing session\n");
		corerouter_close_session(ucr, cs);
		break;

	}
}
