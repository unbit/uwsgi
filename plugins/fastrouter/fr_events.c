#include "../../uwsgi.h"

#include "fr.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_fastrouter ufr;

void uwsgi_fastrouter_switch_events(struct fastrouter_session *fr_session, int interesting_fd, char **magic_table) {

	socklen_t solen = sizeof(int);
	struct iovec iov[2];

	struct msghdr msg;
	union {
		struct cmsghdr cmsg;
		char control[CMSG_SPACE(sizeof(int))];
	} msg_control;
	struct cmsghdr *cmsg;

	ssize_t len;
	char *post_tmp_buf[0xffff];

	switch (fr_session->status) {

	case FASTROUTER_STATUS_RECV_HDR:
		len = recv(fr_session->fd, (char *) (&fr_session->uh) + fr_session->h_pos, 4 - fr_session->h_pos, 0);
		if (len <= 0) {
			if (len < 0)
				uwsgi_error("recv()");
			close_session(fr_session);
			break;
		}
		fr_session->h_pos += len;
		if (fr_session->h_pos == 4) {
#ifdef UWSGI_DEBUG
			uwsgi_log("modifier1: %d pktsize: %d modifier2: %d\n", fr_session->uh.modifier1, fr_session->uh.pktsize, fr_session->uh.modifier2);
#endif
			fr_session->status = FASTROUTER_STATUS_RECV_VARS;
		}
		break;


	case FASTROUTER_STATUS_RECV_VARS:

		if (interesting_fd == -1) {
			goto choose_node;
		}

		len = recv(fr_session->fd, fr_session->buffer + fr_session->pos, fr_session->uh.pktsize - fr_session->pos, 0);
		if (len <= 0) {
			uwsgi_error("recv()");
			close_session(fr_session);
			break;
		}
		fr_session->pos += len;
		if (fr_session->pos == fr_session->uh.pktsize) {
			if (uwsgi_hooked_parse(fr_session->buffer, fr_session->uh.pktsize, fr_get_hostname, (void *) fr_session)) {
				close_session(fr_session);
				break;
			}

			if (fr_session->hostname_len == 0) {
				close_session(fr_session);
				break;
			}

#ifdef UWSGI_DEBUG
			//uwsgi_log("requested domain %.*s\n", fr_session->hostname_len, fr_session->hostname);
#endif

			// the mapper hook
		      choose_node:
			if (ufr.mapper(fr_session, magic_table))
				break;

			// no address found
			if (!fr_session->instance_address_len) {
				// if fallback nodes are configured, trigger them
				if (ufr.fallback) {
					fr_session->instance_failed = 1;
				}
				close_session(fr_session);
				break;
			}

			if (ufr.post_buffering > 0 && fr_session->post_cl > ufr.post_buffering) {
				fr_session->status = FASTROUTER_STATUS_BUFFERING;
				fr_session->buf_file_name = uwsgi_tmpname(ufr.pb_base_dir, "uwsgiXXXXX");
				if (!fr_session->buf_file_name) {
					uwsgi_error("tempnam()");
					close_session(fr_session);
					break;
				}
				fr_session->post_remains = fr_session->post_cl;

				// 2 + UWSGI_POSTFILE + 2 + fr_session->buf_file_name
				if (fr_session->uh.pktsize + (2 + 14 + 2 + strlen(fr_session->buf_file_name)) > 0xffff) {
					uwsgi_log("unable to buffer request body to file %s: not enough space\n", fr_session->buf_file_name);
					close_session(fr_session);
					break;
				}

				char *ptr = fr_session->buffer + fr_session->uh.pktsize;
				uint16_t bfn_len = strlen(fr_session->buf_file_name);
				*ptr++ = 14;
				*ptr++ = 0;
				memcpy(ptr, "UWSGI_POSTFILE", 14);
				ptr += 14;
				*ptr++ = (char) (bfn_len & 0xff);
				*ptr++ = (char) ((bfn_len >> 8) & 0xff);
				memcpy(ptr, fr_session->buf_file_name, bfn_len);
				fr_session->uh.pktsize += 2 + 14 + 2 + bfn_len;


				fr_session->buf_file = fopen(fr_session->buf_file_name, "w");
				if (!fr_session->buf_file) {
					uwsgi_error_open(fr_session->buf_file_name);
					close_session(fr_session);
					break;
				}

			}

			else {

				fr_session->pass_fd = is_unix(fr_session->instance_address, fr_session->instance_address_len);

				fr_session->instance_fd = uwsgi_connectn(fr_session->instance_address, fr_session->instance_address_len, 0, 1);

				if (fr_session->instance_fd < 0) {
					fr_session->instance_failed = 1;
					fr_session->soopt = errno;
					close_session(fr_session);
					break;
				}


				fr_session->status = FASTROUTER_STATUS_CONNECTING;
				ufr.fr_table[fr_session->instance_fd] = fr_session;
				event_queue_add_fd_write(ufr.queue, fr_session->instance_fd);
			}
		}
		break;



	case FASTROUTER_STATUS_CONNECTING:

		if (interesting_fd == fr_session->instance_fd) {

			if (getsockopt(fr_session->instance_fd, SOL_SOCKET, SO_ERROR, (void *) (&fr_session->soopt), &solen) < 0) {
				uwsgi_error("getsockopt()");
				fr_session->instance_failed = 1;
				close_session(fr_session);
				break;
			}

			if (fr_session->soopt) {
				fr_session->instance_failed = 1;
				close_session(fr_session);
				break;
			}

			fr_session->uh.modifier1 = fr_session->modifier1;

			iov[0].iov_base = &fr_session->uh;
			iov[0].iov_len = 4;
			iov[1].iov_base = fr_session->buffer;
			iov[1].iov_len = fr_session->uh.pktsize;

			// increment node requests counter
			if (fr_session->un)
				fr_session->un->requests++;

			// fd passing: PERFORMANCE EXTREME BOOST !!!
			if (fr_session->pass_fd && !uwsgi.no_fd_passing) {
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

				memcpy(CMSG_DATA(cmsg), &fr_session->fd, sizeof(int));

				if (sendmsg(fr_session->instance_fd, &msg, 0) < 0) {
					uwsgi_error("sendmsg()");
				}

				close_session(fr_session);
				break;
			}

			if (writev(fr_session->instance_fd, iov, 2) < 0) {
				uwsgi_error("writev()");
				close_session(fr_session);
				break;
			}

			event_queue_fd_write_to_read(ufr.queue, fr_session->instance_fd);
			fr_session->status = FASTROUTER_STATUS_RESPONSE;
		}

		break;
#ifdef UWSGI_SCTP
	case FASTROUTER_STATUS_SCTP_NODE_FREE:

		{
			struct sctp_sndrcvinfo sinfo;
			int msg_flags = 0;

			memset(&sinfo, 0, sizeof(struct sctp_sndrcvinfo));
			len = sctp_recvmsg(interesting_fd, fr_session->buffer, 0xffff, NULL, NULL, &sinfo, &msg_flags);
			// remove the SCTP node
			uwsgi_log("[0] removing SCTP node %d flags = %d len = %d\n", interesting_fd, msg_flags, len);
			uwsgi_fr_sctp_del_node(interesting_fd);
			if (ufr.fr_table[interesting_fd]->timeout) {
				del_timeout(ufr.fr_table[interesting_fd]);
			}
			free(ufr.fr_table[interesting_fd]);
			ufr.fr_table[interesting_fd] = NULL;
			close(interesting_fd);
		}

		break;
	case FASTROUTER_STATUS_SCTP_RESPONSE:

		// data from instance
		if (interesting_fd == fr_session->instance_fd) {
			struct sctp_sndrcvinfo sinfo;
			struct uwsgi_header *uh;
			int msg_flags = 0;
			memset(&sinfo, 0, sizeof(struct sctp_sndrcvinfo));
			len = sctp_recvmsg(fr_session->instance_fd, fr_session->buffer, 0xffff, NULL, NULL, &sinfo, &msg_flags);
			if (len <= 0) {
				if (len < 0)
					uwsgi_error("recv()");
				close_session(ufr.fr_table[fr_session->fd]);
				// REMOVE THE NODE
				uwsgi_log("[1] removing SCTP node %d flags = %d len = %d\n", interesting_fd, msg_flags, len);
				uwsgi_fr_sctp_del_node(interesting_fd);
				if (ufr.fr_table[interesting_fd]->timeout) {
					del_timeout(ufr.fr_table[interesting_fd]);
				}
				free(ufr.fr_table[interesting_fd]);
				ufr.fr_table[interesting_fd] = NULL;
				close(interesting_fd);
				break;
			}


			if (fr_session->fd != -1 && sinfo.sinfo_stream != fr_session->fd) {
				if (fr_session->fd != -1) {
					uwsgi_log("INVALID SCTP STREAM !!!\n");
					close_session(ufr.fr_table[fr_session->fd]);
				}
				break;
			}

			uh = (struct uwsgi_header *) &sinfo.sinfo_ppid;

			// check for close packet
			if (uh->modifier1 == 200) {
				fr_session->status = FASTROUTER_STATUS_SCTP_NODE_FREE;
				if (fr_session->fd != -1) {
					close_session(ufr.fr_table[fr_session->fd]);
				}
				break;
			}

			if (fr_session->fd == -1) {
				break;		
			}

			len = send(fr_session->fd, fr_session->buffer, len, 0);

			if (len <= 0) {
				if (len < 0)
					uwsgi_error("send()");
				close_session(ufr.fr_table[fr_session->fd]);
				break;
			}

			// update transfer statistics
			if (fr_session->un)
				fr_session->un->transferred += len;

		}
		// body from client
		else if (interesting_fd == fr_session->fd) {

			len = recv(fr_session->fd, fr_session->buffer, 0xffff, 0);
			if (len <= 0) {
				if (len < 0)
					uwsgi_error("recv()");
				// mark session as broken
				ufr.fr_table[fr_session->instance_fd]->fd = -1;
				close_session(fr_session);
				break;
			}

			struct sctp_sndrcvinfo sinfo;
			memset(&sinfo, 0, sizeof(struct sctp_sndrcvinfo));
			// map the stream id to the file descriptor 
			struct uwsgi_header uh;
			uh.modifier1 = 199;
			uh.pktsize = 0;
			uh.modifier2 = 0;
			memcpy(&sinfo.sinfo_ppid, &uh, sizeof(uint32_t));
			sinfo.sinfo_stream = fr_session->fd;

			len = sctp_send(fr_session->instance_fd, fr_session->buffer, len, &sinfo, 0);

			if (len <= 0) {
				if (len < 0)
					uwsgi_error("send()");
				close_session(fr_session);
				break;
			}
		}

		break;
#endif
	case FASTROUTER_STATUS_RESPONSE:

		// data from instance
		if (interesting_fd == fr_session->instance_fd) {
			len = recv(fr_session->instance_fd, fr_session->buffer, 0xffff, 0);
			if (len <= 0) {
				if (len < 0)
					uwsgi_error("recv()");
				close_session(fr_session);
				break;
			}

			len = send(fr_session->fd, fr_session->buffer, len, 0);

			if (len <= 0) {
				if (len < 0)
					uwsgi_error("send()");
				close_session(fr_session);
				break;
			}

			// update transfer statistics
			if (fr_session->un)
				fr_session->un->transferred += len;
		}
		// body from client
		else if (interesting_fd == fr_session->fd) {

			//uwsgi_log("receiving body...\n");
			len = recv(fr_session->fd, fr_session->buffer, 0xffff, 0);
			if (len <= 0) {
				if (len < 0)
					uwsgi_error("recv()");
				close_session(fr_session);
				break;
			}


			len = send(fr_session->instance_fd, fr_session->buffer, len, 0);

			if (len <= 0) {
				if (len < 0)
					uwsgi_error("send()");
				close_session(fr_session);
				break;
			}
		}

		break;

	case FASTROUTER_STATUS_BUFFERING:
		len = recv(fr_session->fd, post_tmp_buf, UMIN(0xffff, fr_session->post_remains), 0);
		if (len <= 0) {
			if (len < 0)
				uwsgi_error("recv()");
			close_session(fr_session);
			break;
		}

		if (fwrite(post_tmp_buf, len, 1, fr_session->buf_file) != 1) {
			uwsgi_error("fwrite()");
			close_session(fr_session);
			break;
		}

		fr_session->post_remains -= len;

		if (fr_session->post_remains == 0) {
			// close the buf_file ASAP
			fclose(fr_session->buf_file);
			fr_session->buf_file = NULL;

			fr_session->pass_fd = is_unix(fr_session->instance_address, fr_session->instance_address_len);

			fr_session->instance_fd = uwsgi_connectn(fr_session->instance_address, fr_session->instance_address_len, 0, 1);

			if (fr_session->instance_fd < 0) {
				fr_session->instance_failed = 1;
				close_session(fr_session);
				break;
			}

			fr_session->status = FASTROUTER_STATUS_CONNECTING;
			ufr.fr_table[fr_session->instance_fd] = fr_session;
			event_queue_add_fd_write(ufr.queue, fr_session->instance_fd);
		}
		break;




		// fallback to destroy !!!
	default:
		uwsgi_log("unknown event: closing session\n");
		close_session(fr_session);
		break;

	}
}
