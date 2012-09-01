/* async uwsgi protocol parser */

#include "../uwsgi.h"

extern struct uwsgi_server uwsgi;

#define PROTO_STATUS_RECV_HDR 0
#define PROTO_STATUS_RECV_VARS 1

int uwsgi_proto_uwsgi_parser(struct wsgi_request *wsgi_req) {

	uint8_t *hdr_buf = (uint8_t *) & wsgi_req->uh;
	ssize_t len;

	struct iovec iov[1];
	struct cmsghdr *cmsg;

	if (wsgi_req->proto_parser_status == PROTO_STATUS_RECV_HDR) {


		if (wsgi_req->proto_parser_pos > 0) {
			len = read(wsgi_req->poll.fd, hdr_buf + wsgi_req->proto_parser_pos, 4 - wsgi_req->proto_parser_pos);
		}
		else {
			iov[0].iov_base = hdr_buf;
			iov[0].iov_len = 4;

			wsgi_req->msg.msg_name = NULL;
			wsgi_req->msg.msg_namelen = 0;
			wsgi_req->msg.msg_iov = iov;
			wsgi_req->msg.msg_iovlen = 1;
			wsgi_req->msg.msg_control = &wsgi_req->msg_control;
			wsgi_req->msg.msg_controllen = sizeof(wsgi_req->msg_control);
			wsgi_req->msg.msg_flags = 0;

			len = recvmsg(wsgi_req->poll.fd, &wsgi_req->msg, 0);
		}

		if (len <= 0) {
			// ignore empty packets
			if (len == 0 && wsgi_req->proto_parser_pos == 0) return -3;
			uwsgi_error(wsgi_req->proto_parser_pos > 0 ? "read()" : "recvmsg()");
			return -1;
		}
		wsgi_req->proto_parser_pos += len;
		// header ready ?
		if (wsgi_req->proto_parser_pos == 4) {
			wsgi_req->proto_parser_status = PROTO_STATUS_RECV_VARS;
			wsgi_req->proto_parser_pos = 0;
/* big endian ? */
#ifdef __BIG_ENDIAN__
			wsgi_req->uh.pktsize = uwsgi_swap16(wsgi_req->uh.pktsize);
#endif

#ifdef UWSGI_DEBUG
			uwsgi_debug("uwsgi payload size: %d (0x%X) modifier1: %d modifier2: %d\n", wsgi_req->uh.pktsize, wsgi_req->uh.pktsize, wsgi_req->uh.modifier1, wsgi_req->uh.modifier2);
#endif

			/* check for max buffer size */
			if (wsgi_req->uh.pktsize > uwsgi.buffer_size) {
				uwsgi_log("invalid request block size: %d (max %d)...skip\n", wsgi_req->uh.pktsize, uwsgi.buffer_size);
				return -1;
			}

			if (!wsgi_req->uh.pktsize)
				return UWSGI_OK;

		}
		return UWSGI_AGAIN;
	}

	else if (wsgi_req->proto_parser_status == PROTO_STATUS_RECV_VARS) {
		len = read(wsgi_req->poll.fd, wsgi_req->buffer + wsgi_req->proto_parser_pos, wsgi_req->uh.pktsize - wsgi_req->proto_parser_pos);
		if (len <= 0) {
			uwsgi_error("read()");
			return -1;
		}
		wsgi_req->proto_parser_pos += len;

		// body ready ?
		if (wsgi_req->proto_parser_pos >= wsgi_req->uh.pktsize) {

			// older OSX versions make mess with CMSG_FIRSTHDR
#ifdef __APPLE__
			if (!wsgi_req->msg.msg_controllen)
				return UWSGI_OK;
#endif

			if (uwsgi.no_fd_passing)
				return UWSGI_OK;

			cmsg = CMSG_FIRSTHDR(&wsgi_req->msg);
			while (cmsg != NULL) {
				if (cmsg->cmsg_len == CMSG_LEN(sizeof(int)) && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type && SCM_RIGHTS) {

					// upgrade connection to the new socket
#ifdef UWSGI_DEBUG
					uwsgi_log("upgrading fd %d to ", wsgi_req->poll.fd);
#endif
					close(wsgi_req->poll.fd);
					memcpy(&wsgi_req->poll.fd, CMSG_DATA(cmsg), sizeof(int));
#ifdef UWSGI_DEBUG
					uwsgi_log("%d\n", wsgi_req->poll.fd);
#endif
				}
				cmsg = CMSG_NXTHDR(&wsgi_req->msg, cmsg);
			}

			return UWSGI_OK;
		}
		return UWSGI_AGAIN;
	}

	// never here

	return -1;
}

ssize_t uwsgi_proto_uwsgi_writev_header(struct wsgi_request *wsgi_req, struct iovec * iovec, size_t iov_len) {
	if (iov_len == 0) return 0;
	ssize_t wlen = writev(wsgi_req->poll.fd, iovec, iov_len);
	if (wlen < 0) {
		if (!uwsgi.ignore_write_errors) {
			uwsgi_req_error("writev()");
		}
		wsgi_req->write_errors++;
		return 0;
	}
	return wlen;
}

ssize_t uwsgi_proto_uwsgi_writev(struct wsgi_request *wsgi_req, struct iovec * iovec, size_t iov_len) {
	return uwsgi_proto_uwsgi_writev_header(wsgi_req, iovec, iov_len);
}

ssize_t uwsgi_proto_uwsgi_write(struct wsgi_request * wsgi_req, char *buf, size_t len) {
	ssize_t wlen;
	char *ptr = buf;
	if (len == 0) return 0;

	while(len > 0) {
		wlen = write(wsgi_req->poll.fd, ptr, len);
		if (wlen <= 0) {
			if (!uwsgi.ignore_write_errors) {
				uwsgi_req_error("write()");
			}
			wsgi_req->write_errors++;
			return ptr-buf;
		}
		ptr+=wlen;
		len -= wlen;
	}

	return ptr-buf;
}

ssize_t uwsgi_proto_uwsgi_write_header(struct wsgi_request *wsgi_req, char *buf, size_t len) {
	return uwsgi_proto_uwsgi_write(wsgi_req, buf, len);
}
