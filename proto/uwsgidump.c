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
			uwsgi_error("read()");
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

			uwsgi_debug("uwsgi payload size: %d (0x%X) modifier1: %d modifier2: %d\n", wsgi_req->uh.pktsize, wsgi_req->uh.pktsize, wsgi_req->uh.modifier1, wsgi_req->uh.modifier2);

			/* check for max buffer size */
			if (wsgi_req->uh.pktsize > uwsgi.buffer_size) {
				uwsgi_log("invalid request block size. requested %d bytes available %d bytes...skip\n", wsgi_req->uh.pktsize, uwsgi.buffer_size);
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

			cmsg = CMSG_FIRSTHDR(&wsgi_req->msg);
			while (cmsg != NULL) {
				if (cmsg->cmsg_len == CMSG_LEN(sizeof(int)) && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type && SCM_RIGHTS) {

					// upgrade connection to the new socket
					uwsgi_log("upgrading fd %d to ", wsgi_req->poll.fd);

					close(wsgi_req->poll.fd);
					memcpy(&wsgi_req->poll.fd, CMSG_DATA(cmsg), sizeof(int));

					uwsgi_log("%d\n", wsgi_req->poll.fd);
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
