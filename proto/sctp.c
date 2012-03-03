/* async uwsgi protocol parser */

#include "../uwsgi.h"

extern struct uwsgi_server uwsgi;

int uwsgi_proto_sctp_parser(struct wsgi_request *wsgi_req) {

	struct sctp_sndrcvinfo sinfo;
	int msg_flags;

	ssize_t len = sctp_recvmsg(wsgi_req->socket->fd, wsgi_req->buffer, uwsgi.buffer_size, NULL, NULL, &sinfo, &msg_flags);

	if (len < 0) {
		uwsgi_error("sctp_recvmsg()");
		if (msg_flags == 0) {
			// connection lost, retrigger it
			close(wsgi_req->socket->fd);
			wsgi_req->socket->fd = connect_to_sctp(wsgi_req->socket->name, wsgi_req->socket->queue);
		}
		return -1;
	}
	else if (len == 0) {
		uwsgi_log("lost connection with the SCTP server\n");
		// connection lost, retrigger it
		close(wsgi_req->socket->fd);
		wsgi_req->socket->fd = connect_to_sctp(wsgi_req->socket->name, wsgi_req->socket->queue);
		return -2;
	}

	// check for a request stream
	if (sinfo.sinfo_stream != 0) {
		uwsgi_log("invalid SCTP stream id (must be 0)\n");
		return -1;
	}

	memcpy(&wsgi_req->uh, &sinfo.sinfo_ppid, sizeof(uint32_t));
	
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

	return UWSGI_OK;

}

ssize_t uwsgi_proto_sctp_writev_header(struct wsgi_request * wsgi_req, struct iovec * iovec, size_t iov_len) {
	ssize_t wlen = writev(wsgi_req->poll.fd, iovec, iov_len);
	if (wlen < 0) {
		uwsgi_req_error("writev()");
		return 0;
	}
	return wlen;
}

ssize_t uwsgi_proto_sctp_writev(struct wsgi_request * wsgi_req, struct iovec * iovec, size_t iov_len) {
	ssize_t wlen = writev(wsgi_req->poll.fd, iovec, iov_len);
	if (wlen < 0) {
		uwsgi_req_error("writev()");
		return 0;
	}
	return wlen;
}

ssize_t uwsgi_proto_sctp_write(struct wsgi_request * wsgi_req, char *buf, size_t len) {
	ssize_t wlen = write(wsgi_req->poll.fd, buf, len);
	if (wlen < 0) {
		uwsgi_req_error("write()");
		return 0;
	}
	return wlen;
}

ssize_t uwsgi_proto_sctp_write_header(struct wsgi_request * wsgi_req, char *buf, size_t len) {
	ssize_t wlen = write(wsgi_req->poll.fd, buf, len);
	if (wlen < 0) {
		uwsgi_req_error("write()");
		return 0;
	}
	return wlen;
}

// accept on persistent connections is a noop
int uwsgi_proto_sctp_accept(struct wsgi_request *wsgi_req, int fd) {
	return wsgi_req->socket->fd;
}

void uwsgi_proto_sctp_close(struct wsgi_request *wsgi_req) {

	struct sctp_sndrcvinfo sinfo;
        memset(&sinfo, 0, sizeof(struct sctp_sndrcvinfo));
	// stream 2 is used for closing requests
        sinfo.sinfo_stream = 2;
        memcpy(&sinfo.sinfo_ppid, &wsgi_req->uh, sizeof(uint32_t));

        if (wsgi_req->async_post) {
                fclose(wsgi_req->async_post);
        }
	sctp_send(wsgi_req->poll.fd, &wsgi_req->uh , sizeof(uint32_t), &sinfo, 0);
}

