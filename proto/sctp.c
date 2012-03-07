/* async uwsgi protocol parser */

#include "../uwsgi.h"

extern struct uwsgi_server uwsgi;

#if defined(__linux__) || defined(__sun__)
ssize_t sctp_sendv(int s, struct iovec *iov, size_t iov_len,
          const struct sctp_sndrcvinfo *sinfo, int flags)
{
        struct msghdr outmsg;

        outmsg.msg_name = NULL;
        outmsg.msg_namelen = 0;
        outmsg.msg_iov = iov;
        outmsg.msg_iovlen = iov_len;
        outmsg.msg_controllen = 0;

        if (sinfo) {
                char outcmsg[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
                struct cmsghdr *cmsg;

                outmsg.msg_control = outcmsg;
                outmsg.msg_controllen = sizeof(outcmsg);
                outmsg.msg_flags = 0;

                cmsg = CMSG_FIRSTHDR(&outmsg);
                cmsg->cmsg_level = IPPROTO_SCTP;
                cmsg->cmsg_type = SCTP_SNDRCV;
                cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));

                outmsg.msg_controllen = cmsg->cmsg_len;
                memcpy(CMSG_DATA(cmsg), sinfo, sizeof(struct sctp_sndrcvinfo));
        }

        return sendmsg(s, &outmsg, flags);
}

#endif

int uwsgi_proto_sctp_parser(struct wsgi_request *wsgi_req) {

	struct sctp_sndrcvinfo sinfo;
	memset(&sinfo, 0, sizeof(sinfo));
	int msg_flags = 0;

	ssize_t len = sctp_recvmsg(wsgi_req->socket->fd, wsgi_req->buffer, uwsgi.buffer_size, NULL, NULL, &sinfo, &msg_flags);

	if (len <= 0) {
		if (len < 0)
			uwsgi_error("sctp_recvmsg()");
		uwsgi_log("lost connection with the SCTP server %d\n", msg_flags);
		// connection lost, retrigger it
		close(wsgi_req->socket->fd);
		wsgi_req->socket->fd = connect_to_sctp(wsgi_req->socket->name, wsgi_req->socket->queue);
		// avoid closing connection
		wsgi_req->fd_closed = 1;
		// no special message needed
		return -3;
	}

	// get the uwsgi 4 bytes header from ppid
	memcpy(&wsgi_req->uh, &sinfo.sinfo_ppid, sizeof(uint32_t));

	// check for invalid modifiers
	if (wsgi_req->uh.modifier1 == 199 || wsgi_req->uh.modifier1 == 200) {
		uwsgi_log("invalid SCTP uwsgi modifier1: %d\n", wsgi_req->uh.modifier1);
		return -1;
	}

	wsgi_req->stream_id = sinfo.sinfo_stream;
	
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
	struct sctp_sndrcvinfo sinfo;
        memset(&sinfo, 0, sizeof(struct sctp_sndrcvinfo));
	sinfo.sinfo_stream = wsgi_req->stream_id;

        ssize_t wlen = sctp_sendv(wsgi_req->poll.fd, iovec, iov_len, &sinfo, 0);
        if (wlen < 0) {
                uwsgi_req_error("writev()");
                return 0;
        }
        return wlen;
}

ssize_t uwsgi_proto_sctp_writev(struct wsgi_request * wsgi_req, struct iovec * iovec, size_t iov_len) {
	struct sctp_sndrcvinfo sinfo;
        memset(&sinfo, 0, sizeof(struct sctp_sndrcvinfo));
	sinfo.sinfo_stream = wsgi_req->stream_id;

        ssize_t wlen = sctp_sendv(wsgi_req->poll.fd, iovec, iov_len, &sinfo, 0);
        if (wlen < 0) {
                uwsgi_req_error("writev()");
                return 0;
        }
        return wlen;
}

ssize_t uwsgi_proto_sctp_write(struct wsgi_request * wsgi_req, char *buf, size_t len) {
	struct sctp_sndrcvinfo sinfo;
        memset(&sinfo, 0, sizeof(struct sctp_sndrcvinfo));
	sinfo.sinfo_stream = wsgi_req->stream_id;

        ssize_t wlen = sctp_send(wsgi_req->poll.fd, buf, len, &sinfo, 0);
	if (wlen < 0) {
		uwsgi_req_error("write()");
		return 0;
	}
	return wlen;
}

ssize_t uwsgi_proto_sctp_write_header(struct wsgi_request * wsgi_req, char *buf, size_t len) {
	struct sctp_sndrcvinfo sinfo;
        memset(&sinfo, 0, sizeof(struct sctp_sndrcvinfo));
	sinfo.sinfo_stream = wsgi_req->stream_id;

	ssize_t wlen = sctp_send(wsgi_req->poll.fd, buf, len, &sinfo, 0);
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

	// this function could be called in uwsgi_destroy_request too
	if (wsgi_req->fd_closed) return;

	struct uwsgi_header uh;
	// ppid->modifier1 200 is used for closing requests
	uh.modifier1 = 200;
	uh.pktsize = 0;
	uh.modifier2 = 0;

	struct sctp_sndrcvinfo sinfo;
        memset(&sinfo, 0, sizeof(struct sctp_sndrcvinfo));
        memcpy(&sinfo.sinfo_ppid, &uh, sizeof(uint32_t));
	sinfo.sinfo_stream = wsgi_req->stream_id;

        if (wsgi_req->async_post) {
                fclose(wsgi_req->async_post);
        }

	sctp_send(wsgi_req->poll.fd, &uh, sizeof(uh), &sinfo, 0);
}

ssize_t uwsgi_proto_sctp_sendfile(struct wsgi_request * wsgi_req) {

        ssize_t len;
        char buf[65536];
        size_t remains = wsgi_req->sendfile_fd_size - wsgi_req->sendfile_fd_pos;

        wsgi_req->sendfile_fd_chunk = 65536;

        if (uwsgi.async > 1) {
                len = read(wsgi_req->sendfile_fd, buf, UMIN(remains, wsgi_req->sendfile_fd_chunk));
                if (len != (int) UMIN(remains, wsgi_req->sendfile_fd_chunk)) {
                        uwsgi_error("read()");
                        return -1;
                }
                wsgi_req->sendfile_fd_pos += len;
                return uwsgi_proto_sctp_write(wsgi_req, buf, len);
        }

        while (remains) {
                len = read(wsgi_req->sendfile_fd, buf, UMIN(remains, wsgi_req->sendfile_fd_chunk));
                if (len != (int) UMIN(remains, wsgi_req->sendfile_fd_chunk)) {
                        uwsgi_error("read()");
                        return -1;
                }
                wsgi_req->sendfile_fd_pos += len;
                len = uwsgi_proto_sctp_write(wsgi_req, buf, len);
                remains = wsgi_req->sendfile_fd_size - wsgi_req->sendfile_fd_pos;
        }

        return wsgi_req->sendfile_fd_pos;

}

ssize_t uwsgi_proto_sctp_read_body(struct wsgi_request * wsgi_req, char *buf, size_t len) {

	struct sctp_sndrcvinfo sinfo;
        memset(&sinfo, 0, sizeof(sinfo));
	int msg_flags = 0;
	struct uwsgi_header *uh;

	ssize_t slen = sctp_recvmsg(wsgi_req->socket->fd, buf, len, NULL, NULL, &sinfo, &msg_flags);

	if (slen <= 0) {
		return -1;
	}

	if (wsgi_req->stream_id != sinfo.sinfo_stream) {
		return -1;
	}

	uh = (struct uwsgi_header *) &sinfo.sinfo_ppid;

	if (uh->modifier1 != 199) {
		return -1;
	}

	return slen;
	
}

