#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

ssize_t uwsgi_sendfile(struct wsgi_request * wsgi_req) {

	int fd = wsgi_req->sendfile_fd;
	int sockfd = wsgi_req->poll.fd;
	struct stat stat_buf;
	ssize_t sst = 0;

	if (!wsgi_req->sendfile_fd_size) {

		if (fstat(fd, &stat_buf)) {
			uwsgi_error("fstat()");
			goto end;
		}
		else {
			wsgi_req->sendfile_fd_size = stat_buf.st_size;
		}
	}

	if (wsgi_req->sendfile_fd_size) {

		if (!wsgi_req->sendfile_fd_chunk)
			wsgi_req->sendfile_fd_chunk = 4096;

		if (wsgi_req->socket->proto_sendfile) {
			sst = wsgi_req->socket->proto_sendfile(wsgi_req);
		}
		else {
			sst = uwsgi_do_sendfile(sockfd, wsgi_req->sendfile_fd, wsgi_req->sendfile_fd_size, wsgi_req->sendfile_fd_chunk, &wsgi_req->sendfile_fd_pos, uwsgi.async);
		}

	}

end:
	return sst;
}

ssize_t uwsgi_do_sendfile(int sockfd, int filefd, size_t filesize, size_t chunk, off_t * pos, int async) {

#if defined(__FreeBSD__) || defined(__DragonFly__)

	int sf_ret;

	off_t sf_len = filesize;

	if (async > 1) {
		sf_len = chunk;
		sf_ret = sendfile(filefd, sockfd, *pos, 0, NULL, &sf_len, 0);
		*pos += sf_len;
	}
	else {
		sf_ret = sendfile(filefd, sockfd, 0, 0, NULL, &sf_len, 0);
	}

	if (sf_ret < 0) {
		if (errno != EAGAIN) {
			uwsgi_error("sendfile()");
			return 0;
		}
	}

	return sf_len;
#elif defined(__APPLE__)
	int sf_ret;
	off_t sf_len = filesize;

	if (async > 1) {
		sf_len = chunk;
		sf_ret = sendfile(filefd, sockfd, *pos, &sf_len, NULL, 0);
		*pos += sf_len;
	}
	else {
		sf_ret = sendfile(filefd, sockfd, 0, &sf_len, NULL, 0);
	}

	if (sf_ret) {
#ifdef UWSGI_DEBUG
		uwsgi_log("sf_len = %d\n", sf_len);
#endif
		uwsgi_error("sendfile()");
		return 0;
	}

	return sf_len;

#elif defined(__linux__) || defined(__sun__)
	int sf_ret;
	size_t written = 0;

	if (async > 1) {
		sf_ret = sendfile(sockfd, filefd, pos, chunk);
		if (sf_ret < 0) {
			uwsgi_error("sendfile()");
			return 0;
		}
		return sf_ret;
	}

	while (written < filesize) {
		sf_ret = sendfile(sockfd, filefd, pos, filesize - written);
		if (sf_ret < 0) {
			uwsgi_error("sendfile()");
			return 0;
		}
		else if (sf_ret == 0) {
			return 0;
		}
		written += sf_ret;
	}
	return written;

#else
	static size_t nosf_buf_size = 0;
	static char *nosf_buf;
	char *nosf_buf2;

	ssize_t jlen = 0;
	ssize_t rlen = 0;
	ssize_t i = 0;

	if (!nosf_buf) {
		nosf_buf = malloc(chunk);
	}
	else if (chunk != nosf_buf_size) {
		nosf_buf2 = realloc(nosf_buf, chunk);
		if (!nosf_buf2) {
			free(nosf_buf);
		}
		nosf_buf = nosf_buf2;
	}

	if (!nosf_buf) {
		uwsgi_error("sendfile malloc()/realloc()");
		return 0;
	}

	nosf_buf_size = chunk;

	if (async > 1) {
		jlen = read(filefd, nosf_buf, chunk);
		if (jlen <= 0) {
			uwsgi_error("read()");
			return 0;
		}
		jlen = write(sockfd, nosf_buf, jlen);
		if (jlen <= 0) {
			uwsgi_error("write()");
			return 0;
		}
		return jlen;
	}

	while (i < (int) filesize) {
		jlen = read(filefd, nosf_buf, chunk);
		if (jlen <= 0) {
			uwsgi_error("read()");
			break;
		}
		i += jlen;
		jlen = write(sockfd, nosf_buf, jlen);
		if (jlen <= 0) {
			uwsgi_error("write()");
			break;
		}
		rlen += jlen;
	}

	return rlen;
#endif

}
