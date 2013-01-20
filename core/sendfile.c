#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

// sendfile() abstraction
ssize_t uwsgi_sendfile_do(int sockfd, int filefd, size_t pos, size_t len) {

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
	off_t sf_len = len;

	uwsgi_log("sendfile from %d to %d\n", pos, sf_len);

	int sf_ret = sendfile(filefd, sockfd, pos, &sf_len, NULL, 0);
	if (sf_ret == 0 || (sf_ret == -1 && errno == EAGAIN)) return sf_len;
	return -1;

#elif defined(__linux__) || defined(__sun__)
	off_t off = pos;
	return sendfile(sockfd, filefd, &off, len);
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
