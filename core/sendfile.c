#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

// sendfile() abstraction
ssize_t uwsgi_sendfile_do(int sockfd, int filefd, size_t pos, size_t len) {

#if defined(__FreeBSD__) || defined(__DragonFly__)
	off_t sf_len = len;
        int sf_ret = sendfile(filefd, sockfd, pos, len, NULL,  &sf_len, 0);
        if (sf_ret == 0 || (sf_ret == -1 && errno == EAGAIN)) return sf_len;
        return -1;
#elif defined(__APPLE__)
	off_t sf_len = len;
	int sf_ret = sendfile(filefd, sockfd, pos, &sf_len, NULL, 0);
	if (sf_ret == 0 || (sf_ret == -1 && errno == EAGAIN)) return sf_len;
	return -1;
#elif defined(__linux__) || defined(__sun__)
	off_t off = pos;
	return sendfile(sockfd, filefd, &off, len);
#else
	// for platform not supporting sendfile we need to rely on boring read/write
	// generally that platforms have very low memory, so use a 8k buffer
	char buf[8192];
	if (pos > 0) {
		if (lseek(filefd, pos, SEEK_SET)) {
			uwsgi_error("uwsgi_sendfile_do()/seek()");
			return -1;
		}
	}
	ssize_t rlen = read(filefd, buf, UMIN(len, 8192));
	if (rlen <= 0) {
		uwsgi_error("uwsgi_sendfile_do()/read()");
		return -1;
	}
	return write(sockfd, buf, rlen);
#endif

}
