#ifdef UWSGI_SENDFILE

#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

PyObject *py_uwsgi_sendfile(PyObject * self, PyObject * args) {

	if (!PyArg_ParseTuple(args, "Oi:uwsgi_sendfile", &uwsgi.wsgi_req->async_sendfile, &uwsgi.wsgi_req->sendfile_fd_chunk)) {
                return NULL;
        }

#ifdef PYTHREE
        uwsgi.wsgi_req->sendfile_fd = PyObject_AsFileDescriptor(uwsgi.wsgi_req->async_sendfile);
#else
        if (PyFile_Check(uwsgi.wsgi_req->async_sendfile)) {
                uwsgi.wsgi_req->sendfile_fd = PyObject_AsFileDescriptor(uwsgi.wsgi_req->async_sendfile);
        }
#endif


        return PyTuple_New(0);
}

ssize_t uwsgi_sendfile(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {

	int fd = wsgi_req->sendfile_fd ;
	int sockfd = wsgi_req->poll.fd ;
        struct stat stat_buf;
	int sf_ret;

	if (!wsgi_req->sendfile_fd_size) {

        	if (fstat(fd, &stat_buf)) {
                	perror("fstat()");
                	return 0;
        	}
        	else {
                	wsgi_req->sendfile_fd_size = stat_buf.st_size;
        	}
	}

        if (wsgi_req->sendfile_fd_size) {

#if defined(__FreeBSD__) || defined(__DragonFly__)

                if (sendfile(fd, sockfd, 0, 0, NULL, &wsgi_req->sendfile_fd_size, 0)) {
                        perror("sendfile()");
                }
#elif __APPLE__
		off_t sf_len = wsgi_req->sendfile_fd_size ;

		if (uwsgi->async > 1) {
			sf_len = wsgi_req->sendfile_fd_chunk;
                	sf_ret = sendfile(fd, sockfd, wsgi_req->sendfile_fd_pos, &sf_len, NULL, 0);
			wsgi_req->sendfile_fd_pos += sf_len ;
		}
		else {
                	sf_ret = sendfile(fd, sockfd, 0, &sf_len, NULL, 0);
		}

		if (sf_ret) {
                       	perror("sendfile()");
			return 0;
                }

		return sf_len;
			
#elif defined(__linux__) || defined(__sun__)
		if (uwsgi->async > 1) {
                	sf_ret = sendfile(sockfd, fd, &wsgi_req->sendfile_fd_pos, wsgi_req->sendfile_fd_chunk);
		}
		else {
                	sf_ret = sendfile(sockfd, fd, &wsgi_req->sendfile_fd_pos, wsgi_req->sendfile_fd_size);
		}

		if (sf_ret < 0) {
                       	perror("sendfile()");
			return 0;
                }

		return sf_ret ;
#else
                ssize_t i = 0;
                char *no_sendfile_buf[4096];
                ssize_t jlen = 0;
                rlen = 0;
                i = 0;
                while (i < rlen) {
                        jlen = read(fd, no_sendfile_buf, 4096);
                        if (jlen <= 0) {
                                perror("read()");
                                break;
                        }
                        i += jlen;
                        jlen = write(sockfd, no_sendfile_buf, jlen);
                        if (jlen <= 0) {
                                perror("write()");
                                break;
                        }
                        rlen += jlen;
                }

		return rlen;
#endif

        }

        return 0;
}





#endif
