#ifdef UWSGI_SENDFILE

#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

PyObject *py_uwsgi_sendfile(PyObject * self, PyObject * args) {

	struct wsgi_request *wsgi_req = current_wsgi_req(&uwsgi);

	if (!PyArg_ParseTuple(args, "Oi:uwsgi_sendfile", &wsgi_req->async_sendfile, &wsgi_req->sendfile_fd_chunk)) {
                return NULL;
        }

#ifdef PYTHREE
        wsgi_req->sendfile_fd = PyObject_AsFileDescriptor(wsgi_req->async_sendfile);
#else
        if (PyFile_Check((PyObject *)wsgi_req->async_sendfile)) {
		Py_INCREF((PyObject *)wsgi_req->async_sendfile);
                wsgi_req->sendfile_fd = PyObject_AsFileDescriptor(wsgi_req->async_sendfile);
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
                	uwsgi_error("fstat()");
                	return 0;
        	}
        	else {
                	wsgi_req->sendfile_fd_size = stat_buf.st_size;
        	}
	}

        if (wsgi_req->sendfile_fd_size) {

		 if (!wsgi_req->sendfile_fd_chunk) wsgi_req->sendfile_fd_chunk = 4096 ;

#if defined(__FreeBSD__) || defined(__DragonFly__)

		off_t sf_len = wsgi_req->sendfile_fd_size ;

		if (uwsgi->async > 1) {
			sf_len = wsgi_req->sendfile_fd_chunk;
			sf_ret = sendfile(fd, sockfd, wsgi_req->sendfile_fd_pos, 0, NULL, &sf_len, 0);
			wsgi_req->sendfile_fd_pos += sf_len ;
		}
		else {
			sf_ret = sendfile(fd, sockfd, 0, 0, NULL, &sf_len, 0);
		}

		 if (sf_ret) {
                        uwsgi_error("sendfile()");
                        return 0;
                }

		return sf_len;
#elif defined(__APPLE__)
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
                       	uwsgi_error("sendfile()");
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
                       	uwsgi_error("sendfile()");
			return 0;
                }

		return sf_ret ;
#else
		static nosf_buf_size = 0 ;
		static char *nosf_buf ;

                ssize_t jlen = 0;
                ssize_t rlen = 0;
                ssize_t i = 0;

		if (!nosf_buf) {
			nosf_buf = malloc(wsgi_req->sendfile_fd_chunk);
		}
		else if (wsgi_req->sendfile_fd_chunk != nosf_buf_size) {
			nosf_buf = realloc(nosf_buf, wsgi_req->sendfile_fd_chunk);
		}

		nosf_buf_size = wsgi_req->sendfile_fd_chunk ;

		if (uwsgi->async > 1) {
			jlen = read(fd, nosf_buf, wsgi_req->sendfile_fd_chunk);
                        if (jlen <= 0) {
                                uwsgi_error("read()");
				return 0;
			}
			jlen = write(sockfd, nosf_buf, jlen);
                        if (jlen <= 0) {
                                uwsgi_error("write()");
				return 0;
			}
			return jlen ;
		}

                while (i < wsgi_req->sendfile_fd_size) {
                        jlen = read(fd, nosf_buf, wsgi_req->sendfile_fd_chunk);
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
			rlen += jlen ;
                }

		return rlen;
#endif

        }

        return 0;
}





#endif
