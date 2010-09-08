#ifdef UWSGI_SENDFILE

#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

PyObject *py_uwsgi_sendfile(PyObject * self, PyObject * args) {

	struct wsgi_request *wsgi_req = current_wsgi_req(&uwsgi);

	if (!PyArg_ParseTuple(args, "O|i:uwsgi_sendfile", &wsgi_req->async_sendfile, &wsgi_req->sendfile_fd_chunk)) {
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

	// PEP 333 hack
	wsgi_req->sendfile_obj = wsgi_req->async_sendfile;
	//wsgi_req->sendfile_obj = (void *) PyTuple_New(0);

	Py_INCREF((PyObject *) wsgi_req->sendfile_obj);
        return (PyObject *) wsgi_req->sendfile_obj;
}

ssize_t uwsgi_sendfile(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {

	int fd = wsgi_req->sendfile_fd ;
	int sockfd = wsgi_req->poll.fd ;
        struct stat stat_buf;

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

		return uwsgi_do_sendfile(sockfd, wsgi_req->sendfile_fd, wsgi_req->sendfile_fd_size, wsgi_req->sendfile_fd_chunk, &wsgi_req->sendfile_fd_pos, uwsgi->async);

	}

	return 0;
}


ssize_t uwsgi_do_sendfile(int sockfd, int filefd, size_t filesize, size_t chunk, off_t *pos, int async) {


#if defined(__FreeBSD__) || defined(__DragonFly__)

		int sf_ret;

		off_t sf_len = filesize ;

		if (async > 1) {
			sf_len = chunk;
			sf_ret = sendfile(filefd, sockfd, *pos, 0, NULL, &sf_len, 0);
			*pos += sf_len ;
		}
		else {
			sf_ret = sendfile(filefd, sockfd, 0, 0, NULL, &sf_len, 0);
		}

		 if (sf_ret) {
                        uwsgi_error("sendfile()");
                        return 0;
                }

		return sf_len;
#elif defined(__APPLE__)
		int sf_ret;
		off_t sf_len = filesize ;

		if (async > 1) {
			sf_len = chunk;
                	sf_ret = sendfile(filefd, sockfd, *pos, &sf_len, NULL, 0);
			*pos += sf_len ;
		}
		else {
                	sf_ret = sendfile(filefd, sockfd, 0, &sf_len, NULL, 0);
		}

		if (sf_ret) {
                       	uwsgi_error("sendfile()");
			return 0;
                }

		return sf_len;
			
#elif defined(__linux__) || defined(__sun__)
		int sf_ret;

		if (async > 1) {
                	sf_ret = sendfile(sockfd, filefd, pos, chunk);
		}
		else {
                	sf_ret = sendfile(sockfd, filefd, pos, filesize);
		}

		if (sf_ret < 0) {
                       	uwsgi_error("sendfile()");
			return 0;
                }

		return sf_ret ;
#else
		static size_t nosf_buf_size = 0 ;
		static char *nosf_buf ;

                ssize_t jlen = 0;
                ssize_t rlen = 0;
                ssize_t i = 0;

		if (!nosf_buf) {
			nosf_buf = malloc(chunk);
		}
		else if (chunk != nosf_buf_size) {
			nosf_buf = realloc(nosf_buf, chunk);
		}

		nosf_buf_size = chunk ;

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
			return jlen ;
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
			rlen += jlen ;
                }

		return rlen;
#endif

}






#endif
