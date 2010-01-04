#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

int uwsgi_enqueue_message(char *host, int port, uint8_t modifier1, uint8_t modifier2, char *message, int size, int timeout) {

	int uwsgi_fd;
	struct sockaddr_in uws_addr;
        int cnt ;
        struct uwsgi_header uh;

	if (size > 0xFFFF) {
                fprintf(stderr,"invalid object (marshalled) size\n");
		return -1 ;
        }

	uwsgi_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (uwsgi_fd < 0) {
		perror("socket()");
		return -1 ;
	}

	memset(&uws_addr, 0, sizeof(struct sockaddr_in));
        uws_addr.sin_family = AF_INET;
        uws_addr.sin_port = htons(port);
        uws_addr.sin_addr.s_addr = inet_addr(host);


        if (connect(uwsgi_fd, (const struct sockaddr *) &uws_addr, sizeof(struct sockaddr_in))) {
                perror("connect()");
                close(uwsgi_fd);
		return -1 ;
        }

        uh.modifier1 = modifier1;
        uh.pktsize = (uint16_t) size ;
        uh.modifier2 = modifier2;

        cnt = write(uwsgi_fd, &uh, 4) ;
        if (cnt != 4) {
                perror("write()");
                close(uwsgi_fd);
                return -1;
        }

	cnt = write(uwsgi_fd, message, size) ;
        if (cnt != size) {
                perror("write()");
                close(uwsgi_fd);
                return -1;
        }

	return uwsgi_fd;
}

PyObject *uwsgi_send_message(char *host, int port, uint8_t modifier1, uint8_t modifier2, char *message, int size, int timeout) {

	struct pollfd uwsgi_mpoll ;
	struct sockaddr_in uws_addr;
	int cnt ;
	struct uwsgi_header uh;
	char buffer[0xFFFF];


	if (size > 0xFFFF) {
		fprintf(stderr,"invalid object (marshalled) size\n");
		Py_INCREF(Py_None);
                return Py_None;
	}

	uwsgi_mpoll.events = POLLIN ;

	uwsgi_mpoll.fd = socket(AF_INET, SOCK_STREAM, 0);
	if (uwsgi_mpoll.fd < 0) {
		perror("socket()");
		Py_INCREF(Py_None);
                return Py_None;
	}

	memset(&uws_addr, 0, sizeof(struct sockaddr_in));
	uws_addr.sin_family = AF_INET;
        uws_addr.sin_port = htons(port);
	uws_addr.sin_addr.s_addr = inet_addr(host);


	if (connect(uwsgi_mpoll.fd, (const struct sockaddr *) &uws_addr, sizeof(struct sockaddr_in))) {
		perror("connect()");
		close(uwsgi_mpoll.fd);
		Py_INCREF(Py_None);
                return Py_None;
	}

	uh.modifier1 = modifier1;
	uh.pktsize = (uint16_t) size ;
	uh.modifier2 = modifier2;

	cnt = write(uwsgi_mpoll.fd, &uh, 4) ;
	if (cnt != 4) {
                perror("write()");      
                close(uwsgi_mpoll.fd);
                Py_INCREF(Py_None);
                return Py_None;
        }
	
	cnt = write(uwsgi_mpoll.fd, message, size) ;
	if (cnt != size) {
		perror("write()");	
		close(uwsgi_mpoll.fd);
		Py_INCREF(Py_None);
		return Py_None;
	}
	
	
	if (!uwsgi_parse_response(&uwsgi_mpoll, timeout, &uh, buffer)) {
		Py_INCREF(Py_None);
                return Py_None;
	}

	close(uwsgi_mpoll.fd);
	
	return PyMarshal_ReadObjectFromString(buffer, uh.pktsize);	
}

int uwsgi_parse_response(struct pollfd * upoll, int timeout, struct uwsgi_header *uh, char *buffer) {
	int rlen, i;
	/* first 4 byte header */
                rlen = poll(upoll, 1, timeout*1000) ;
                if (rlen < 0) {
                        perror("poll()");
                        exit(1);
                }
                else if (rlen == 0) {
                        fprintf(stderr, "timeout. skip request\n");
                        close(upoll->fd);
                        return 0 ;
                }
                rlen = read(upoll->fd, uh, 4) ;
                if (rlen > 0 && rlen < 4) {
                        i = rlen ;
                        while(i < 4) {
                                rlen = poll(upoll, 1, timeout*1000) ;
                                if (rlen < 0) {
                                        perror("poll()");
                                        exit(1);
                                }
                                else if (rlen == 0) {
                                        fprintf(stderr, "timeout waiting for header. skip request.\n");
                                        close(upoll->fd);
                                        break ;
                                }
                                rlen = read(upoll->fd, (char *)(uh)+i, 4-i);
                                if (rlen <= 0) {
                                        fprintf(stderr, "broken header. skip request.\n");
                                        close(upoll->fd);
                                        break ;
                                }
                                i += rlen;
                        }
                        if (i < 4) {
                                return 0;
                        }
                }
                else if (rlen <= 0){
                        fprintf(stderr,"invalid request header size: %d...skip\n", rlen);
                        close(upoll->fd);
                        return 0;
                }
                /* big endian ? */
                #ifdef __BIG_ENDIAN__
                uh->pktsize = uwsgi_swap16(uh->pktsize);
                #endif

                /* check for max buffer size */
                if (uh->pktsize > uwsgi.buffer_size) {
                        fprintf(stderr,"invalid request block size: %d...skip\n", uh->pktsize);
                        close(upoll->fd);
			return 0;
                }

                //fprintf(stderr,"ready for reading %d bytes\n", wsgi_req.size);

                i = 0 ;
                while(i < uh->pktsize) {
                        rlen = poll(upoll, 1, timeout*1000) ;
                        if (rlen < 0) {
                                perror("poll()");
                                exit(1);
                        }
                        else if (rlen == 0) {
                                fprintf(stderr, "timeout. skip request. (expecting %d bytes, got %d)\n", uh->pktsize, i);
                                close(upoll->fd);
                                break ;
                        }
                        rlen = read(upoll->fd, buffer+i, uh->pktsize-i);
                        if (rlen <= 0) {
                                fprintf(stderr, "broken vars. skip request.\n");
                                close(upoll->fd);
                                break ;
                        }
                        i += rlen ;
                }


                if (i < uh->pktsize) {
                        return 0;
                }

		return 1;
}
