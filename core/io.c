#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

/*

	poll based fd waiter.
	Use it for blocking areas (like startup functions)
	DO NOT USE IN REQUEST PLUGINS !!!

*/
int uwsgi_waitfd_event(int fd, int timeout, int event) {

	int ret;
	struct pollfd upoll;

	if (!timeout)
		timeout = uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT];

	timeout = timeout * 1000;
	if (timeout < 0)
		timeout = -1;

	upoll.fd = fd;
	upoll.events = event;
	upoll.revents = 0;
	ret = poll(&upoll, 1, timeout);

	if (ret < 0) {
		uwsgi_error("uwsgi_waitfd_event()/poll()");
	}
	else if (ret > 0) {
		if (upoll.revents & event) {
			return ret;
		}
		return -1;
	}

	return ret;
}

/*
	consume data from an fd (blocking)
*/
char *uwsgi_read_fd(int fd, size_t *size, int add_zero) {

	char stack_buf[4096];
	ssize_t len;
	char *buffer = NULL;

	len = 1;
	while (len > 0) {
		len = read(fd, stack_buf, 4096);
		if (len > 0) {
			*size += len;
			char *tmp = realloc(buffer, *size);
			if (!tmp) {
				uwsgi_error("uwsgi_read_fd()/realloc()");
				exit(1);
			}
			buffer = tmp;
			memcpy(buffer + (*size - len), stack_buf, len);
		}
	}

	if (add_zero) {
		*size = *size + 1;
		buffer = realloc(buffer, *size);
		if (!buffer) {
			uwsgi_error("uwsgi_read_fd()/realloc()");
			exit(1);
		}
		buffer[*size - 1] = 0;
	}

	return buffer;

}

// simply read the whole content of a file
char *uwsgi_simple_file_read(char *filename) {

	struct stat sb;
	char *buffer;
	ssize_t len;
	int fd = open(filename, O_RDONLY);
	if (fd < 0) {
		uwsgi_error_open(filename);
		goto end;
	}

	if (fstat(fd, &sb)) {
		uwsgi_error("fstat()");
		close(fd);
		goto end;
	}

	buffer = uwsgi_malloc(sb.st_size + 1);

	len = read(fd, buffer, sb.st_size);
	if (len != sb.st_size) {
		uwsgi_error("read()");
		free(buffer);
		close(fd);
		goto end;
	}

	close(fd);
	if (buffer[sb.st_size - 1] == '\n' || buffer[sb.st_size - 1] == '\r') {
		buffer[sb.st_size - 1] = 0;
	}
	buffer[sb.st_size] = 0;
	return buffer;
end:
	return (char *) "";

}

/*
	extremely complex function for reading resources (files, url...)
	need a lot of refactoring...
*/
char *uwsgi_open_and_read(char *url, size_t *size, int add_zero, char *magic_table[]) {

	int fd;
	struct stat sb;
	char *buffer = NULL;
	char byte;
	ssize_t len;
	char *uri, *colon;
	char *domain;
	char *ip;
	int body = 0;
	char *magic_buf;

	// stdin ?
	if (!strcmp(url, "-")) {
		buffer = uwsgi_read_fd(0, size, add_zero);
	}
	// fd ?
	else if (!strncmp("fd://", url, 5)) {
		fd = atoi(url + 5);
		buffer = uwsgi_read_fd(fd, size, add_zero);
	}
	// exec ?
	else if (!strncmp("exec://", url, 5)) {
		int cpipe[2];
		if (pipe(cpipe)) {
			uwsgi_error("pipe()");
			exit(1);
		}
		uwsgi_run_command(url + 7, NULL, cpipe[1]);
		buffer = uwsgi_read_fd(cpipe[0], size, add_zero);
		close(cpipe[0]);
		close(cpipe[1]);
	}
	// http url ?
	else if (!strncmp("http://", url, 7)) {
		domain = url + 7;
		uri = strchr(domain, '/');
		if (!uri) {
			uwsgi_log("invalid http url\n");
			exit(1);
		}
		uri[0] = 0;
		uwsgi_log("domain: %s\n", domain);

		colon = uwsgi_get_last_char(domain, ':');

		if (colon) {
			colon[0] = 0;
		}


		ip = uwsgi_resolve_ip(domain);
		if (!ip) {
			uwsgi_log("unable to resolve address %s\n", domain);
			exit(1);
		}

		if (colon) {
			colon[0] = ':';
			ip = uwsgi_concat2(ip, colon);
		}
		else {
			ip = uwsgi_concat2(ip, ":80");
		}

		fd = uwsgi_connect(ip, 0, 0);

		if (fd < 0) {
			exit(1);
		}

		free(ip);

		uri[0] = '/';

		len = write(fd, "GET ", 4);
		len = write(fd, uri, strlen(uri));
		len = write(fd, " HTTP/1.0\r\n", 11);
		len = write(fd, "Host: ", 6);

		uri[0] = 0;
		len = write(fd, domain, strlen(domain));
		uri[0] = '/';

		len = write(fd, "\r\nUser-Agent: uWSGI on ", 23);
		len = write(fd, uwsgi.hostname, uwsgi.hostname_len);
		len = write(fd, "\r\n\r\n", 4);

		int http_status_code_ptr = 0;

		while (read(fd, &byte, 1) == 1) {
			if (byte == '\r' && body == 0) {
				body = 1;
			}
			else if (byte == '\n' && body == 1) {
				body = 2;
			}
			else if (byte == '\r' && body == 2) {
				body = 3;
			}
			else if (byte == '\n' && body == 3) {
				body = 4;
			}
			else if (body == 4) {
				*size = *size + 1;
				char *tmp = realloc(buffer, *size);
				if (!tmp) {
					uwsgi_error("uwsgi_open_and_read()/realloc()");
					exit(1);
				}
				buffer = tmp;
				buffer[*size - 1] = byte;
			}
			else {
				body = 0;
				http_status_code_ptr++;
				if (http_status_code_ptr == 10) {
					if (byte != '2') {
						uwsgi_log("Not usable HTTP response: %cxx\n", byte);
						if (uwsgi.has_emperor) {
							exit(UWSGI_EXILE_CODE);
						}
						else {
							exit(1);
						}
					}
				}
			}
		}

		close(fd);

		if (add_zero) {
			*size = *size + 1;
			char *tmp = realloc(buffer, *size);
			if (!tmp) {
				uwsgi_error("uwsgi_open_and_read()/realloc()");
				exit(1);
			}
			buffer = tmp;
			buffer[*size - 1] = 0;
		}

	}
	else if (!strncmp("emperor://", url, 10)) {
		if (uwsgi.emperor_fd_config < 0) {
			uwsgi_log("this is not a vassal instance\n");
			exit(1);
		}
		ssize_t rlen;
		*size = 0;
		struct uwsgi_header uh;
		size_t remains = 4;
		char *ptr = (char *) &uh;
		while(remains) {
			int ret = uwsgi_waitfd(uwsgi.emperor_fd_config, 5);
			if (ret <= 0) {
				uwsgi_log("[uwsgi-vassal] error waiting for config header %s !!!\n", url);
				exit(1);
			}
			rlen = read(uwsgi.emperor_fd_config, ptr, remains);
			if (rlen <= 0) {
				uwsgi_log("[uwsgi-vassal] error reading config header from !!!\n", url);
				exit(1);
			}
			ptr+=rlen;
			remains-=rlen;
		}

		remains = uh.pktsize;
		if (!remains) {
			uwsgi_log("[uwsgi-vassal] invalid config from %s\n", url);
			exit(1);
		}

		buffer = uwsgi_calloc(remains + add_zero);
		ptr = buffer;
		while (remains) {
			int ret = uwsgi_waitfd(uwsgi.emperor_fd_config, 5);
                        if (ret <= 0) {
                                uwsgi_log("[uwsgi-vassal] error waiting for config %s !!!\n", url);
                                exit(1);
                        }
			rlen = read(uwsgi.emperor_fd_config, ptr, remains);
			if (rlen <= 0) {
                                uwsgi_log("[uwsgi-vassal] error reading config from !!!\n", url);
                                exit(1);
                        }
                        ptr+=rlen;
                        remains-=rlen;
		}

		*size = uh.pktsize + add_zero;
	}
#ifdef UWSGI_EMBED_CONFIG
	else if (url[0] == 0) {
		*size = &UWSGI_EMBED_CONFIG_END - &UWSGI_EMBED_CONFIG;
		if (add_zero) {
			*size += 1;
		}
		buffer = uwsgi_malloc(*size);
		memset(buffer, 0, *size);
		memcpy(buffer, &UWSGI_EMBED_CONFIG, &UWSGI_EMBED_CONFIG_END - &UWSGI_EMBED_CONFIG);
	}
#endif
	else if (!strncmp("data://", url, 7)) {
		fd = open(uwsgi.binary_path, O_RDONLY);
		if (fd < 0) {
			uwsgi_error_open(uwsgi.binary_path);
			exit(1);
		}
		int slot = atoi(url + 7);
		if (slot < 0) {
			uwsgi_log("invalid binary data slot requested\n");
			exit(1);
		}
		uwsgi_log("requesting binary data slot %d\n", slot);
		off_t fo = lseek(fd, 0, SEEK_END);
		if (fo < 0) {
			uwsgi_error("lseek()");
			uwsgi_log("invalid binary data slot requested\n");
			exit(1);
		}
		int i = 0;
		uint64_t datasize = 0;
		for (i = 0; i <= slot; i++) {
			fo = lseek(fd, -9, SEEK_CUR);
			if (fo < 0) {
				uwsgi_error("lseek()");
				uwsgi_log("invalid binary data slot requested\n");
				exit(1);
			}
			ssize_t len = read(fd, &datasize, 8);
			if (len != 8) {
				uwsgi_error("read()");
				uwsgi_log("invalid binary data slot requested\n");
				exit(1);
			}
			if (datasize == 0) {
				uwsgi_log("0 size binary data !!!\n");
				exit(1);
			}
			fo = lseek(fd, -(datasize + 9), SEEK_CUR);
			if (fo < 0) {
				uwsgi_error("lseek()");
				uwsgi_log("invalid binary data slot requested\n");
				exit(1);
			}

			if (i == slot) {
				*size = datasize;
				if (add_zero) {
					*size += 1;
				}
				buffer = uwsgi_malloc(*size);
				memset(buffer, 0, *size);
				len = read(fd, buffer, datasize);
				if (len != (ssize_t) datasize) {
					uwsgi_error("read()");
					uwsgi_log("invalid binary data slot requested\n");
					exit(1);
				}
			}
		}
	}
	else if (!strncmp("sym://", url, 6)) {
		char *symbol = uwsgi_concat3("_binary_", url + 6, "_start");
		void *sym_start_ptr = dlsym(RTLD_DEFAULT, symbol);
		if (!sym_start_ptr) {
			uwsgi_log("unable to find symbol %s\n", symbol);
			exit(1);
		}
		free(symbol);
		symbol = uwsgi_concat3("_binary_", url + 6, "_end");
		void *sym_end_ptr = dlsym(RTLD_DEFAULT, symbol);
		if (!sym_end_ptr) {
			uwsgi_log("unable to find symbol %s\n", symbol);
			exit(1);
		}
		free(symbol);

		*size = sym_end_ptr - sym_start_ptr;
		if (add_zero) {
			*size += 1;
		}
		buffer = uwsgi_malloc(*size);
		memset(buffer, 0, *size);
		memcpy(buffer, sym_start_ptr, sym_end_ptr - sym_start_ptr);

	}
#ifdef UWSGI_ELF
	else if (!strncmp("section://", url, 10)) {
		size_t s_len = 0;
		buffer = uwsgi_elf_section(uwsgi.binary_path, url + 10, &s_len);
		if (!buffer) {
			uwsgi_log("unable to find section %s in %s\n", url + 10, uwsgi.binary_path);
			exit(1);
		}
		*size = s_len;
		if (add_zero)
			*size += 1;
	}
#endif
	// fallback to file
	else {
		fd = open(url, O_RDONLY);
		if (fd < 0) {
			uwsgi_error_open(url);
			exit(1);
		}

		if (fstat(fd, &sb)) {
			uwsgi_error("fstat()");
			exit(1);
		}

		if (S_ISFIFO(sb.st_mode)) {
			buffer = uwsgi_read_fd(fd, size, add_zero);
			close(fd);
			goto end;
		}

		buffer = uwsgi_malloc(sb.st_size + add_zero);

		len = read(fd, buffer, sb.st_size);
		if (len != sb.st_size) {
			uwsgi_error("read()");
			exit(1);
		}

		close(fd);

		*size = sb.st_size + add_zero;

		if (add_zero)
			buffer[sb.st_size] = 0;
	}

end:

	if (magic_table) {

		magic_buf = magic_sub(buffer, *size, size, magic_table);
		free(buffer);
		return magic_buf;
	}

	return buffer;
}

// attach an fd using UNIX sockets
int *uwsgi_attach_fd(int fd, int *count_ptr, char *code, size_t code_len) {

	struct msghdr msg;
	ssize_t len;
	char *id = NULL;

	struct iovec iov;
	struct cmsghdr *cmsg;
	int *ret;
	int i;
	int count = *count_ptr;

	void *msg_control = uwsgi_malloc(CMSG_SPACE(sizeof(int) * count));

	memset(msg_control, 0, CMSG_SPACE(sizeof(int) * count));

	if (code && code_len > 0) {
		// allocate space for code and num_sockets
		id = uwsgi_malloc(code_len + sizeof(int));
		memset(id, 0, code_len);
		iov.iov_len = code_len + sizeof(int);
	}

	iov.iov_base = id;

	memset(&msg, 0, sizeof(msg));

	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	msg.msg_control = msg_control;
	msg.msg_controllen = CMSG_SPACE(sizeof(int) * count);

	msg.msg_flags = 0;

	len = recvmsg(fd, &msg, 0);
	if (len <= 0) {
		uwsgi_error("recvmsg()");
		return NULL;
	}

	if (code && code_len > 0) {
		if (uwsgi_strncmp(id, code_len, code, code_len)) {
			return NULL;
		}

		if ((size_t) len == code_len + sizeof(int)) {
			memcpy(&i, id + code_len, sizeof(int));
			if (i > count) {
				*count_ptr = i;
				free(msg_control);
				free(id);
				return NULL;
			}
		}
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg)
		return NULL;

	if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
		return NULL;
	}

	if ((size_t) (cmsg->cmsg_len - ((char *) CMSG_DATA(cmsg) - (char *) cmsg)) > (size_t) (sizeof(int) * (count + 1))) {
		uwsgi_log("not enough space for sockets data, consider increasing it\n");
		return NULL;
	}

	ret = uwsgi_malloc(sizeof(int) * (count + 1));
	for (i = 0; i < count + 1; i++) {
		ret[i] = -1;
	}

	memcpy(ret, CMSG_DATA(cmsg), cmsg->cmsg_len - ((char *) CMSG_DATA(cmsg) - (char *) cmsg));

	free(msg_control);
	if (code && code_len > 0) {
		free(id);
	}

	return ret;
}

// signal free close
void uwsgi_protected_close(int fd) {

	sigset_t mask, oset;
	sigfillset(&mask);
	if (sigprocmask(SIG_BLOCK, &mask, &oset)) {
		uwsgi_error("sigprocmask()");
		exit(1);
	}
	close(fd);
	if (sigprocmask(SIG_SETMASK, &oset, NULL)) {
		uwsgi_error("sigprocmask()");
		exit(1);
	}
}

// signal free read
ssize_t uwsgi_protected_read(int fd, void *buf, size_t len) {

	sigset_t mask, oset;
	sigfillset(&mask);
	if (sigprocmask(SIG_BLOCK, &mask, &oset)) {
		uwsgi_error("sigprocmask()");
		exit(1);
	}

	ssize_t ret = read(fd, buf, len);

	if (sigprocmask(SIG_SETMASK, &oset, NULL)) {
		uwsgi_error("sigprocmask()");
		exit(1);
	}
	return ret;
}


// pipe datas from a fd to another (blocking)
ssize_t uwsgi_pipe(int src, int dst, int timeout) {
	char buf[8192];
	size_t written = -1;
	ssize_t len;

	for (;;) {
		int ret = uwsgi_waitfd(src, timeout);
		if (ret > 0) {
			len = read(src, buf, 8192);
			if (len == 0) {
				return written;
			}
			else if (len < 0) {
				uwsgi_error("read()");
				return -1;
			}

			size_t remains = len;
			while (remains > 0) {
				int ret = uwsgi_waitfd_write(dst, timeout);
				if (ret > 0) {
					len = write(dst, buf, remains);
					if (len > 0) {
						remains -= len;
						written += len;
					}
					else if (len == 0) {
						return written;
					}
					else {
						uwsgi_error("write()");
						return -1;
					}
				}
				else if (ret == 0) {
					goto timeout;
				}
				else {
					return -1;
				}
			}
		}
		else if (ret == 0) {
			goto timeout;
		}
		else {
			return -1;
		}
	}

	return written;
timeout:
	uwsgi_log("timeout while piping from %d to %d !!!\n", src, dst);
	return -1;
}

/*
	even if it is marked as non-blocking, so not use in request plugins as it uses poll() and not the hooks
*/
int uwsgi_write_nb(int fd, char *buf, size_t remains, int timeout) {
	char *ptr = buf;
	while(remains > 0) {
		int ret = uwsgi_waitfd_write(fd, timeout);
		if (ret > 0) {
			ssize_t len = write(fd, ptr, remains);
			if (len <= 0) {
				return -1;
			} 
			ptr += len;
			remains -= len;	
			continue;
		}
		return -1;
	}

	return 0;
}

/*
	this is like uwsgi_write_nb() but with fast initial write and hooked wait (use it in request plugin)
*/
int uwsgi_write_true_nb(int fd, char *buf, size_t remains, int timeout) {
        char *ptr = buf;
	int ret;

        while(remains > 0) {
		ssize_t len = write(fd, ptr, remains);
		if (len > 0) goto written;
		if (len == 0) return -1;		
		if (len < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) goto wait;
			return -1;
		}
wait:
                ret = uwsgi.wait_write_hook(fd, timeout);
                if (ret > 0) {
			len = write(fd, ptr, remains);
			if (len > 0) goto written;
                }
                return -1;
written:
                ptr += len;
                remains -= len;
                continue;
        }

        return 0;
}




// like uwsgi_pipe but with fixed size
ssize_t uwsgi_pipe_sized(int src, int dst, size_t required, int timeout) {
	char buf[8192];
	size_t written = 0;
	ssize_t len;

	while (written < required) {
		int ret = uwsgi_waitfd(src, timeout);
		if (ret > 0) {
			len = read(src, buf, UMIN(8192, required - written));
			if (len == 0) {
				return written;
			}
			else if (len < 0) {
				uwsgi_error("read()");
				return -1;
			}

			size_t remains = len;
			while (remains > 0) {
				int ret = uwsgi_waitfd_write(dst, timeout);
				if (ret > 0) {
					len = write(dst, buf, remains);
					if (len > 0) {
						remains -= len;
						written += len;
					}
					else if (len == 0) {
						return written;
					}
					else {
						uwsgi_error("write()");
						return -1;
					}
				}
				else if (ret == 0) {
					goto timeout;
				}
				else {
					return -1;
				}
			}
		}
		else if (ret == 0) {
			goto timeout;
		}
		else {
			return -1;
		}
	}

	return written;
timeout:
	uwsgi_log("timeout while piping from %d to %d !!!\n", src, dst);
	return -1;
}


// check if an fd is valid
int uwsgi_valid_fd(int fd) {
	int ret = fcntl(fd, F_GETFL);
	if (ret == -1) {
		return 0;
	}
	return 1;
}

void uwsgi_close_all_fds(void) {
	int i;
	for (i = 3; i < (int) uwsgi.max_fd; i++) {
#ifdef __APPLE__
        	fcntl(i, F_SETFD, FD_CLOEXEC);
#else
                close(i);
#endif
	}
}

int uwsgi_read_uh(int fd, struct uwsgi_header *uh, int timeout) {
	char *ptr = (char *) uh;
	size_t remains = 4;
	while(remains > 0) {
		int ret = uwsgi_waitfd(fd, timeout);
		if (ret > 0) {
			ssize_t len = read(fd, ptr, remains);
			if (len <= 0) {
				return -1;
			}
			remains -=len;
			ptr +=len;
			continue;
		}
		return -1;
	}

	return 0;
}

int uwsgi_read_nb(int fd, char *buf, size_t remains, int timeout) {
	char *ptr = buf;
        while(remains > 0) {
                int ret = uwsgi_waitfd(fd, timeout);
                if (ret > 0) {
                        ssize_t len = read(fd, ptr, remains);
                        if (len <= 0) {
                                return -1;
                        }
                        remains -=len;
                        ptr +=len;
                        continue;
                }
                return -1;
        }

        return 0;
}

/*
        this is like uwsgi_read_nb() but with fast initial read and hooked wait (use it in request plugin)
*/
ssize_t uwsgi_read_true_nb(int fd, char *buf, size_t len, int timeout) {
        int ret;

	ssize_t rlen = read(fd, buf, len);
        if (rlen > 0) {
		return rlen;	
	}
        if (rlen == 0) return -1;
        if (rlen < 0) {
        	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) goto wait;
        }
        return -1;
wait:
        ret = uwsgi.wait_read_hook(fd, timeout);
        if (ret > 0) {
        	rlen = read(fd, buf, len);
                if (rlen > 0) {
			return rlen;
                }
		return -1;
	}
        return ret;
}


/*
	like the previous one but consume the whole len (if possibile)
*/

int uwsgi_read_whole_true_nb(int fd, char *buf, size_t remains, int timeout) {
	char *ptr = buf;
	while(remains > 0) {
		ssize_t len = uwsgi_read_true_nb(fd, ptr, remains, timeout);
		if (len <= 0) return -1;
		ptr += len;
		remains -= len;
	}
	return 0;
}

/*
	this is a pretty magic function used for read a full uwsgi response
	it is true non blocking, so you can use it in request plugins
	buffer is expected to be at least 4 bytes, rlen is a get/set value
*/

int uwsgi_read_with_realloc(int fd, char **buffer, size_t *rlen, int timeout) {
	if (*rlen < 4) return -1;
	char *buf = *buffer;
	int ret;

	// start reading the header
	char *ptr = buf;
	size_t remains = 4;
	while(remains > 0) {
		ssize_t len = read(fd, ptr, remains);
                if (len > 0) goto readok;
                if (len == 0) return -1;
                if (len < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) goto wait;
                        return -1;
                }
wait:
                ret = uwsgi.wait_read_hook(fd, timeout);
                if (ret > 0) {
                        len = read(fd, ptr, remains);
                        if (len > 0) goto readok;
                }
                return -1;
readok:
                ptr += len;
                remains -= len;
                continue;
        }

	struct uwsgi_header *uh = (struct uwsgi_header *) buf;
	uint16_t pktsize = uh->pktsize;
	
	if (pktsize > *rlen) {
		char *tmp_buf = realloc(buf, pktsize);
		if (!tmp_buf) {
			uwsgi_error("uwsgi_read_with_realloc()/realloc()");
			return -1;
		}
		*buffer = tmp_buf;
		buf = *buffer;
	}

	*rlen = pktsize;
	// read the body
	remains = pktsize;
	ptr = buf;
	while(remains > 0) {
                ssize_t len = read(fd, ptr, remains);
                if (len > 0) goto readok2;
                if (len == 0) return -1;
                if (len < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) goto wait2;
                        return -1;
                }
wait2:
                ret = uwsgi.wait_read_hook(fd, timeout);
                if (ret > 0) {
                        len = read(fd, ptr, remains);
                        if (len > 0) goto readok2;
                }
                return -1;
readok2:
                ptr += len;
                remains -= len;
                continue;
        }

	return 0;
	
}

/*

	this is a commodity (big) function to send a buffer and wsgi_req body to a socket
	and to receive back data (and send them to the client)

*/

int uwsgi_proxy_nb(struct wsgi_request *wsgi_req, char *addr, struct uwsgi_buffer *ub, size_t remains, int timeout) {

        int fd = uwsgi_connect(addr, 0, 1);
        if (fd < 0) {
		return -1;
        }

        int ret = uwsgi.wait_write_hook(fd, timeout);
        if (ret <= 0) {
		goto end;
        }

        // send the request (+ remaining data)
	if (ub) {
        	if (uwsgi_write_true_nb(fd, ub->buf, ub->pos, timeout)) {
			goto end;
        	}
	}

        // send the body
        while(remains > 0) {
                ssize_t rlen = 0;
                char *buf = uwsgi_request_body_read(wsgi_req, 8192, &rlen);
                if (!buf) {
			goto end;
                }
                if (buf == uwsgi.empty) break;
                // write data to the node
                if (uwsgi_write_true_nb(fd, buf, rlen, timeout)) {
			goto end;
                }
                remains -= rlen;
        }

        // read the response
        for(;;) {
                char buf[8192];
                ssize_t rlen = uwsgi_read_true_nb(fd, buf, 8192, timeout);
                if (rlen > 0) {
                        if (uwsgi_response_write_body_do(wsgi_req, buf, rlen)) {
                                break;
                        }
                        continue;
                }
                break;
        }

	close(fd);
	return 0;
end:
	close(fd);
	return -1;
}
