#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

int uwsgi_read_whole_body_in_mem(struct wsgi_request *wsgi_req, char *buf) {

	size_t post_remains = wsgi_req->post_cl;
	int ret;
	ssize_t len;
	char *ptr = buf;

	while (post_remains > 0) {
		if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0) {
			inc_harakiri(uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
		}

		ret = uwsgi_waitfd(wsgi_req->poll.fd, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
		if (ret < 0) {
			return 0;
		}

		if (!ret) {
			uwsgi_log("buffering POST data to memory timed-out !!! (Content-Length: %llu received: %llu)\n", (unsigned long long) wsgi_req->post_cl, (unsigned long long) wsgi_req->post_cl - post_remains);
			return 0;
		}

		if (wsgi_req->socket->proto_read_body) {
			len = wsgi_req->socket->proto_read_body(wsgi_req, ptr, post_remains);
		}
		else {
			len = read(wsgi_req->poll.fd, ptr, post_remains);
		}

		if (len < 0) {
			uwsgi_error("read()");
			return 0;
		}

		if (len == 0) {
			uwsgi_log("client did not send the whole body: %s (Content-Length: %llu received: %llu)\n", strerror(errno), (unsigned long long) wsgi_req->post_cl, (unsigned long long) wsgi_req->post_cl - post_remains);
			return 0;
		}

		ptr += len;
		post_remains -= len;
	}

	return 1;

}

int uwsgi_read_whole_body(struct wsgi_request *wsgi_req, char *buf, size_t len) {

	size_t post_remains = wsgi_req->post_cl;
	ssize_t post_chunk;
	int ret, i;
	int upload_progress_fd = -1;
	char *upload_progress_filename = NULL;
	const char *x_progress_id = "X-Progress-ID=";
	char *xpi_ptr = (char *) x_progress_id;

	wsgi_req->async_post = tmpfile();
	if (!wsgi_req->async_post) {
		uwsgi_error("tmpfile()");
		return 0;
	}

	if (uwsgi.upload_progress) {
		// first check for X-Progress-ID size
		// separator + 'X-Progress-ID' + '=' + uuid     
		if (wsgi_req->uri_len > 51) {
			for (i = 0; i < wsgi_req->uri_len; i++) {
				if (wsgi_req->uri[i] == xpi_ptr[0]) {
					if (xpi_ptr[0] == '=') {
						if (wsgi_req->uri + i + 36 <= wsgi_req->uri + wsgi_req->uri_len) {
							upload_progress_filename = wsgi_req->uri + i + 1;
						}
						break;
					}
					xpi_ptr++;
				}
				else {
					xpi_ptr = (char *) x_progress_id;
				}
			}

			// now check for valid uuid (from spec available at http://en.wikipedia.org/wiki/Universally_unique_identifier)
			if (upload_progress_filename) {

				uwsgi_log("upload progress uuid = %.*s\n", 36, upload_progress_filename);
				if (!check_hex(upload_progress_filename, 8))
					goto cycle;
				if (upload_progress_filename[8] != '-')
					goto cycle;

				if (!check_hex(upload_progress_filename + 9, 4))
					goto cycle;
				if (upload_progress_filename[13] != '-')
					goto cycle;

				if (!check_hex(upload_progress_filename + 14, 4))
					goto cycle;
				if (upload_progress_filename[18] != '-')
					goto cycle;

				if (!check_hex(upload_progress_filename + 19, 4))
					goto cycle;
				if (upload_progress_filename[23] != '-')
					goto cycle;

				if (!check_hex(upload_progress_filename + 24, 12))
					goto cycle;

				upload_progress_filename = uwsgi_concat4n(uwsgi.upload_progress, strlen(uwsgi.upload_progress), "/", 1, upload_progress_filename, 36, ".js", 3);
				// here we use O_EXCL to avoid eventual application bug in uuid generation/using
				upload_progress_fd = open(upload_progress_filename, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR | S_IRGRP);
				if (upload_progress_fd < 0) {
					uwsgi_error_open(upload_progress_filename);
					free(upload_progress_filename);
				}
			}
		}
	}

cycle:
	if (upload_progress_filename && upload_progress_fd == -1) {
		uwsgi_log("invalid X-Progress-ID value: must be a UUID\n");
	}
	// manage buffered data and upload progress
	while (post_remains > 0) {

		if (uwsgi.shared->options[UWSGI_OPTION_HARAKIRI] > 0) {
			inc_harakiri(uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
		}

		ret = uwsgi_waitfd(wsgi_req->poll.fd, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
		if (ret < 0) {
			return 0;
		}

		if (!ret) {
			uwsgi_log("buffering POST data to disk timed-out !!! (Content-Length: %llu received: %llu)\n", (unsigned long long) wsgi_req->post_cl, (unsigned long long) wsgi_req->post_cl - post_remains);
			goto end;
		}

		if (post_remains > len) {
			if (wsgi_req->socket->proto_read_body) {
				post_chunk = wsgi_req->socket->proto_read_body(wsgi_req, buf, len);
			}
			else {
				post_chunk = read(wsgi_req->poll.fd, buf, len);
			}
		}
		else {
			if (wsgi_req->socket->proto_read_body) {
				post_chunk = wsgi_req->socket->proto_read_body(wsgi_req, buf, len);
			}
			else {
				post_chunk = read(wsgi_req->poll.fd, buf, post_remains);
			}
		}

		if (post_chunk < 0) {
			uwsgi_error("read()");
			goto end;
		}

		if (post_chunk == 0) {
			uwsgi_log("client did not send the whole body: %s (Content-Length: %llu received: %llu)\n", strerror(errno), (unsigned long long) wsgi_req->post_cl, (unsigned long long) wsgi_req->post_cl - post_remains);
			goto end;
		}

		if (fwrite(buf, post_chunk, 1, wsgi_req->async_post) != 1) {
			uwsgi_error("fwrite()");
			goto end;
		}
		if (upload_progress_fd > -1) {
			//write json data to the upload progress file
			if (lseek(upload_progress_fd, 0, SEEK_SET)) {
				uwsgi_error("lseek()");
				goto end;
			}

			// reuse buf for json buffer
			ret = snprintf(buf, len, "{ \"state\" : \"uploading\", \"received\" : %d, \"size\" : %d }\r\n", (int) (wsgi_req->post_cl - post_remains), (int) wsgi_req->post_cl);
			if (ret < 0) {
				uwsgi_log("unable to write JSON data in upload progress file %s\n", upload_progress_filename);
				goto end;
			}
			if (write(upload_progress_fd, buf, ret) < 0) {
				uwsgi_error("write()");
				goto end;
			}

			if (fsync(upload_progress_fd)) {
				uwsgi_error("fsync()");
			}
		}
		post_remains -= post_chunk;
	}
	rewind(wsgi_req->async_post);

	if (upload_progress_fd > -1) {
		close(upload_progress_fd);
		if (unlink(upload_progress_filename)) {
			uwsgi_error("unlink()");
		}
		free(upload_progress_filename);
	}

	return 1;

end:
	if (upload_progress_fd > -1) {
		close(upload_progress_fd);
		if (unlink(upload_progress_filename)) {
			uwsgi_error("unlink()");
		}
		free(upload_progress_filename);
	}
	return 0;
}

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
		uwsgi_error("poll()");
	}
	else if (ret > 0) {
		if (upoll.revents & event) {
			return ret;
		}
		return -1;
	}

	return ret;
}

char *uwsgi_read_fd(int fd, int *size, int add_zero) {

	char stack_buf[4096];
	ssize_t len;
	char *buffer = NULL;

	len = 1;
	while (len > 0) {
		len = read(fd, stack_buf, 4096);
		if (len > 0) {
			*size += len;
			buffer = realloc(buffer, *size);
			memcpy(buffer + (*size - len), stack_buf, len);
		}
	}

	if (add_zero) {
		*size = *size + 1;
		buffer = realloc(buffer, *size);
		buffer[*size - 1] = 0;
	}

	return buffer;

}

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

char *uwsgi_open_and_read(char *url, int *size, int add_zero, char *magic_table[]) {

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
				buffer = realloc(buffer, *size);
				if (!buffer) {
					uwsgi_error("realloc()");
					exit(1);
				}
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
			buffer = realloc(buffer, *size);
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

		buffer = malloc(sb.st_size + add_zero);

		if (!buffer) {
			uwsgi_error("malloc()");
			exit(1);
		}


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


int uwsgi_valid_fd(int fd) {
	int ret = fcntl(fd, F_GETFL);
	if (ret == 0) {
		return 1;
	}
	return 0;
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
