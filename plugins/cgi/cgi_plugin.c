#include "../../uwsgi.h"

#include <wordexp.h>

extern struct uwsgi_server uwsgi;

struct uwsgi_cgi {
	char *docroot;
	struct uwsgi_dyn_dict *helpers;
	int buffer_size;
	int timeout;
} uc ;

#define LONG_ARGS_CGI_BASE		17000 + ((9 + 1) * 1000)
#define LONG_ARGS_CGI			LONG_ARGS_CGI_BASE + 1
#define LONG_ARGS_CGI_MAP_HELPER	LONG_ARGS_CGI_BASE + 2
#define LONG_ARGS_CGI_BUFFER_SIZE	LONG_ARGS_CGI_BASE + 3
#define LONG_ARGS_CGI_TIMEOUT		LONG_ARGS_CGI_BASE + 4

struct option uwsgi_cgi_options[] = {

        {"cgi", required_argument, 0, LONG_ARGS_CGI},
        {"cgi-map-helper", required_argument, 0, LONG_ARGS_CGI_MAP_HELPER},
        {"cgi-buffer-size", required_argument, 0, LONG_ARGS_CGI_BUFFER_SIZE},
        {"cgi-timeout", required_argument, 0, LONG_ARGS_CGI_TIMEOUT},
        {0, 0, 0, 0},

};

int uwsgi_cgi_init(){

	if (!uc.buffer_size) uc.buffer_size = 65536;
	if (!uc.timeout) uc.timeout = 60;

	uwsgi_log("initialized CGI engine on directory %s\n", uc.docroot);

	return 1;

}

char *uwsgi_cgi_get_helper(char *filename) {

	struct uwsgi_dyn_dict *helpers = uc.helpers;
	size_t len = strlen(filename);

	while(helpers) {
		if (len >= (size_t) helpers->keylen) {
			if (!uwsgi_strncmp((filename+len)-helpers->keylen, helpers->keylen, helpers->key, helpers->keylen)) {
				return helpers->value;
			}
		}
		helpers = helpers->next;
	}

	return NULL;
	
}

int uwsgi_cgi_parse(struct wsgi_request *wsgi_req, char *buf, size_t len) {

	size_t i;
	char *key = buf, *value = NULL;
	size_t header_size = 0;
	int status_sent = 0;

	struct iovec iov[3];

	for(i=0;i<len;i++) {
		// end of a line
		if (buf[i] == '\n') {
			// end of headers
			if (key == NULL) {
				goto send_body;
			}
			// invalid header
			else if (value == NULL) {
				return -1;	
			}
			header_size = (buf+i) - key;
			// security check
			if (buf+i > buf) {
				if ((buf[i-1]) == '\r') {
					header_size--;
				}
			}

#ifdef UWSGI_DEBUG
			uwsgi_log("found CGI header: %.*s\n", header_size, key);
#endif

			if (status_sent == 0) {
				// "Status: NNN"
				if (header_size >= 11) {
					if (!strncasecmp("Status: ", key, 8)) {
						wsgi_req->status = uwsgi_str3_num(key+9);
						iov[0].iov_base = wsgi_req->protocol;
						iov[0].iov_len = wsgi_req->protocol_len;
						iov[1].iov_base = key+9;
						iov[1].iov_len = header_size - 9;
						iov[2].iov_base = "\r\n";
                                		iov[2].iov_len = 2;
						wsgi_req->headers_size += wsgi_req->socket->proto_writev_header(wsgi_req, iov, 3);
						status_sent = 1;
					}
				}
			}

			// default status
			if (status_sent == 0) {

				// Location: X
				if (header_size >= 11) {
					if (!strncasecmp("Location: ", key, 10)) {

						wsgi_req->status = 302;
						iov[0].iov_base = wsgi_req->protocol;
						iov[0].iov_len = wsgi_req->protocol_len;
						iov[1].iov_base = " 302 Found\r\n";
						iov[1].iov_len = 12;
						wsgi_req->headers_size += wsgi_req->socket->proto_writev_header(wsgi_req, iov, 2);
						status_sent = 1;
					}
				}

				if (status_sent == 0) {
					wsgi_req->status = 200;
					iov[0].iov_base = wsgi_req->protocol;
					iov[0].iov_len = wsgi_req->protocol_len;
					iov[1].iov_base = " 200 OK\r\n";
					iov[1].iov_len = 9;
					wsgi_req->headers_size += wsgi_req->socket->proto_writev_header(wsgi_req, iov, 2);
					status_sent = 1;
				}
			}

			iov[0].iov_base = key;
			iov[0].iov_len = header_size;
			iov[1].iov_base = "\r\n";
                        iov[1].iov_len = 2;
			wsgi_req->headers_size += wsgi_req->socket->proto_writev_header(wsgi_req, iov, 2);

			key = NULL;
			value = NULL;
		}
		else if (buf[i] == ':') {
			value = buf+i;
		}
		else if (buf[i] != '\r') {
			if (key == NULL) {
				key = buf + i;
			}
		}
	}

	return -1;

send_body:
	wsgi_req->headers_size += wsgi_req->socket->proto_write_header(wsgi_req, "\r\n", 2);
	if (len-i > 0) {
		wsgi_req->response_size += wsgi_req->socket->proto_write(wsgi_req, buf+i, len-i);
	}

	return 0;	
}

int uwsgi_cgi_request(struct wsgi_request *wsgi_req) {

	int i;
	pid_t cgi_pid;
	int waitpid_status;
	char *argv[3];
	char full_path[PATH_MAX];
	int cgi_pipe[2];
	ssize_t len;

	/* Standard CGI request */
	if (!wsgi_req->uh.pktsize) {
		uwsgi_log("Invalid CGI request. skip.\n");
		return -1;
	}


	if (uwsgi_parse_vars(wsgi_req)) {
		uwsgi_log("Invalid CGI request. skip.\n");
		return -1;
	}

	// check for file availability (and 'runnability')

	char *path_info = uwsgi_concat4n(uc.docroot, strlen(uc.docroot), "/", 1,wsgi_req->path_info, wsgi_req->path_info_len, "", 0);

	if (realpath(path_info, full_path) == NULL) {
		free(path_info);
		wsgi_req->status = 404;
		wsgi_req->socket->proto_write(wsgi_req, "HTTP/1.1 404 Not Found\r\n\r\n", 26);
		return UWSGI_OK;
	}

	free(path_info);

	if (uwsgi_starts_with(full_path, strlen(full_path), uc.docroot, strlen(uc.docroot))) {
                uwsgi_log("CGI security error: %s is not under %s\n", full_path, uc.docroot);
                return -1;
        }

	if (access(full_path, R_OK)) {
		uwsgi_error("access()");
		wsgi_req->status = 404;
		wsgi_req->socket->proto_write(wsgi_req, "HTTP/1.1 404 Not Found\r\n\r\n", 26);
		return UWSGI_OK;
	}

	char *helper = uwsgi_cgi_get_helper(full_path);

	if (helper == NULL) {
		if (access(full_path, X_OK)) {
			uwsgi_error("access()");
			wsgi_req->status = 500;
			wsgi_req->socket->proto_write(wsgi_req, "HTTP/1.1 500 Internal Server Error\r\n\r\n", 38);
			return UWSGI_OK;
		}
	}

	if (pipe(cgi_pipe)) {
		uwsgi_error("pipe()");
		return UWSGI_OK;
	}

	cgi_pid = fork();

	if (cgi_pid < 0) {
		uwsgi_error("fork()");
		return -1;
	}

	if (cgi_pid > 0) {
		close(cgi_pipe[1]);
		// wait for data
		char *headers_buf = uwsgi_malloc(uc.buffer_size);
		char *ptr = headers_buf;
		size_t remains = uc.buffer_size;
		int completed = 0;
		while(remains > 0) {
			int ret = uwsgi_waitfd(cgi_pipe[0], uc.timeout);
			if (ret > 0) {
				len = read(cgi_pipe[0], ptr, remains);
				if (len > 0) {
					ptr+=len;
					remains -= len;
				}
				else if (len == 0) {
					completed = 1;
					break;
				}
				else {
					uwsgi_error("read()");
					goto clear;
				}
				continue;
			}
			else if (ret == 0) {
				uwsgi_log("CGI timeout !!!\n");
				goto clear;
			}
			break;
		}

		if (uwsgi_cgi_parse(wsgi_req, headers_buf, uc.buffer_size-remains)) {
			uwsgi_log("invalid CGI output !!!\n");
			goto clear;
		}

		while (!completed) {
			int ret = uwsgi_waitfd(cgi_pipe[0], uc.timeout);
			if (ret > 0) {
				len = read(cgi_pipe[0], headers_buf, uc.buffer_size);
				if (len > 0) {
					wsgi_req->response_size += wsgi_req->socket->proto_write(wsgi_req, headers_buf, len);
				}
				// end of output
				else if (len == 0) {
					break;
				}
				else {
					uwsgi_error("read()");
					goto clear;
				}
				continue;
			}
			else if (ret == 0) {
                                uwsgi_log("CGI timeout !!!\n");
                                goto clear;
                        }
                        break;
		}

clear:
		free(headers_buf);
		close(cgi_pipe[0]);

		// now wait for process exit/death
		if (waitpid(cgi_pid, &waitpid_status, 0) < 0) {
			uwsgi_error("waitpid()");
		}

		return UWSGI_OK;
	}

	// close all the fd except wsgi_req->poll.fd and 2;

	for(i=0;i< (int)uwsgi.max_fd;i++) {
		if (i != wsgi_req->poll.fd && i != 2 && i != cgi_pipe[1]) {
			close(i);
		}
	}

	// now map wsgi_req->poll.fd to 0 & cgi_pipe[1] to 1
	if (wsgi_req->poll.fd != 0) {
		dup2(wsgi_req->poll.fd, 0);
		close(wsgi_req->poll.fd);
	}

#ifdef UWSGI_DEBUG
	uwsgi_log("mapping cgi_pipe %d to 1\n", cgi_pipe[1]);
#endif

	dup2(cgi_pipe[1],1);
	
	// fill cgi env
	for(i=0;i<wsgi_req->var_cnt;i++) {
		// no need to free the putenv() memory
		if (putenv(uwsgi_concat3n(wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len, "=", 1, wsgi_req->hvec[i+1].iov_base, wsgi_req->hvec[i+1].iov_len))) {
			uwsgi_error("putenv()");
		}
		i++;
	}

	if (setenv("DOCUMENT_ROOT", uc.docroot, 0)) {
		uwsgi_error("setenv()");
	}

	if (setenv("GATEWAY_INTERFACE", "CGI/1.1", 0)) {
		uwsgi_error("setenv()");
	}

	if (setenv("SERVER_SOFTWARE", uwsgi_concat2("uWSGI/", UWSGI_VERSION), 0)) {
		uwsgi_error("setenv()");
	}

	if (setenv("SCRIPT_NAME", uwsgi_concat2n(wsgi_req->path_info, wsgi_req->path_info_len, "", 0), 0)) {
		uwsgi_error("setenv()");
	}

	if (setenv("SCRIPT_FILENAME", uwsgi_concat3n(uc.docroot, strlen(uc.docroot), wsgi_req->path_info, wsgi_req->path_info_len, "", 0), 0)) {
		uwsgi_error("setenv()");
	}

	if (helper) {
		argv[0] = helper;
		argv[1] = full_path;
		argv[2] = NULL;
	}
	else {
		argv[0] = full_path;
		argv[1] = NULL;
	}

	if (execvp(argv[0], argv)) {
		uwsgi_error("execvp()");
	}

	// never here
	exit(1);
}


void uwsgi_cgi_after_request(struct wsgi_request *wsgi_req) {

	if (uwsgi.shared->options[UWSGI_OPTION_LOGGING])
		log_request(wsgi_req);
}

int uwsgi_cgi_manage_options(int i, char *optarg) {

	char *value;

        switch(i) {
                case LONG_ARGS_CGI:
                        uc.docroot = realpath(optarg, NULL);
                        return 1;
                case LONG_ARGS_CGI_BUFFER_SIZE:
                        uc.buffer_size = atoi(optarg);
                        return 1;
                case LONG_ARGS_CGI_TIMEOUT:
                        uc.timeout = atoi(optarg);
                        return 1;
		case LONG_ARGS_CGI_MAP_HELPER:
			value = strchr(optarg, '=');
			if (!value) {
				uwsgi_log("invalid CGI helper syntax, must be ext=command\n");
				exit(1);
			}
			uwsgi_dyn_dict_new(&uc.helpers, optarg, value-optarg, value+1, strlen(value+1));
			return 1;
        }

        return 0;
}


struct uwsgi_plugin cgi_plugin = {

	.name = "cgi",
	.modifier1 = 9,
	.init = uwsgi_cgi_init,
	.options = uwsgi_cgi_options,
	.manage_opt = uwsgi_cgi_manage_options,
	.request = uwsgi_cgi_request,
	.after_request = uwsgi_cgi_after_request,

};
