#include "php.h"
#include "SAPI.h"
#include "php_main.h"
#include "php_variables.h"

#include "ext/standard/php_smart_str.h"

#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

// http status codes list
extern struct http_status_codes hsc[];

struct uwsgi_php {
	struct uwsgi_string_list *allowed_docroot;
	struct uwsgi_string_list *allowed_ext;
} uphp;

#define LONG_ARGS_PHP_BASE		17000 + ((14 + 1) * 1000)
#define LONG_ARGS_PHP_INI		LONG_ARGS_PHP_BASE + 1
#define LONG_ARGS_PHP_ALLOWED_DOCROOT	LONG_ARGS_PHP_BASE + 2
#define LONG_ARGS_PHP_ALLOWED_EXT	LONG_ARGS_PHP_BASE + 3

struct option uwsgi_php_options[] = {

        {"php-ini", required_argument, 0, LONG_ARGS_PHP_INI},
        {"php-config", required_argument, 0, LONG_ARGS_PHP_INI},
        {"php-allowed-docroot", required_argument, 0, LONG_ARGS_PHP_ALLOWED_DOCROOT},
        {"php-allowed-ext", required_argument, 0, LONG_ARGS_PHP_ALLOWED_EXT},
        {0, 0, 0, 0},

};


static int sapi_uwsgi_ub_write(const char *str, uint str_length TSRMLS_DC)
{
	struct wsgi_request *wsgi_req = (struct wsgi_request *) SG(server_context);

	ssize_t len = wsgi_req->socket->proto_write(wsgi_req, (char *) str, str_length);
	if (len != str_length) {
		php_handle_aborted_connection();
		return -1;
	}
	wsgi_req->response_size += len;
	return str_length;
}

void uwsgi_php_404(struct wsgi_request *wsgi_req) {

        wsgi_req->status = 404;
        wsgi_req->headers_size += wsgi_req->socket->proto_write(wsgi_req, "HTTP/1.0 404 Not Found\r\n\r\nNot Found", 35);
}

void uwsgi_php_403(struct wsgi_request *wsgi_req) {

        wsgi_req->status = 403;
        wsgi_req->headers_size += wsgi_req->socket->proto_write(wsgi_req, "HTTP/1.0 403 Forbidden\r\n\r\nForbidden", 35);

}


static int sapi_uwsgi_send_headers(sapi_headers_struct *sapi_headers)
{
	sapi_header_struct *h;
	zend_llist_position pos;
	struct iovec iov[6];
	char status[4];
	struct http_status_codes *http_sc;

	struct wsgi_request *wsgi_req = (struct wsgi_request *) SG(server_context);
	wsgi_req->status = SG(sapi_headers).http_response_code;
	if (!wsgi_req->status) wsgi_req->status = 200;

	iov[0].iov_base = wsgi_req->protocol;
	iov[0].iov_len = wsgi_req->protocol_len;


	iov[1].iov_base = " ";
	iov[1].iov_len = 1;

	uwsgi_num2str2n(wsgi_req->status, status, 4);

	iov[2].iov_base = status;
	iov[2].iov_len = 3;

	iov[3].iov_base = " ";
	iov[3].iov_len = 1;

	// get the status code
        for (http_sc = hsc; http_sc->message != NULL; http_sc++) {
                if (!strncmp(http_sc->key, status, 3)) {
                        iov[4].iov_base = (char *) http_sc->message;
                        iov[4].iov_len = http_sc->message_size;
                        break;
                }
        }

        if (iov[4].iov_len == 0) {
                iov[4].iov_base = "Unknown";
                iov[4].iov_len =  7;
        }

	iov[5].iov_base = "\r\n";
	iov[5].iov_len = 2;

	wsgi_req->headers_size += wsgi_req->socket->proto_writev_header(wsgi_req, iov, 6);
	
	h = zend_llist_get_first_ex(&sapi_headers->headers, &pos);
	while (h) {
		iov[0].iov_base = h->header;
		iov[0].iov_len = h->header_len;
		iov[1].iov_base = "\r\n";
		iov[1].iov_len = 2;
		wsgi_req->headers_size += wsgi_req->socket->proto_writev_header(wsgi_req, iov, 2);	
		wsgi_req->header_cnt++;
		h = zend_llist_get_next_ex(&sapi_headers->headers, &pos);
	}

	wsgi_req->headers_size += wsgi_req->socket->proto_write_header(wsgi_req, "\r\n", 2);
	
	return SAPI_HEADER_SENT_SUCCESSFULLY;
}

static int sapi_uwsgi_read_post(char *buffer, uint count_bytes TSRMLS_DC)
{
	uint read_bytes = 0;
	size_t len;
	int fd = -1;
	
	struct wsgi_request *wsgi_req = (struct wsgi_request *) SG(server_context);

	if (wsgi_req->body_as_file) {
                fd = fileno((FILE *)wsgi_req->async_post);
        }
        else if (uwsgi.post_buffering > 0) {
                if (wsgi_req->post_cl > (size_t) uwsgi.post_buffering) {
                        fd = fileno((FILE *)wsgi_req->async_post);
                }
        }
        else {
                fd = wsgi_req->poll.fd;
        }


        count_bytes = MIN(count_bytes, wsgi_req->post_cl - SG(read_post_bytes));

	// data in memory
	if (fd == -1) {
		if (count_bytes > 0) {
			memcpy(buffer, wsgi_req->post_buffering_buf + wsgi_req->post_pos, count_bytes);
			wsgi_req->post_pos += count_bytes;
		}
		return count_bytes;
	}

        while (read_bytes < count_bytes) {
                len = read(fd, buffer + read_bytes, count_bytes - read_bytes);
		if (len <= 0) {
			break;
		}
                read_bytes += len;
        }

        return read_bytes;
}


static char *sapi_uwsgi_read_cookies(void)
{
	uint16_t len = 0;
	struct wsgi_request *wsgi_req = (struct wsgi_request *) SG(server_context);

	char *cookie = uwsgi_get_var(wsgi_req, (char *)"HTTP_COOKIE", 11, &len);
	if (cookie) {
		return estrndup(cookie, len);
	}

	return NULL;
}

static void sapi_uwsgi_register_variables(zval *track_vars_array TSRMLS_DC)
{
	int i;
	struct wsgi_request *wsgi_req = (struct wsgi_request *) SG(server_context);
	php_import_environment_variables(track_vars_array TSRMLS_CC);

	for (i = 0; i < wsgi_req->var_cnt; i += 2) {
		php_register_variable_safe( estrndup(wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len),
			wsgi_req->hvec[i + 1].iov_base, wsgi_req->hvec[i + 1].iov_len,
			track_vars_array TSRMLS_CC);
        }

	php_register_variable_safe("PATH_INFO", wsgi_req->path_info, wsgi_req->path_info_len, track_vars_array TSRMLS_CC);

	php_register_variable_safe("SCRIPT_NAME", wsgi_req->script_name, wsgi_req->script_name_len, track_vars_array TSRMLS_CC);
	php_register_variable_safe("SCRIPT_FILENAME", wsgi_req->file, wsgi_req->file_len, track_vars_array TSRMLS_CC);


	if (wsgi_req->path_info_len) {
		char *path_translated = ecalloc(1, (wsgi_req->file_len - wsgi_req->script_name_len) + wsgi_req->path_info_len + 1);

		memcpy(path_translated, wsgi_req->file, (wsgi_req->file_len - wsgi_req->script_name_len));
		memcpy(path_translated + (wsgi_req->file_len - wsgi_req->script_name_len), wsgi_req->path_info, wsgi_req->path_info_len);
		php_register_variable_safe("PATH_TRANSLATED", path_translated, (wsgi_req->file_len - wsgi_req->script_name_len) + wsgi_req->path_info_len , track_vars_array TSRMLS_CC);
	}

	php_register_variable_safe("PHP_SELF", wsgi_req->script_name, wsgi_req->script_name_len, track_vars_array TSRMLS_CC);


}

static sapi_module_struct uwsgi_sapi_module;

static int php_uwsgi_startup(sapi_module_struct *sapi_module)
{
	if (php_module_startup(&uwsgi_sapi_module, NULL, 0)==FAILURE) {
		return FAILURE;
	} else {
		return SUCCESS;
	}
}

static void sapi_uwsgi_log_message(char *message) {

	uwsgi_log(message);
}

static sapi_module_struct uwsgi_sapi_module = {
	"uwsgi",
	"uWSGI/php",
	
	php_uwsgi_startup,
	php_module_shutdown_wrapper,
	
	NULL,									/* activate */
	NULL,									/* deactivate */

	sapi_uwsgi_ub_write,
	NULL,
	NULL,									/* get uid */
	NULL,									/* getenv */

	php_error,
	
	NULL,
	sapi_uwsgi_send_headers,
	NULL,
	sapi_uwsgi_read_post,
	sapi_uwsgi_read_cookies,

	sapi_uwsgi_register_variables,
	sapi_uwsgi_log_message,									/* Log message */
	NULL,									/* Get request time */
	NULL,									/* Child terminate */

	STANDARD_SAPI_MODULE_PROPERTIES
};

int uwsgi_php_init(void) {

	struct http_status_codes *http_sc;

	sapi_startup(&uwsgi_sapi_module);
	uwsgi_sapi_module.startup(&uwsgi_sapi_module);

	// filling http status codes
        for (http_sc = hsc; http_sc->message != NULL; http_sc++) {
                http_sc->message_size = strlen(http_sc->message);
        }


	uwsgi_log("PHP %s initialized\n", PHP_VERSION);

	return 0;
}

int uwsgi_php_walk(struct wsgi_request *wsgi_req, char *full_path, char *docroot, size_t docroot_len, char **path_info) {

        // and now start walking...
        uint16_t i;
        char *ptr = wsgi_req->path_info;
        char *dst = full_path+docroot_len;
        char *part = ptr;
        int part_size = 0;
        struct stat st;

        if (ptr[0] == '/') part_size++;

        for(i=0;i<wsgi_req->path_info_len;i++) {
                if (ptr[i] == '/') {
                        memcpy(dst, part, part_size-1);
                        *(dst+part_size-1) = 0;

                        if (stat(full_path, &st)) {
				uwsgi_php_404(wsgi_req);
                                return -1;
                        }


                        // not a directory, stop walking
                        if (!S_ISDIR(st.st_mode)) {
                                if (i < (wsgi_req->path_info_len)-1) {
                                        *path_info = ptr + i;
                                }

                                return 0;
                        }


                        // check for buffer overflow !!!
                        *(dst+part_size-1) = '/';
                        *(dst+part_size) = 0;

                        dst += part_size ;
                        part_size = 0;
                        part = ptr + i + 1;
                }

                part_size++;
        }

        if (part < wsgi_req->path_info+wsgi_req->path_info_len) {
                memcpy(dst, part, part_size-1);
                *(dst+part_size-1) = 0;
        }

        return 0;


}


int uwsgi_php_request(struct wsgi_request *wsgi_req) {

	char real_filename[PATH_MAX+1];
	uint16_t docroot_len = 0;
	char *path_info = NULL;
	size_t real_filename_len = 0;

	zend_file_handle file_handle;

	SG(server_context) = (void *) wsgi_req;

	if (uwsgi_parse_vars(wsgi_req)) {
		return -1;
	}

	char *docroot = uwsgi_get_var(wsgi_req, (char *) "DOCUMENT_ROOT", 13, &docroot_len);

	if (!docroot) {
		docroot = uwsgi.cwd;
		docroot_len = strlen(uwsgi.cwd);
	}

	char *filename = uwsgi_concat4n(docroot, docroot_len, "/", 1, wsgi_req->path_info, wsgi_req->path_info_len, "", 0);

	if (uwsgi_php_walk(wsgi_req, filename, docroot, docroot_len, &path_info)) {
		free(filename);
		return -1;
	}

	if (path_info) {
		wsgi_req->path_info = path_info;
		wsgi_req->path_info_len = strlen(wsgi_req->path_info);
	}
	else {
		wsgi_req->path_info = "";
		wsgi_req->path_info_len = 0;
	}


	if (!realpath(filename, real_filename)) {
		free(filename);
		uwsgi_php_404(wsgi_req);
		return -1;
	}

	free(filename);
	real_filename_len = strlen(real_filename);

	if (uphp.allowed_docroot) {
		struct uwsgi_string_list *usl = uphp.allowed_docroot;
		while(usl) {
			if (!uwsgi_starts_with(real_filename, real_filename_len, usl->value, usl->len)) {
				goto secure;
			}
			usl = usl->next;
		}
		uwsgi_php_403(wsgi_req);
		uwsgi_log("PHP security error: %s is not under an allowed docroot\n", real_filename);
		return -1;
	}

secure:

	if (uphp.allowed_ext) {
		struct uwsgi_string_list *usl = uphp.allowed_ext;
                while(usl) {
			if (real_filename_len >= usl->len) {
				if (!uwsgi_strncmp(real_filename+(real_filename_len-usl->len), usl->len, usl->value, usl->len)) {
                                	goto secure2;
                        	}
			}
                        usl = usl->next;
                }
                uwsgi_php_403(wsgi_req);
                uwsgi_log("PHP security error: %s does not end with an allowed extension\n", real_filename);
                return -1;
	}

secure2:

	wsgi_req->file = real_filename;
	wsgi_req->file_len = strlen(wsgi_req->file);

	if (docroot[docroot_len-1] == '/') {
		wsgi_req->script_name = real_filename + (docroot_len-1);
	}
	else {
		wsgi_req->script_name = real_filename + docroot_len;
	}

	wsgi_req->script_name_len = strlen(wsgi_req->script_name);

#ifdef UWSGI_DEBUG
	uwsgi_log("php filename = %s\n", real_filename);
#endif

	// now check for allowed paths and extensions

	SG(request_info).request_uri = estrndup(wsgi_req->uri, wsgi_req->uri_len);
        SG(request_info).request_method = estrndup(wsgi_req->method, wsgi_req->method_len);
	SG(request_info).proto_num = 1001;

	SG(request_info).query_string = estrndup(wsgi_req->query_string, wsgi_req->query_string_len);
        SG(request_info).content_length = wsgi_req->post_cl;
	SG(request_info).content_type = estrndup(wsgi_req->content_type, wsgi_req->content_type_len);

	SG(request_info).path_translated = wsgi_req->file;

        file_handle.type = ZEND_HANDLE_FILENAME;
        file_handle.filename = real_filename;
        file_handle.free_filename = 0;
        file_handle.opened_path = NULL;


        if (php_request_startup(TSRMLS_C) == FAILURE) {
		internal_server_error(wsgi_req, "unable to start php request");
                return -1;
        }

        php_execute_script(&file_handle TSRMLS_CC);

        php_request_shutdown(NULL);

	return 0;
}

void uwsgi_php_after_request(struct wsgi_request *wsgi_req) {

        if (uwsgi.shared->options[UWSGI_OPTION_LOGGING])
                log_request(wsgi_req);
}

int uwsgi_php_manage_options(int i, char *optarg) {

        switch(i) {
                case LONG_ARGS_PHP_INI:
			uwsgi_sapi_module.php_ini_path_override = uwsgi_str(optarg);
                        uwsgi_sapi_module.php_ini_ignore = 1;
                        return 1;
		case LONG_ARGS_PHP_ALLOWED_DOCROOT:
			uwsgi_string_new_list(&uphp.allowed_docroot, optarg);
			return 1;
		case LONG_ARGS_PHP_ALLOWED_EXT:
			uwsgi_string_new_list(&uphp.allowed_ext, optarg);
			return 1;
        }

        return 0;
}



SAPI_API struct uwsgi_plugin php_plugin = {
	.modifier1 = 14,
	.init = uwsgi_php_init,
	.request = uwsgi_php_request,
	.after_request = uwsgi_php_after_request,
	.options = uwsgi_php_options,
        .manage_opt = uwsgi_php_manage_options,
};

