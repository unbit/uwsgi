#include "php.h"
#include "SAPI.h"
#include "php_main.h"
#include "php_variables.h"

#include "ext/standard/php_smart_str.h"

#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

static int sapi_uwsgi_ub_write(const char *str, uint str_length TSRMLS_DC)
{
	struct wsgi_request *wsgi_req = (struct wsgi_request *) SG(server_context);

	size_t len = wsgi_req->socket->proto_write(wsgi_req, (char *) str, str_length);
	wsgi_req->response_size += len;
	return len;
}

static int sapi_uwsgi_send_headers(sapi_headers_struct *sapi_headers)
{
	sapi_header_struct *h;
	zend_llist_position pos;
	struct iovec iov[4];
	char status[4];

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

	iov[3].iov_base = " Test\r\n";
	iov[3].iov_len = 7;

	wsgi_req->headers_size += wsgi_req->socket->proto_writev_header(wsgi_req, iov, 4);
	
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
	
	struct wsgi_request *wsgi_req = (struct wsgi_request *) SG(server_context);

        count_bytes = MIN(count_bytes, wsgi_req->post_cl - SG(read_post_bytes));
        while (read_bytes < count_bytes) {
                len = read(wsgi_req->poll.fd, buffer + read_bytes, count_bytes - read_bytes);
		if (len <= 0) {
			break;
		}
                read_bytes += len;
        }
        return read_bytes;
}

static char *sapi_uwsgi_read_cookies(void)
{
	int i;
	struct wsgi_request *wsgi_req = (struct wsgi_request *) SG(server_context);

	for (i = 0; i < wsgi_req->var_cnt; i += 2) {
		if (!uwsgi_strncmp((char *)"HTTP_COOKIE", 11, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len)) {
			return estrndup(wsgi_req->hvec[i + 1].iov_base, wsgi_req->hvec[i + 1].iov_len);
		}
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

	php_register_variable_safe("PHP_SELF", wsgi_req->path_info, wsgi_req->path_info_len, track_vars_array TSRMLS_CC);


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

	TSRMLS_FETCH();

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

	sapi_startup(&uwsgi_sapi_module);
	uwsgi_sapi_module.startup(&uwsgi_sapi_module);

	uwsgi_log("*** PHP plugin initialized ***\n");

	return 0;
}

int uwsgi_php_request(struct wsgi_request *wsgi_req) {

	zend_file_handle file_handle;
	SG(server_context) = (void *) wsgi_req;

	if (uwsgi_parse_vars(wsgi_req)) {
		return -1;
	}

	SG(request_info).request_uri = estrndup(wsgi_req->uri, wsgi_req->uri_len);
        SG(request_info).request_method = estrndup(wsgi_req->method, wsgi_req->method_len);
	SG(request_info).proto_num = 1001;

	SG(request_info).query_string = estrndup(wsgi_req->query_string, wsgi_req->query_string_len);
        SG(request_info).content_length = wsgi_req->post_cl;
	SG(request_info).content_type = estrndup(wsgi_req->content_type, wsgi_req->content_type_len);

        file_handle.type = ZEND_HANDLE_FILENAME;
        file_handle.filename = uwsgi_concat3n("/root/uwsgi/", 12, wsgi_req->path_info, wsgi_req->path_info_len, "", 0);
        file_handle.free_filename = 1;
        file_handle.opened_path = NULL;

        if (php_request_startup(TSRMLS_C) == FAILURE) {
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



SAPI_API struct uwsgi_plugin php_plugin = {
	.modifier1 = 14,
	.init = uwsgi_php_init,
	.request = uwsgi_php_request,
	.after_request = uwsgi_php_after_request,
};

