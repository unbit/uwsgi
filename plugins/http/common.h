#include "../../uwsgi.h"

extern struct uwsgi_server uwsgi;

#include "../corerouter/cr.h"

#ifdef UWSGI_SSL
#ifdef OPENSSL_NPN_UNSUPPORTED
#define UWSGI_SPDY
#include <zlib.h>
#endif
#endif

struct uwsgi_http {

        struct uwsgi_corerouter cr;

        uint8_t modifier1;
        struct uwsgi_string_list *http_vars;
        int manage_expect;

        int raw_body;
        int keepalive;

#ifdef UWSGI_SSL
        int websockets;
        char *https_session_context;
        int https_export_cert;
#endif

        struct uwsgi_string_list *stud_prefix;

#ifdef UWSGI_SPDY
        int spdy_index;
#endif

}; 

struct http_session {

        struct corerouter_session session;

	// used for http parser
        int rnrn;
	size_t headers_size;
	size_t remains;
	size_t content_length;

	int raw_body;

        char *port;
        int port_len;

        char *request_uri;
        uint16_t request_uri_len;

        char *path_info;
        uint16_t path_info_len;

#ifdef UWSGI_SSL
	int websockets;
	char *origin;
	uint16_t origin_len;
	char *websocket_key;
	uint16_t websocket_key_len;
#endif

        size_t received_body;

#ifdef UWSGI_SSL
        SSL *ssl;
        X509 *ssl_client_cert;
        char *ssl_client_dn;
        BIO *ssl_bio;
        char *ssl_cc;
        int force_ssl;
        struct uwsgi_buffer *force_ssl_buf;
#endif

#ifdef UWSGI_SPDY
        int spdy;
        int spdy_initialized;
	int spdy_phase;
	uint32_t spdy_need;

        z_stream spdy_z_in;
        z_stream spdy_z_out;

        uint8_t spdy_frame_type;

        uint16_t spdy_control_version;
        uint16_t spdy_control_type;
        uint8_t spdy_control_flags;
        uint32_t spdy_control_length;

	uint32_t spdy_data_stream_id;
        uint8_t spdy_data_flags;
        uint32_t spdy_data_length;

        ssize_t (*spdy_hook)(struct corerouter_peer *);
#endif

        int send_expect_100;

        in_addr_t ip_addr;

        // 1 (family) + 4/16 (addr)
        char stud_prefix[17];
        size_t stud_prefix_remains;
        size_t stud_prefix_pos;

	ssize_t (*func_write)(struct corerouter_peer *);

};


#ifdef UWSGI_SSL

#define UWSGI_HTTP_NOSSL        0
#define UWSGI_HTTP_SSL          1
#define UWSGI_HTTP_FORCE_SSL    2

void uwsgi_opt_https(char *, char *, void *);
void uwsgi_opt_https2(char *, char *, void *);
void uwsgi_opt_http_to_https(char *, char *, void *);

ssize_t hr_recv_http_ssl(struct corerouter_peer *);
ssize_t hr_read_ssl_body(struct corerouter_peer *);
ssize_t hr_write_ssl_response(struct corerouter_peer *);

ssize_t hr_send_force_https(struct corerouter_peer *);

void hr_session_ssl_close(struct corerouter_session *);

ssize_t hr_ssl_read(struct corerouter_peer *);
ssize_t hr_ssl_write(struct corerouter_peer *);

int hr_https_add_vars(struct http_session *, struct uwsgi_buffer *);
void hr_setup_ssl(struct http_session *, struct uwsgi_gateway_socket *);

#endif

#ifdef UWSGI_SPDY
int uwsgi_spdy_npn(SSL *ssl, const unsigned char **, unsigned int *, void *);
void uwsgi_spdy_info_cb(SSL const *, int, int);
ssize_t hr_recv_spdy_control_frame(struct corerouter_peer *);
ssize_t spdy_parse(struct corerouter_peer *);
#endif

ssize_t hs_http_manage(struct corerouter_peer *, ssize_t);

ssize_t hr_instance_connected(struct corerouter_peer *);

ssize_t hr_instance_read_response(struct corerouter_peer *);
ssize_t hr_read_body(struct corerouter_peer *);
ssize_t hr_write_body(struct corerouter_peer *);

void hr_session_close(struct corerouter_session *);
ssize_t http_parse(struct corerouter_peer *);
