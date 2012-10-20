#include "../corerouter/cr.h"

struct uwsgi_fastrouter {
	struct uwsgi_corerouter cr;
};

struct fastrouter_session {
	struct corerouter_session crs;
	struct uwsgi_buffer *post_buf;
	size_t post_buf_max;
	size_t post_buf_len;
	off_t post_buf_pos;
};

