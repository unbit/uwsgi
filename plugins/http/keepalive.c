#include "common.h"

extern struct uwsgi_http uhttp;

int http_response_parse(struct http_session *hr, struct uwsgi_buffer *ub, size_t len) {

        size_t i;
        size_t next = 0;

	char *buf = ub->buf;

        int found = 0;
        // protocol
        for(i=0;i<len;i++) {
                if (buf[i] == ' ') {
			if (hr->can_keepalive && uwsgi_strncmp("HTTP/1.1", 8, buf, i)) {
				goto end;
			}
                        if (i+1 >= len) return -1;;
                        next = i+1;
                        found = 1;
                        break;
                }
        }

        if (!found) goto end;

        // status
        found = 0;
        for(i=next;i<len;i++) {
                if (buf[i] == '\r' || buf[i] == '\n') {
			// status ready
                        if (i+1 >= len) return -1;
                        next = i + 1;
                        found = 1;
                        break;
                }
        }

        if (!found) goto end;

        char *key = NULL;

        // find first header position
        for(i=next;i<len;i++) {
                if (buf[i] != '\r' && buf[i] != '\n') {
                        key = buf + i;
                        next = i;
                        break;
                }
        }

	if (!key) goto end;

        uint32_t h_len = 0;

	int has_size = 0;

        for(i=next;i<len;i++) {
                if (key) {
                        if (buf[i] == '\r' || buf[i] == '\n') {
                                char *colon = memchr(key, ':', h_len);
                                if (!colon) return -1;
                                // security check
                                if (colon+2 >= buf+len) return -1;
				if (hr->can_keepalive) {
					if (!uwsgi_strnicmp(key, colon-key, "Connection", 10)) {
						if (!uwsgi_strnicmp(colon+2, h_len-((colon-key)+2), "close", 5)) {
							goto end;
						}
					}
					else if (!uwsgi_strnicmp(key, colon-key, "Trailers", 8)) {
						goto end;
					}
					else if (!uwsgi_strnicmp(key, colon-key, "Content-Length", 14)) {
						has_size = 1;
					}
					else if (!uwsgi_strnicmp(key, colon-key, "Transfer-Encoding", 17)) {
						has_size = 1;
					}
				}
                                key = NULL;
                                h_len = 0;
                        }
                        else {
                                h_len++;
                        }
                }
                else {
                        if (buf[i] != '\r' && buf[i] != '\n') {
                                key = buf+i;
                                h_len = 1;
                        }
                }
        }

	if (hr->can_keepalive && !has_size) {
		if (uhttp.auto_chunked) {
			char cr = buf[len-2];
			char nl = buf[len-1];
			if (cr == '\r' && nl == '\n') {
				if (uwsgi_buffer_insert(ub, len-2, "Transfer-Encoding: chunked\r\n", 28)) return -1;
				size_t remains = ub->pos - (len+28);
				if (remains > 0) {
					if (uwsgi_buffer_insert_chunked(ub, len + 28, remains)) return -1;
					if (uwsgi_buffer_append(ub, "\r\n", 2)) return -1;
				}
				hr->force_chunked = 1;
				return 0;
			}
		}
		hr->can_keepalive = 0;
	}
        return 0;

end:
	hr->can_keepalive = 0;
        return 0;
}

