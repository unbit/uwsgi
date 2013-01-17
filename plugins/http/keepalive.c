#include "common.h"

extern struct uwsgi_http uhttp;

void http_response_parse(struct http_session *hr, char *buf, size_t len) {

        size_t i;
        size_t next = 0;

        int found = 0;
        // :version
        for(i=0;i<len;i++) {
                if (buf[i] == ' ') {
			if (hr->can_keepalive && uwsgi_strncmp("HTTP/1.1", 8, buf, i)) {
				goto end;
			}
                        if (i+1 >= len) goto end;
                        next = i+1;
                        found = 1;
                        break;
                }
        }

        if (!found) goto end;

        // :status
        found = 0;
        for(i=next;i<len;i++) {
                if (buf[i] == '\r' || buf[i] == '\n') {
			// status ready
                        if (i+1 >= len) goto end;
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

        // headers (key lowercase...)
        for(i=next;i<len;i++) {
                if (key) {
                        if (buf[i] == '\r' || buf[i] == '\n') {
                                char *colon = memchr(key, ':', h_len);
                                if (!colon) goto end;
                                // security check
                                if (colon+2 >= buf+len) goto end;
				if (hr->can_keepalive) {
					if (!uwsgi_strnicmp(key, colon-key, "Connection", 10)) {
						if (!uwsgi_strnicmp(colon+2, h_len-((colon-key)+2), "close", 5)) {
							goto end;
						}
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
		hr->can_keepalive = 0;
	}
        return;

end:
	hr->can_keepalive = 0;
        return;
}

