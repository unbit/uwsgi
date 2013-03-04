#include <uwsgi.h>


int uwsgi_deflate_init(z_stream *z, char *dict, size_t dict_len) {
        z->zalloc = Z_NULL;
        z->zfree = Z_NULL;
        z->opaque = Z_NULL;
        if (deflateInit2(z, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 9, Z_DEFAULT_STRATEGY) != Z_OK) {
	//if (deflateInit(z, Z_DEFAULT_COMPRESSION)) {
		return -1;
	}
	if (dict && dict_len) {
                if (deflateSetDictionary(z, (Bytef *) dict, dict_len) != Z_OK) {
                        return -1;
                }
	}
	return 0;
}


char *uwsgi_deflate(z_stream *z, char *buf, size_t len, size_t *dlen) {

	// calculate the amount of bytes needed for output (+30 should be enough)
        Bytef *dbuf = uwsgi_malloc(len+30);
	z->avail_in = len;
	z->next_in = (Bytef *) buf;
	z->avail_out = len+30;
	z->next_out = dbuf;

	if (len > 0) {
		if (deflate(z, Z_SYNC_FLUSH) != Z_OK) {
			free(dbuf);
			return NULL;
		}
	}
	else {
        	if (deflate(z, Z_FINISH) != Z_STREAM_END) {
                	free(dbuf);
                	return NULL;
		}
		deflateEnd(z);
        }

        *dlen = (z->next_out - dbuf);
        return (char *) dbuf;
}

void uwsgi_crc32(uint32_t *ctx, char *buf, size_t len) {
	if (!buf) {
		*ctx = crc32(*ctx, Z_NULL, 0);
	}
	else {
		*ctx = crc32(*ctx, (const Bytef *) buf, len);
	}
}
