#include <uwsgi.h>
#include <zlib.h>

/*

z_stream *uwsgi_deflate_init(int 
	z_stream *z = uwsgi_malloc(sizeof(z_stream));
        z->zalloc = Z_NULL;
        z->zfree = Z_NULL;
        z->opaque = Z_NULL;
        if (deflateInit(z, Z_DEFAULT_COMPRESSION) != Z_OK) {
       		goto end; 
                }
                if (deflateSetDictionary(&hr->spdy_z_out, (Bytef *) SPDY_dictionary_txt, sizeof(SPDY_dictionary_txt)) != Z_OK) {
                        return -1;
                }
                cs->can_keepalive = 1;
                hr->spdy_initialized = 1;

                hr->spdy_phase = UWSGI_SPDY_PHASE_HEADER;
                hr->spdy_need = 8;

                main_peer->out = uhttp.spdy3_settings;
                main_peer->out->pos = uhttp.spdy3_settings_size;
                main_peer->out_pos = 0;
                cr_write_to_main(main_peer, hr_ssl_write);
                return 1;
end:
	return NULL
}


char *uwsgi_deflate(char *buf, size_t len, size_t *dlen) {
	// calculate the amount of bytes needed for output (+30 should be enough)
        Bytef *dbuf = uwsgi_malloc(len+30);
        z_stream *z = &hr->spdy_z_out;
z->avail_in = h_buf->pos; z->next_in = (Bytef *) h_buf->buf; z->avail_out = h_buf->pos+30; z->next_out = dbuf;
        if (deflate(z, Z_SYNC_FLUSH) != Z_OK) {
                free(dbuf);
                return NULL;
        }

        *dlen = z->next_out - dbuf;
        return (char *) dbuf;

*/
