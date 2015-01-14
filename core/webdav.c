#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

/*

The following functions are useful to implement simil-webdav support in plugins.

Most of them are not fully webdav compliant, but will work on the vast majority of clients.

*/

// a multi-status response (207) will return an xml with a list
// of <D:response> stanzas

struct uwsgi_buffer *uwsgi_webdav_multistatus_new() {
	struct uwsgi_buffer *ub = uwsgi_buffer_new(uwsgi.page_size);
	if (uwsgi_buffer_append(ub, "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n", 40)) goto error;
	if (uwsgi_buffer_append(ub, "<D:multistatus xmlns:D=\"DAV:\">\n", 31)) goto error;
	return ub;
error:
	uwsgi_buffer_destroy(ub);
	return NULL;
}

int uwsgi_webdav_multistatus_close(struct uwsgi_buffer *ub) {
	if (uwsgi_buffer_append(ub, "</D:multistatus>\n", 17)) return -1;
	return 0;
}

int uwsgi_webdav_multistatus_response_new(struct uwsgi_buffer *ub) {
	if (uwsgi_buffer_append(ub, "<D:response>\n", 13)) return -1;
        return 0;
}

int uwsgi_webdav_multistatus_response_close(struct uwsgi_buffer *ub) {
	if (uwsgi_buffer_append(ub, "</D:response>\n", 14)) return -1;
        return 0;
}

int uwsgi_webdav_multistatus_propstat_new(struct uwsgi_buffer *ub) {
	if (uwsgi_buffer_append(ub, "<D:propstat>\n", 13)) return -1;
        return 0;
}

int uwsgi_webdav_multistatus_propstat_close(struct uwsgi_buffer *ub) {
	if (uwsgi_buffer_append(ub, "</D:propstat>\n", 14)) return -1;
        return 0;
}

int uwsgi_webdav_multistatus_prop_new(struct uwsgi_buffer *ub) {
	if (uwsgi_buffer_append(ub, "<D:prop>\n", 9)) return -1;
        return 0;
}

int uwsgi_webdav_multistatus_prop_close(struct uwsgi_buffer *ub) {
	if (uwsgi_buffer_append(ub, "</D:prop>\n", 10)) return -1;
        return 0;
}

// shortcut for adding a propfind-response item
int uwsgi_webdav_propfind_item_add(struct uwsgi_buffer *ub, char *href, uint16_t href_len, uint64_t cl, time_t mtime, char *ctype, uint16_t ctype_len, char *displayname, uint16_t displayname_len, char *etag, uint16_t etag_len) {
	if (uwsgi_webdav_multistatus_response_new(ub)) return -1;
	if (uwsgi_buffer_append(ub, "<D:href>", 8)) return -1;
	if (uwsgi_buffer_append(ub, href, href_len)) return -1;
	if (uwsgi_buffer_append(ub, "</D:href>\n", 10)) return -1;
	if (uwsgi_webdav_multistatus_propstat_new(ub)) return -1;
	if (uwsgi_webdav_multistatus_prop_new(ub)) return -1;

	if (href[href_len-1] == '/') {
		if (uwsgi_buffer_append(ub, "<D:resourcetype><D:collection/></D:resourcetype>\n", 49)) return -1;
	}
	else {
		// getcontentlength
		if (uwsgi_buffer_append(ub, "<D:getcontentlength>", 20)) return -1;
		if (uwsgi_buffer_num64(ub, cl)) return -1;
		if (uwsgi_buffer_append(ub, "</D:getcontentlength>\n", 22)) return -1;
	}

	// getlastmodified
	if (mtime > 0) {
		if (uwsgi_buffer_append(ub, "<D:getlastmodified>", 19)) return -1;	
		if (uwsgi_buffer_httpdate(ub, mtime)) return -1;
		if (uwsgi_buffer_append(ub, "</D:getlastmodified>\n", 21)) return -1;	
	}

	// displayname
	if (displayname_len > 0) {
		if (uwsgi_buffer_append(ub, "<D:displayname>\n", 16)) return -1;
		if (uwsgi_buffer_append_xml(ub, displayname, displayname_len)) return -1;
		if (uwsgi_buffer_append(ub, "</D:displayname>\n", 17)) return -1;
	}

	if (ctype_len > 0) {
		if (uwsgi_buffer_append(ub, "<D:getcontenttype>", 18)) return -1;
		if (uwsgi_buffer_append(ub, ctype, ctype_len)) return -1;
		if (uwsgi_buffer_append(ub, "</D:getcontenttype>\n", 20)) return -1;
	}

	if (etag_len > 0) {
		if (uwsgi_buffer_append(ub, "<D:getetag>\n", 12)) return -1;
		if (uwsgi_buffer_append_xml(ub, etag, etag_len)) return -1;
		if (uwsgi_buffer_append(ub, "</D:getetag>\n", 13)) return -1;
	}

	if (uwsgi_webdav_multistatus_prop_close(ub)) return -1;
	if (uwsgi_webdav_multistatus_propstat_close(ub)) return -1;
	if (uwsgi_webdav_multistatus_response_close(ub)) return -1;
	return 0;
}
