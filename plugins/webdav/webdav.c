#include <uwsgi.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#if defined(__linux__) || defined(__APPLE__)
#include <sys/xattr.h>
#endif

/*

	rfc4918 implementation (WebDAV)

	requires libxml2

	--webdav-mount [mountpoint=]<dir>

	or

	--webdav-use-docroot[=VAR]

	steps to build a path:

	1) get the mountpoint

	2) concat the base with the path_info

	3) realpath() on it

	step 3 could be a non-existent file (for example on MKCOL or PUT). In such a case:

	4) find the last / in the path_info, and try realpath() on it, if success the resource can be created

	ALL MUST BE BOTH THREAD SAFE AND ASYNC SAFE !!!

	Locking requires a cache (local or remote)

	when a lock request is made, an item is added to the cache (directly using cache_set to avoid duplicates). The
	item key is the full url of the request (host + path_info, in such a way we have virtualhosting for locks). The value is
	a uuid.

	if a lock_token is passed the url is checked in the cache and uuid compared

	- Resource properties are stored as filesystem xattr (warning, not all operating system support them) -

*/

extern struct uwsgi_server uwsgi;
struct uwsgi_plugin webdav_plugin;

struct uwsgi_webdav {
	struct uwsgi_string_list *mountpoints;
	struct uwsgi_string_list *css;
	struct uwsgi_string_list *javascript;
	char *class_directory;
	char *div;

	char *lock_cache;
	char *principal_base;

	struct uwsgi_string_list *add_option;

	struct uwsgi_string_list *add_prop;
	struct uwsgi_string_list *add_collection_prop;
	struct uwsgi_string_list *add_object_prop;

	struct uwsgi_string_list *add_prop_href;
	struct uwsgi_string_list *add_collection_prop_href;
	struct uwsgi_string_list *add_object_prop_href;

	struct uwsgi_string_list *add_prop_comp;
	struct uwsgi_string_list *add_collection_prop_comp;
	struct uwsgi_string_list *add_object_prop_comp;

	struct uwsgi_string_list *add_rtype_prop;
	struct uwsgi_string_list *add_rtype_collection_prop;
	struct uwsgi_string_list *add_rtype_object_prop;

	struct uwsgi_string_list *skip_prop;

} udav;

struct uwsgi_option uwsgi_webdav_options[] = {
	{ "webdav-mount", required_argument, 0, "map a filesystem directory as a webdav store", uwsgi_opt_add_string_list, &udav.mountpoints, UWSGI_OPT_MIME},
	{ "webdav-css", required_argument, 0, "add a css url for automatic webdav directory listing", uwsgi_opt_add_string_list, &udav.css, UWSGI_OPT_MIME},
	{ "webdav-javascript", required_argument, 0, "add a javascript url for automatic webdav directory listing", uwsgi_opt_add_string_list, &udav.javascript, UWSGI_OPT_MIME},
	{ "webdav-js", required_argument, 0, "add a javascript url for automatic webdav directory listing", uwsgi_opt_add_string_list, &udav.javascript, UWSGI_OPT_MIME},
	{ "webdav-class-directory", required_argument, 0, "set the css directory class for automatic webdav directory listing", uwsgi_opt_set_str, &udav.class_directory, UWSGI_OPT_MIME},
	{ "webdav-div", required_argument, 0, "set the div id for automatic webdav directory listing", uwsgi_opt_set_str, &udav.div, UWSGI_OPT_MIME},
	{ "webdav-lock-cache", required_argument, 0, "set the cache to use for webdav locking", uwsgi_opt_set_str, &udav.lock_cache, UWSGI_OPT_MIME},
	{ "webdav-principal-base", required_argument, 0, "enable WebDAV Current Principal Extension using the specified base", uwsgi_opt_set_str, &udav.principal_base, UWSGI_OPT_MIME},
	{ "webdav-add-option", required_argument, 0, "add a WebDAV standard to the OPTIONS response", uwsgi_opt_add_string_list, &udav.add_option, UWSGI_OPT_MIME},

	{ "webdav-add-prop", required_argument, 0, "add a WebDAV property to all resources", uwsgi_opt_add_string_list, &udav.add_prop, UWSGI_OPT_MIME},
	{ "webdav-add-collection-prop", required_argument, 0, "add a WebDAV property to all collections", uwsgi_opt_add_string_list, &udav.add_collection_prop, UWSGI_OPT_MIME},
	{ "webdav-add-object-prop", required_argument, 0, "add a WebDAV property to all objects", uwsgi_opt_add_string_list, &udav.add_object_prop, UWSGI_OPT_MIME},

	{ "webdav-add-prop-href", required_argument, 0, "add a WebDAV property to all resources (href value)", uwsgi_opt_add_string_list, &udav.add_prop_href, UWSGI_OPT_MIME},
	{ "webdav-add-collection-prop-href", required_argument, 0, "add a WebDAV property to all collections (href value)", uwsgi_opt_add_string_list, &udav.add_collection_prop_href, UWSGI_OPT_MIME},
	{ "webdav-add-object-prop-href", required_argument, 0, "add a WebDAV property to all objects (href value)", uwsgi_opt_add_string_list, &udav.add_object_prop_href, UWSGI_OPT_MIME},

	{ "webdav-add-prop-comp", required_argument, 0, "add a WebDAV property to all resources (xml value)", uwsgi_opt_add_string_list, &udav.add_prop_comp, UWSGI_OPT_MIME},
	{ "webdav-add-collection-prop-comp", required_argument, 0, "add a WebDAV property to all collections (xml value)", uwsgi_opt_add_string_list, &udav.add_collection_prop_comp, UWSGI_OPT_MIME},
	{ "webdav-add-object-prop-comp", required_argument, 0, "add a WebDAV property to all objects (xml value)", uwsgi_opt_add_string_list, &udav.add_object_prop_comp, UWSGI_OPT_MIME},

	{ "webdav-add-rtype-prop", required_argument, 0, "add a WebDAV resourcetype property to all resources", uwsgi_opt_add_string_list, &udav.add_rtype_prop, UWSGI_OPT_MIME},
	{ "webdav-add-rtype-collection-prop", required_argument, 0, "add a WebDAV resourcetype property to all collections", uwsgi_opt_add_string_list, &udav.add_rtype_collection_prop, UWSGI_OPT_MIME},
	{ "webdav-add-rtype-object-prop", required_argument, 0, "add a WebDAV resourcetype property to all objects", uwsgi_opt_add_string_list, &udav.add_rtype_object_prop, UWSGI_OPT_MIME},

	{ "webdav-skip-prop", required_argument, 0, "do not add the specified prop if available in resource xattr", uwsgi_opt_add_string_list, &udav.skip_prop, UWSGI_OPT_MIME},

	{ 0, 0, 0, 0, 0, 0, 0 },
};

static int uwsgi_webdav_prop_requested(xmlNode *req_prop, char *ns, char *name) {
        if (!req_prop) return 1;
        xmlNode *node;
        for (node = req_prop->children; node; node = node->next) {
                if (node->type == XML_ELEMENT_NODE) {
                        if (ns) {
                                if (node->ns && !strcmp((char *) node->ns->href, ns)) {
                                        if (!strcmp((char *) node->name, name)) return 1;
                                }
                        }
                        else {
                                if (!strcmp((char *) node->name, name)) return 1;
                        }
                }
        }
        return 0;
}

static void uwsgi_webdav_add_a_prop(xmlNode *node, char *opt, xmlNode *req_prop, int type, char *force_name) {
	char *first_space = strchr(opt, ' ');
	if (!first_space) return;
	*first_space = 0;
	char *second_space = strchr(first_space + 1, ' ');
	xmlNode *new_node = NULL;
	char *ns = opt;
	if (!force_name) force_name = first_space + 1;
	else {
		ns = "DAV:";
	}
	if (second_space) {
		*second_space = 0;
		if (!uwsgi_webdav_prop_requested(req_prop, ns, force_name)) {
                	*first_space = ' ';
                        *second_space = ' ';
                        return;
                }
		// href
		if (type == 1) {
			new_node = xmlNewChild(node, NULL, BAD_CAST first_space + 1, NULL);
			xmlNewTextChild(new_node, NULL, BAD_CAST "href", BAD_CAST second_space + 1);
		}
		// comp
		else if (type == 2) {
			new_node = xmlNewChild(node, NULL, BAD_CAST first_space + 1, NULL);
			char *comps = uwsgi_str(second_space + 1);
			char *p, *ctx = NULL;
			uwsgi_foreach_token(comps, ",", p, ctx) {
				xmlNode *comp = xmlNewChild(new_node, NULL, BAD_CAST "comp", NULL);
				xmlNewProp(comp, BAD_CAST "name", BAD_CAST p);
			}
			free(comps);
		}
		else {
			if (!uwsgi_webdav_prop_requested(req_prop, ns, first_space + 1)) {
                                *first_space = ' ';
                                *second_space = ' ';
                                return;
                        }
			new_node = xmlNewTextChild(node, NULL, BAD_CAST first_space + 1, BAD_CAST second_space + 1);
		}
		*second_space = ' ';
	}
	else {
		if (!uwsgi_webdav_prop_requested(req_prop, ns, force_name)) {
                        *first_space = ' ';
                        return;
                }
		new_node = xmlNewChild(node, NULL, BAD_CAST first_space + 1, NULL);
	}
	xmlNsPtr x_ns = xmlNewNs(new_node, BAD_CAST opt, NULL);
	xmlSetNs(new_node, x_ns);
	*first_space = ' ';
}

static void uwsgi_webdav_foreach_prop(struct uwsgi_string_list *usl, xmlNode *req_prop, xmlNode *node, int type, char *force_name) {
	if (!usl) return;
	while(usl) {
		uwsgi_webdav_add_a_prop(node, usl->value, req_prop, type, force_name);
		usl = usl->next;
	}
}


/*
	OPTIONS: if it is a valid webdav resource add Dav: to the response header	
*/
static int uwsgi_wevdav_manage_options(struct wsgi_request *wsgi_req) {
	uwsgi_response_prepare_headers(wsgi_req, "200 OK", 6);
	if (udav.add_option) {
		struct uwsgi_buffer *ub = uwsgi_buffer_new(uwsgi.page_size);
		if (uwsgi_buffer_append(ub, "1, 2, 3", 7)) goto end;
		struct uwsgi_string_list *usl = udav.add_option;
		while(usl) {
			if (uwsgi_buffer_append(ub, ", ", 2)) goto end;
			if (uwsgi_buffer_append(ub, usl->value, usl->len)) goto end;
			usl = usl->next;
		}
		uwsgi_response_add_header(wsgi_req, "Dav", 3, ub->buf, ub->pos);
end:	
		uwsgi_buffer_destroy(ub);
	}
	else {
		uwsgi_response_add_header(wsgi_req, "Dav", 3, "1, 2, 3", 7);
	}
	return UWSGI_OK;
}

static char *uwsgi_webdav_new_date(uint64_t t) {
	// 30+1
	char d[31];
	int len = uwsgi_http_date((time_t) t, d);
	if (!len) {
		return NULL;
	}
	return uwsgi_concat2n(d, len, "", 0);
}

static int uwsgi_webdav_add_props(struct wsgi_request *wsgi_req, xmlNode *req_prop, xmlNode * multistatus, xmlNsPtr dav_ns, char *uri, char *filename, int with_values) {
	struct stat st;
	if (stat(filename, &st)) {
		uwsgi_error("uwsgi_webdav_add_props()/stat()");
		return -1;
	}

	int is_collection = 0;

	xmlNode *response = xmlNewChild(multistatus, dav_ns, BAD_CAST "response", NULL);
	uint16_t uri_len = strlen(uri) ;
	char *encoded_uri = uwsgi_malloc( (uri_len * 3) + 1);
	http_url_encode(uri, &uri_len, encoded_uri);
	encoded_uri[uri_len] = 0;
	xmlNewChild(response, dav_ns, BAD_CAST "href", BAD_CAST encoded_uri);
	free(encoded_uri);
	xmlNode *r_propstat = xmlNewChild(response, dav_ns, BAD_CAST "propstat", NULL);
	char *r_status = uwsgi_concat2n(wsgi_req->protocol, wsgi_req->protocol_len, " 200 OK", 7);
	xmlNewChild(r_propstat, dav_ns, BAD_CAST "status", BAD_CAST r_status);
	free(r_status);

	xmlNode *r_prop = xmlNewChild(r_propstat, dav_ns, BAD_CAST "prop", NULL);

	if (with_values) {
		if (uwsgi_webdav_prop_requested(req_prop, "DAV:", "displayname")) {
			char *base_uri = uwsgi_get_last_char(uri, '/');
			if (base_uri) {
				xmlNewChild(r_prop, dav_ns, BAD_CAST "displayname", BAD_CAST base_uri+1);
			}
			else {
				xmlNewChild(r_prop, dav_ns, BAD_CAST "displayname", BAD_CAST uri);
			}

		}

		if (S_ISDIR(st.st_mode)) is_collection = 1;

		xmlNode *r_type = NULL;

		if (uwsgi_webdav_prop_requested(req_prop, "DAV:", "resourcetype")) {
			r_type = xmlNewChild(r_prop, dav_ns, BAD_CAST "resourcetype", NULL);
			if (is_collection) {
				xmlNewChild(r_type, dav_ns, BAD_CAST "collection", NULL);
				is_collection = 1;
			}
		}


		if (!is_collection) {
			if (uwsgi_webdav_prop_requested(req_prop, "DAV:", "getcontentlength")) {
				char *r_contentlength = uwsgi_num2str(st.st_size);
				xmlNewChild(r_prop, dav_ns, BAD_CAST "getcontentlength", BAD_CAST r_contentlength);
				free(r_contentlength);
			}
			if (uwsgi_webdav_prop_requested(req_prop, "DAV:", "getcontenttype")) {
				size_t mime_type_len = 0;
				char *mime_type = uwsgi_get_mime_type(filename, strlen(filename), &mime_type_len);
				if (mime_type) {
					char *r_ctype = uwsgi_concat2n(mime_type, mime_type_len, "", 0);
					xmlNewTextChild(r_prop, dav_ns, BAD_CAST "getcontenttype", BAD_CAST r_ctype);
					free(r_ctype);
				}
			}
		}

		if (uwsgi_webdav_prop_requested(req_prop, "DAV:", "creationdate")) {
			// there is no creation date on UNIX/POSIX, ctime is the nearest thing...
			char *cdate = uwsgi_webdav_new_date(st.st_ctime);
			if (cdate) {
				xmlNewTextChild(r_prop, dav_ns, BAD_CAST "creationdate", BAD_CAST cdate);
				free(cdate);
			}
		}

		if (uwsgi_webdav_prop_requested(req_prop, "DAV:", "getlastmodified")) {
			char *mdate = uwsgi_webdav_new_date(st.st_mtime);
			if (mdate) {
				xmlNewTextChild(r_prop, dav_ns, BAD_CAST "getlastmodified", BAD_CAST mdate);
				free(mdate);
			}
		}

		if (uwsgi_webdav_prop_requested(req_prop, "DAV:", "getetag")) {
			char *etag = uwsgi_num2str(st.st_mtime);
			xmlNewTextChild(r_prop, dav_ns, BAD_CAST "getetag", BAD_CAST etag);
			free(etag);
		}

		if (uwsgi_webdav_prop_requested(req_prop, "DAV:", "executable")) {
			xmlNewChild(r_prop, dav_ns, BAD_CAST "executable", NULL);
		}

		if (uwsgi_webdav_prop_requested(req_prop, "DAV:", "owner")) {
			xmlNewTextChild(r_prop, dav_ns, BAD_CAST "owner", NULL);
		}

		if (wsgi_req->remote_user_len > 0) {

			if (udav.principal_base) {
				if (uwsgi_webdav_prop_requested(req_prop, "DAV:", "current-user-principal")) {
					char *current_user_principal = uwsgi_concat2n(udav.principal_base, strlen(udav.principal_base), wsgi_req->remote_user, wsgi_req->remote_user_len);
					xmlNode *cup = xmlNewChild(r_prop, dav_ns, BAD_CAST "current-user-principal", NULL);
					xmlNewTextChild(cup, dav_ns, BAD_CAST "href", BAD_CAST current_user_principal);
					if (uwsgi_webdav_prop_requested(req_prop, "DAV:", "resourcetype")) {
						if (!strcmp(current_user_principal, uri)) {
							xmlNewChild(r_type, dav_ns, BAD_CAST "principal", NULL);
						}
					}
					free(current_user_principal);
				}
			}

			if (uwsgi_webdav_prop_requested(req_prop, "DAV:", "current-user-privilege-set")) {
				xmlNode *cups = xmlNewChild(r_prop, dav_ns, BAD_CAST "current-user-privilege-set", NULL);
				xmlNode *privilege = xmlNewChild(cups, dav_ns, BAD_CAST "privilege", NULL);	
				xmlNewChild(privilege, dav_ns, BAD_CAST "all", NULL);
				xmlNewChild(privilege, dav_ns, BAD_CAST "read", NULL);
				xmlNewChild(privilege, dav_ns, BAD_CAST "write", NULL);
				xmlNewChild(privilege, dav_ns, BAD_CAST "write-content", NULL);
				xmlNewChild(privilege, dav_ns, BAD_CAST "write-properties", NULL);
			}
		}

		if (uwsgi_webdav_prop_requested(req_prop, "DAV:", "supported-report-set")) {
			xmlNode *report_set = xmlNewChild(r_prop, dav_ns, BAD_CAST "supported-report-set", NULL);
			xmlNode *supported_report = xmlNewChild(report_set, dav_ns, BAD_CAST "supported-report", NULL);
			xmlNewChild(supported_report, dav_ns, BAD_CAST "report", BAD_CAST "principal-property-search");
			supported_report = xmlNewChild(report_set, dav_ns, BAD_CAST "supported-report", NULL);
			xmlNewChild(supported_report, dav_ns, BAD_CAST "report", BAD_CAST "sync-collection");
			supported_report = xmlNewChild(report_set, dav_ns, BAD_CAST "supported-report", NULL);
			xmlNewChild(supported_report, dav_ns, BAD_CAST "report", BAD_CAST "expand-property");
			supported_report = xmlNewChild(report_set, dav_ns, BAD_CAST "supported-report", NULL);
			xmlNewChild(supported_report, dav_ns, BAD_CAST "report", BAD_CAST "principal-search-property-set");
		}

		uwsgi_webdav_foreach_prop(udav.add_prop, req_prop, r_prop, 0, NULL );
                uwsgi_webdav_foreach_prop(udav.add_prop_href, req_prop, r_prop, 1, NULL);
                uwsgi_webdav_foreach_prop(udav.add_prop_comp,req_prop, r_prop, 2 , NULL);

		uwsgi_webdav_foreach_prop(udav.add_rtype_prop,req_prop, r_type, 0, "resourcetype");

		if (is_collection) {
			uwsgi_webdav_foreach_prop(udav.add_rtype_collection_prop,req_prop, r_type, 0, "resourcetype");
			uwsgi_webdav_foreach_prop(udav.add_collection_prop,req_prop, r_prop, 0, NULL);
			uwsgi_webdav_foreach_prop(udav.add_collection_prop_href,req_prop, r_prop, 1, NULL);
			uwsgi_webdav_foreach_prop(udav.add_collection_prop_comp,req_prop, r_prop, 2, NULL);
		}
		else {
			uwsgi_webdav_foreach_prop(udav.add_rtype_object_prop,req_prop, r_type, 0, "resourcetype");
			uwsgi_webdav_foreach_prop(udav.add_object_prop,req_prop, r_prop, 0, NULL);
			uwsgi_webdav_foreach_prop(udav.add_object_prop_href,req_prop, r_prop, 1, NULL);
			uwsgi_webdav_foreach_prop(udav.add_object_prop_comp,req_prop, r_prop, 2, NULL);
		}
	}
	else {
		xmlNewChild(r_prop, dav_ns, BAD_CAST "displayname", NULL);
		xmlNewChild(r_prop, dav_ns, BAD_CAST "resourcetype", NULL);
		if (!S_ISDIR(st.st_mode)) {
			xmlNewChild(r_prop, dav_ns, BAD_CAST "getcontentlength", NULL);
			xmlNewChild(r_prop, dav_ns, BAD_CAST "getcontenttype", NULL);
		}
		xmlNewChild(r_prop, dav_ns, BAD_CAST "creationdate", NULL);
		xmlNewChild(r_prop, dav_ns, BAD_CAST "getlastmodified", NULL);
		xmlNewChild(r_prop, dav_ns, BAD_CAST "supported-report-set", NULL);
		if (wsgi_req->remote_user_len > 0) {
			xmlNewChild(r_prop, dav_ns, BAD_CAST "current-user-privilege-set", NULL);
			if (udav.principal_base) {
				xmlNewChild(r_prop, dav_ns, BAD_CAST "current-user-principal", NULL);
			}
		}
	}

#if defined(__linux__) || defined(__APPLE__)
	// get xattr for user.uwsgi.webdav.
#if defined(__linux__)
	ssize_t rlen = listxattr(filename, NULL, 0);
#elif defined(__APPLE__)
	ssize_t rlen = listxattr(filename, NULL, 0, 0);
#endif
	// do not return -1 as the previous xml is valid !!!
	if (rlen <= 0) return 0;
	// use calloc to avoid races
	char *xattrs = uwsgi_calloc(rlen);
#if defined(__linux__)
	if (listxattr(filename, xattrs, rlen) <= 0) {
#elif defined(__APPLE__)
	if (listxattr(filename, xattrs, rlen, 0) <= 0) {
#endif
		free(xattrs);
		return 0;
	}
	// parse the name list
	ssize_t i;
	char *key = NULL;
	for(i=0;i<rlen;i++) {
		// check for wrong condition
		if (xattrs[i] == 0 && key == NULL) break;
		if (key && xattrs[i] == 0) {
			if (!uwsgi_starts_with(key, strlen(key), "user.uwsgi.webdav.", 18)) {
				if (uwsgi_string_list_has_item(udav.skip_prop, key + 18, strlen(key + 18))) continue;
				xmlNsPtr xattr_ns = NULL;
				// does it has a namespace ?
				char *separator = strchr(key + 18, '|');
				char *xattr_key = key + 18;
				if (separator) {
					xattr_key = separator + 1;
					*separator = 0;
					if (!uwsgi_webdav_prop_requested(req_prop, key + 18, xattr_key)) continue;
				}
				else {
					if (!uwsgi_webdav_prop_requested(req_prop, NULL, xattr_key)) continue;
				}
				xmlNode *xattr_item = NULL;
				if (with_values) {
#if defined(__linux__)
					ssize_t rlen2 = getxattr(filename, key, NULL, 0);
#elif defined(__APPLE__)
					ssize_t rlen2 = getxattr(filename, key, NULL, 0, 0, 0);
#endif
					if (rlen > 0) {
						// leave space for final 0
						char *xvalue = uwsgi_calloc(rlen2 + 1);
#if defined(__linux__)
						if (getxattr(filename, key, xvalue, rlen2) > 0) {
#elif defined(__APPLE__)
						if (getxattr(filename, key, xvalue, rlen2, 0 ,0) > 0) {
#endif
							xattr_item = xmlNewTextChild(r_prop, NULL, BAD_CAST xattr_key, BAD_CAST xvalue);
						}
						free(xvalue);	
					}
					else if (rlen == 0) {
						xattr_item = xmlNewTextChild(r_prop, NULL, BAD_CAST xattr_key, NULL);
					}
				}
				else {
					xattr_item = xmlNewTextChild(r_prop, NULL, BAD_CAST xattr_key, NULL);
				}	
				if (separator && xattr_item) {
					xattr_ns = xmlNewNs(xattr_item, BAD_CAST (key + 18), NULL);
					*separator = '|';
					xmlSetNs(xattr_item, xattr_ns);	
				}
			}
			key = NULL;
		}
		else if (key == NULL) {
			key = &xattrs[i];
		}
	}
	free(xattrs);
	
#endif
	return 0;
}

static size_t uwsgi_webdav_expand_path(struct wsgi_request *wsgi_req, char *item, uint16_t item_len, char *filename) {
	struct uwsgi_app *ua = &uwsgi_apps[wsgi_req->app_id];
	char *docroot = ua->interpreter;
	size_t docroot_len = strlen(docroot);

	// merge docroot with path_info
	char *tmp_filename = uwsgi_concat3n(docroot, docroot_len, "/", 1, item, item_len);
	// try expanding the path 
	if (!realpath(tmp_filename, filename)) {
		free(tmp_filename);
		return 0;
	}
	free(tmp_filename);
	return strlen(filename);
}

static size_t uwsgi_webdav_expand_fake_path(struct wsgi_request *wsgi_req, char *item, uint16_t item_len, char *filename) {
	char *last_slash = uwsgi_get_last_charn(item, item_len, '/');
        if (!last_slash) return 0;
        size_t filename_len = uwsgi_webdav_expand_path(wsgi_req, item, last_slash - item, filename);
        if (!filename_len) return 0;
        // check for overflow
        if (filename_len + (item_len - (last_slash - item)) >= PATH_MAX) return 0;
        memcpy(filename + filename_len, last_slash, (item_len - (last_slash - item)));
        filename_len += (item_len - (last_slash - item));
        filename[(int)filename_len] = 0;
	return filename_len;
}

static xmlDoc *uwsgi_webdav_manage_prop(struct wsgi_request *wsgi_req, xmlNode *req_prop, char *filename, size_t filename_len, int with_values) {
	// default 1 depth
	int depth = 1;
        uint16_t http_depth_len = 0;
        char *http_depth = uwsgi_get_var(wsgi_req, "HTTP_DEPTH", 10, &http_depth_len);
        if (http_depth) {
                depth = uwsgi_str_num(http_depth, http_depth_len);
        }

	xmlDoc *rdoc = xmlNewDoc(BAD_CAST "1.0");
        xmlNode *multistatus = xmlNewNode(NULL, BAD_CAST "multistatus");
        xmlDocSetRootElement(rdoc, multistatus);
        xmlNsPtr dav_ns = xmlNewNs(multistatus, BAD_CAST "DAV:", BAD_CAST "D");
        xmlSetNs(multistatus, dav_ns);

	if (depth == 0) {
                char *uri = uwsgi_concat2n(wsgi_req->path_info, wsgi_req->path_info_len, "", 0);
                uwsgi_webdav_add_props(wsgi_req, req_prop, multistatus, dav_ns, uri, filename, with_values);
                free(uri);
        }
        else {
                DIR *collection = opendir(filename);
                struct dirent de;
                for (;;) {
                        struct dirent *de_r = NULL;
                        if (readdir_r(collection, &de, &de_r)) {
                                uwsgi_error("uwsgi_wevdav_manage_propfind()/readdir_r()");
                                break;
                        }
                        if (de_r == NULL) {
                                break;
                        }
                        char *uri = NULL;
                        char *direntry = NULL;
                        if (!strcmp(de.d_name, "..")) {
                                // skip ..
                                continue;
                        }
                        else if (!strcmp(de.d_name, ".")) {
                                uri = uwsgi_concat2n(wsgi_req->path_info, wsgi_req->path_info_len, "", 0);
                                direntry = uwsgi_concat2n(filename, filename_len, "", 0);
                        }
                        else if (wsgi_req->path_info[wsgi_req->path_info_len - 1] == '/') {
                                uri = uwsgi_concat2n(wsgi_req->path_info, wsgi_req->path_info_len, de.d_name, strlen(de.d_name));
                                direntry = uwsgi_concat3n(filename, filename_len, "/", 1, de.d_name, strlen(de.d_name));
                        }
                        else {
                                uri = uwsgi_concat3n(wsgi_req->path_info, wsgi_req->path_info_len, "/", 1, de.d_name, strlen(de.d_name));
                                direntry = uwsgi_concat3n(filename, filename_len, "/", 1, de.d_name, strlen(de.d_name));
                        }
                        uwsgi_webdav_add_props(wsgi_req, req_prop, multistatus, dav_ns, uri, direntry, with_values);
                        free(uri);
                        free(direntry);
                }
                closedir(collection);
        }

	return rdoc;
	
}

static int uwsgi_wevdav_manage_propfind(struct wsgi_request *wsgi_req, xmlDoc * doc) {
	char filename[PATH_MAX];
	size_t filename_len = uwsgi_webdav_expand_path(wsgi_req, wsgi_req->path_info, wsgi_req->path_info_len, filename);
	if (filename_len == 0) {
		uwsgi_404(wsgi_req);
		return UWSGI_OK;
	}
	xmlDoc *rdoc = NULL;
	xmlNode *element = NULL;

	if (doc) {
		element = xmlDocGetRootElement(doc);
		if (!element) return -1;

		if (!element || strcmp((char *) element->name, "propfind")) return -1;
	}

	if (uwsgi_response_prepare_headers(wsgi_req, "207 Multi-Status", 16))
		return -1;
	if (uwsgi_response_add_content_type(wsgi_req, "application/xml; charset=\"utf-8\"", 32))
		return -1;

	if (doc) {
	// propfind must have a child (scan them until you find a valid one)
	xmlNode *node;
	for (node = element->children; node; node = node->next) {
		if (node->type == XML_ELEMENT_NODE) {
			if (node->ns && !strcmp((char *) node->ns->href, "DAV:")) {
                		if (!strcmp((char *) node->name, "prop")) {
					rdoc = uwsgi_webdav_manage_prop(wsgi_req, node, filename, filename_len, 1);
					break;
				}
				if (!strcmp((char *) node->name, "allprop")) {
					rdoc = uwsgi_webdav_manage_prop(wsgi_req, NULL, filename, filename_len, 1);
					break;
				}
				if (!strcmp((char *) node->name, "propname")) {
					rdoc = uwsgi_webdav_manage_prop(wsgi_req, node, filename, filename_len, 0);
					break;
				}
			}
		}
	}
	}
	else {
		rdoc = uwsgi_webdav_manage_prop(wsgi_req, NULL, filename, filename_len, 1);
	}

	if (!rdoc) return UWSGI_OK;

	xmlChar *xmlbuf;
	int xlen = 0;
	xmlDocDumpFormatMemory(rdoc, &xmlbuf, &xlen, 1);
	uwsgi_response_add_content_length(wsgi_req, xlen);
	uwsgi_response_write_body_do(wsgi_req, (char *) xmlbuf, xlen);
#ifdef UWSGI_DEBUG
	uwsgi_log("\n%.*s\n", xlen, xmlbuf);
#endif
	xmlFreeDoc(rdoc);
	xmlFree(xmlbuf);
	return UWSGI_OK;
}

static int uwsgi_webdav_prop_set(char *filename, char *attr, char *ns, char *body) {
	int ret = 0;
#if defined(__linux__) || defined(__APPLE__)
	char *xattr_name = NULL;
	if (ns) {
		xattr_name = uwsgi_concat4("user.uwsgi.webdav.", ns, "|", attr);
	}
	else {	
		xattr_name = uwsgi_concat2("user.uwsgi.webdav.", attr);
	}
#if defined(__linux__)
	ret = setxattr(filename, xattr_name, body, strlen(body), 0);
#elif defined(__APPLE__)
	ret = setxattr(filename, xattr_name, body, strlen(body), 0, 0);
#endif
	free(xattr_name);
#endif
	return ret; 
}

static int uwsgi_webdav_prop_del(char *filename, char *attr, char *ns) {
        int ret = 0;
#if defined(__linux__) || defined(__APPLE__)
        char *xattr_name = NULL;
        if (ns) {
                xattr_name = uwsgi_concat4("user.uwsgi.webdav.", ns, "|", attr);
        }
        else {
                xattr_name = uwsgi_concat2("user.uwsgi.webdav.", attr);
        }
#if defined(__linux__)
        ret = removexattr(filename, xattr_name);
#elif defined(__APPLE__)
        ret = removexattr(filename, xattr_name, 0);
#endif
        free(xattr_name);
#endif
        return ret;
}

static void uwsgi_webdav_do_prop_update(struct wsgi_request *wsgi_req, xmlNode *prop, xmlNode *response, char *filename, uint8_t action) {
	xmlNode *node;
        // search for "prop"
        for (node = prop->children; node; node = node->next) {
		if (node->type == XML_ELEMENT_NODE) {
			xmlNode *propstat = xmlNewChild(response, NULL, BAD_CAST "propstat", NULL);
			xmlNode *r_prop = xmlNewChild(propstat, NULL, BAD_CAST "prop" , NULL);
			xmlNode *new_prop = xmlNewChild(r_prop, NULL, node->name, NULL);
			if (node->ns) {
				xmlNsPtr xattr_ns = xmlNewNs(new_prop, node->ns->href, NULL);
                                xmlSetNs(new_prop, xattr_ns);
			}
			if (action == 0) {
				if (uwsgi_webdav_prop_set(filename, (char *) node->name, node->ns ? (char *) node->ns->href : NULL, node->children ? (char *) node->children->content : "")) {
					char *r_status = uwsgi_concat2n(wsgi_req->protocol, wsgi_req->protocol_len, " 403 Forbidden", 14);
					xmlNewChild(r_prop, NULL, BAD_CAST "status", BAD_CAST r_status);
					free(r_status);
				}
				else {
					char *r_status = uwsgi_concat2n(wsgi_req->protocol, wsgi_req->protocol_len, " 200 OK", 7);
					xmlNewChild(r_prop, NULL, BAD_CAST "status", BAD_CAST r_status);
					free(r_status);
				}
			}
			else if (action == 1) {
				if (uwsgi_webdav_prop_del(filename, (char *) node->name, node->ns ? (char *) node->ns->href : NULL)) {
					char *r_status = uwsgi_concat2n(wsgi_req->protocol, wsgi_req->protocol_len, " 403 Forbidden", 14);
					xmlNewChild(r_prop, NULL, BAD_CAST "status", BAD_CAST r_status);
					free(r_status);
				}
				else {
					char *r_status = uwsgi_concat2n(wsgi_req->protocol, wsgi_req->protocol_len, " 200 OK", 7);
					xmlNewChild(r_prop, NULL, BAD_CAST "status", BAD_CAST r_status);
					free(r_status);
				}
			}
		}
	}
}

// action 0 is set, 1 is remove
static void uwsgi_webdav_manage_prop_update(struct wsgi_request *wsgi_req, xmlNode *parent, xmlNode *response, char *filename, uint8_t action) {
	xmlNode *node;
	// search for "prop"
	for (node = parent->children; node; node = node->next) {
		if (node->type == XML_ELEMENT_NODE) {
			if (node->ns && !strcmp((char *) node->ns->href, "DAV:")) {
				if (!strcmp((char *) node->name, "prop")) {
					uwsgi_webdav_do_prop_update(wsgi_req, node, response, filename, action);
				}
			}
		}
	}
}

static int uwsgi_wevdav_manage_proppatch(struct wsgi_request *wsgi_req, xmlDoc * doc) {
        char filename[PATH_MAX];
        size_t filename_len = uwsgi_webdav_expand_path(wsgi_req, wsgi_req->path_info, wsgi_req->path_info_len, filename);
        if (filename_len == 0) {
                uwsgi_404(wsgi_req);
                return UWSGI_OK;
        }

        xmlNode *element = xmlDocGetRootElement(doc);
        if (!element) return -1;

        if (!element || (strcmp((char *) element->name, "propertyupdate"))) return -1;

        if (uwsgi_response_prepare_headers(wsgi_req, "207 Multi-Status", 16))
                return -1;
        if (uwsgi_response_add_content_type(wsgi_req, "application/xml; charset=\"utf-8\"", 32))
                return -1;

	xmlDoc *rdoc = xmlNewDoc(BAD_CAST "1.0");
        xmlNode *multistatus = xmlNewNode(NULL, BAD_CAST "multistatus");
        xmlDocSetRootElement(rdoc, multistatus);
        xmlNsPtr dav_ns = xmlNewNs(multistatus, BAD_CAST "DAV:", BAD_CAST "D");
        xmlSetNs(multistatus, dav_ns);
	xmlNode *response = xmlNewChild(multistatus, dav_ns, BAD_CAST "response", NULL);

	char *uri = uwsgi_concat2n(wsgi_req->path_info, wsgi_req->path_info_len, "", 0);
        uint16_t uri_len = strlen(uri) ;
        char *encoded_uri = uwsgi_malloc( (uri_len * 3) + 1);
        http_url_encode(uri, &uri_len, encoded_uri);
        encoded_uri[uri_len] = 0;
        xmlNewChild(response, dav_ns, BAD_CAST "href", BAD_CAST encoded_uri);
        free(encoded_uri);

        // propfind can be "set" or "remove"
        xmlNode *node;
        for (node = element->children; node; node = node->next) {
                if (node->type == XML_ELEMENT_NODE) {
                        if (node->ns && !strcmp((char *) node->ns->href, "DAV:")) {
                                if (!strcmp((char *) node->name, "set")) {
                                	uwsgi_webdav_manage_prop_update(wsgi_req, node, response, filename, 0);
                                }
                                else if (!strcmp((char *) node->name, "remove")) {
                                	uwsgi_webdav_manage_prop_update(wsgi_req, node, response, filename, 1);
                                }
                        }
                }
        }

        if (!rdoc) return UWSGI_OK;

        xmlChar *xmlbuf;
        int xlen = 0;
        xmlDocDumpFormatMemory(rdoc, &xmlbuf, &xlen, 1);
        uwsgi_response_add_content_length(wsgi_req, xlen);
        uwsgi_response_write_body_do(wsgi_req, (char *) xmlbuf, xlen);
#ifdef UWSGI_DEBUG
        uwsgi_log("\n%.*s\n", xlen, xmlbuf);
#endif
        xmlFreeDoc(rdoc);
        xmlFree(xmlbuf);
        return UWSGI_OK;
}


static int uwsgi_wevdav_manage_put(struct wsgi_request *wsgi_req) {
	char filename[PATH_MAX];
        size_t filename_len = uwsgi_webdav_expand_path(wsgi_req, wsgi_req->path_info, wsgi_req->path_info_len, filename);
        // the collection does not exist, search for the last /
        if (!filename_len) {
		filename_len = uwsgi_webdav_expand_fake_path(wsgi_req, wsgi_req->path_info, wsgi_req->path_info_len, filename);
		if (!filename_len) {
                        uwsgi_response_prepare_headers(wsgi_req, "409 Conflict", 12);
                        return UWSGI_OK;
                }
        }

	int fd = open(filename, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd < 0) {
		uwsgi_403(wsgi_req);
                return UWSGI_OK;
	}

	if (uwsgi_response_prepare_headers(wsgi_req, "201 Created", 11)) goto end;
	
	size_t remains = wsgi_req->post_cl;
	while(remains > 0) {
		ssize_t body_len = 0;
		char *body =  uwsgi_request_body_read(wsgi_req, UMIN(remains, 32768) , &body_len);
		if (!body || body == uwsgi.empty) break;
		if (write(fd, body, body_len) != body_len) goto end;
	}

end:
	close(fd);
	return UWSGI_OK;
}

static int uwsgi_webdav_massive_delete(char *dir) {
	int ret = 0;
	DIR *d = opendir(dir);
	for (;;) {
        	struct dirent *de_r = NULL;
		struct dirent de;
                if (readdir_r(d, &de, &de_r)) {
			ret = -1;
			goto end;
		}
		if (de_r == NULL) break;
		// skip myself and parent
		if (!strcmp(de.d_name, ".") || !strcmp(de.d_name, "..")) continue;
		char *item = uwsgi_concat3(dir, "/", de.d_name);
		if (de.d_type == DT_DIR) {
			if (uwsgi_webdav_massive_delete(item)) {
				free(item);
				ret = -1;
				goto end;
			}
		}
		else {
			if (unlink(item)) {
				free(item);
				ret = -1;
				goto end;
			}
		}
		free(item);
	}
	if (rmdir(dir)) ret = -1;
end:
	closedir(d);
	return ret;
}

static int uwsgi_wevdav_manage_delete(struct wsgi_request *wsgi_req) {
	char filename[PATH_MAX];
	size_t filename_len = uwsgi_webdav_expand_path(wsgi_req, wsgi_req->path_info, wsgi_req->path_info_len, filename);
	// the collection does not exists
	if (!filename_len) {
		uwsgi_404(wsgi_req);
		return UWSGI_OK;
	}

	if (uwsgi_is_dir(filename)) {
		int ret = rmdir(filename);
		if (ret < 0) {
			if (errno == ENOTEMPTY) {
				if (uwsgi_webdav_massive_delete(filename)) {
					uwsgi_403(wsgi_req);
					return UWSGI_OK;
				}
			}
			else {
				uwsgi_403(wsgi_req);
				return UWSGI_OK;
			}
		}
	}
	else {
		if (unlink(filename)) {
			uwsgi_403(wsgi_req);
			return UWSGI_OK;
		}
	}

	uwsgi_response_prepare_headers(wsgi_req, "200 OK", 6);
	return UWSGI_OK;
}

static int uwsgi_webdav_dirlist_add_item(struct uwsgi_buffer *ub, char *item, size_t item_len, uint8_t is_dir) {
	if (is_dir) {
		if (udav.class_directory) {
			if (uwsgi_buffer_append(ub, "<li class=\"", 11)) return -1;
			if (uwsgi_buffer_append(ub, udav.class_directory, strlen(udav.class_directory))) return -1;
			if (uwsgi_buffer_append(ub, "\"><a href=\"", 11)) return -1;
		}
		else {
			if (uwsgi_buffer_append(ub, "<li class=\"directory\"><a href=\"", 31)) return -1;
		}
	}
	else {
		if (uwsgi_buffer_append(ub, "<li><a href=\"", 13)) return -1;
	}
        if (uwsgi_buffer_append(ub, item, item_len)) return -1;
	if (is_dir) {
        	if (uwsgi_buffer_append(ub, "/\">", 3)) return -1;
        	if (uwsgi_buffer_append(ub, item, item_len)) return -1;
        	if (uwsgi_buffer_append(ub, "/", 1)) return -1;
	}
	else {
        	if (uwsgi_buffer_append(ub, "\">", 2)) return -1;
        	if (uwsgi_buffer_append(ub, item, item_len)) return -1;
	}
        if (uwsgi_buffer_append(ub, "</a></li>", 9)) return -1;
	return 0;
}

static void uwsgi_webdav_dirlist(struct wsgi_request *wsgi_req, char *dir) {
	struct uwsgi_buffer *ub = uwsgi_buffer_new(uwsgi.page_size);
	if (uwsgi_buffer_append(ub, "<html><head><title>", 19)) goto end;
	if (uwsgi_buffer_append(ub, dir, strlen(dir))) goto end;
	if (uwsgi_buffer_append(ub, "</title>", 8)) goto end;

	struct uwsgi_string_list *usl = udav.css;
	while(usl) {
		if (uwsgi_buffer_append(ub, "<link rel=\"stylesheet\" href=\"", 29)) goto end;
		if (uwsgi_buffer_append(ub, usl->value, usl->len)) goto end;
		if (uwsgi_buffer_append(ub, "\" type=\"text/css\">", 18)) goto end;
		usl = usl->next;
	}

	
	usl = udav.javascript;
	while(usl) {
		if (uwsgi_buffer_append(ub, "<script src=\"", 13)) goto end;
		if (uwsgi_buffer_append(ub, usl->value, usl->len)) goto end;
		if (uwsgi_buffer_append(ub, "\"></script>", 11)) goto end;
		usl = usl->next;
	}

	if (uwsgi_buffer_append(ub, "</head><body>", 13)) goto end;

	if (udav.div) {
		if (uwsgi_buffer_append(ub, "<div id=\"", 9)) goto end;
		if (uwsgi_buffer_append(ub, udav.div, strlen(udav.div))) goto end;
		if (uwsgi_buffer_append(ub, "\">", 2)) goto end;
	}
	else {
		if (uwsgi_buffer_append(ub, "<div>", 5)) goto end;
	}
	if (uwsgi_webdav_dirlist_add_item(ub, "..", 2, 1)) goto end;

#ifdef __linux__
	struct dirent **tasklist;
        int n = scandir(dir, &tasklist, 0, versionsort);
        if (n < 0) goto end;
	int i;
	for(i=0;i<n;i++) {
		if (tasklist[i]->d_name[0] == '.') goto next;	
		if (uwsgi_webdav_dirlist_add_item(ub, tasklist[i]->d_name, strlen(tasklist[i]->d_name), tasklist[i]->d_type == DT_DIR ? 1 : 0)) {
			free(tasklist[i]);
			free(tasklist);	
			goto end;
		}
next:
                free(tasklist[i]);
        }

        free(tasklist);
#else
	DIR *d = opendir(dir);
        for (;;) {
                struct dirent *de_r = NULL;
                struct dirent de;
                if (readdir_r(d, &de, &de_r)) goto end;
                if (de_r == NULL) break;
		// skip items startign with a dot
		if (de.d_name[0] == '.') continue;
		if (uwsgi_webdav_dirlist_add_item(ub, de.d_name, strlen(de.d_name), de.d_type == DT_DIR ? 1 : 0)) goto end;
        }

	closedir(d);
#endif

	if (uwsgi_buffer_append(ub, "</ul></div></body></html>", 25)) goto end;

	if (uwsgi_response_add_content_type(wsgi_req, "text/html", 9)) goto end;	
	if (uwsgi_response_add_content_length(wsgi_req, ub->pos)) goto end;	

	uwsgi_response_write_body_do(wsgi_req, ub->buf, ub->pos);
end:
	uwsgi_buffer_destroy(ub);
}

static int uwsgi_wevdav_manage_get(struct wsgi_request *wsgi_req, int send_body) {
	char filename[PATH_MAX];
	size_t filename_len = uwsgi_webdav_expand_path(wsgi_req, wsgi_req->path_info, wsgi_req->path_info_len, filename);
	if (!filename_len) {
		uwsgi_404(wsgi_req);
		return UWSGI_OK;
	}

	if (uwsgi_is_dir(filename)) {
		uwsgi_response_prepare_headers(wsgi_req, "200 OK", 6);
		if (send_body) {
			uwsgi_webdav_dirlist(wsgi_req, filename);
		}
		return UWSGI_OK;
	}

	int fd = open(filename, O_RDONLY);
	if (fd < 0) {
		uwsgi_403(wsgi_req);
		return UWSGI_OK;
	}
	struct stat st;
	if (fstat(fd, &st)) {
		close(fd);
		uwsgi_403(wsgi_req);
		return UWSGI_OK;
	}

	if (uwsgi_response_prepare_headers(wsgi_req, "200 OK", 6))
		goto end;
	// add content_length
	if (uwsgi_response_add_content_length(wsgi_req, st.st_size))
		goto end;
	// add last-modified
	if (uwsgi_response_add_last_modified(wsgi_req, st.st_mtime))
		goto end;
	// add mime_type
	size_t mime_type_len = 0;
	char *mime_type = uwsgi_get_mime_type(filename, filename_len, &mime_type_len);
	if (mime_type) {
		if (uwsgi_response_add_content_type(wsgi_req, mime_type, mime_type_len))
			goto end;
	}
	// add ETag (based on file mtime, not rock-solid, but good enough)
	char *etag = uwsgi_num2str(st.st_mtime);
	if (uwsgi_response_add_header(wsgi_req, "ETag", 4, etag, strlen(etag))) {
		free(etag);
		goto end;
	}
	free(etag);
	// start sending the file (note: we do not use sendfile() api, for being able to use caching and transformations)
	if (!send_body)
		goto end;
	// use a pretty big buffer (for performance reasons)
	char buf[32768];
	size_t remains = st.st_size;
	while (remains > 0) {
		ssize_t rlen = read(fd, buf, UMIN(32768, remains));
		if (rlen <= 0) {
			uwsgi_error("uwsgi_wevdav_manage_get/read()");
			break;
		}
		remains -= rlen;
		if (uwsgi_response_write_body_do(wsgi_req, buf, rlen)) {
			break;
		}
	}
end:
	close(fd);
	return UWSGI_OK;
}

static int uwsgi_wevdav_manage_copy(struct wsgi_request *wsgi_req) {
	uint16_t destination_len = 0;
	char *destination = uwsgi_get_var(wsgi_req, "HTTP_DESTINATION", 16, &destination_len);
	uwsgi_log("Destination: %.*s\n", destination_len, destination);
	return -1;
}

static int uwsgi_wevdav_manage_move(struct wsgi_request *wsgi_req) {
	char filename[PATH_MAX];
	char d_filename[PATH_MAX];
        size_t filename_len = uwsgi_webdav_expand_path(wsgi_req, wsgi_req->path_info, wsgi_req->path_info_len, filename);
        if (filename_len == 0) {
		uwsgi_404(wsgi_req);
                return UWSGI_OK;
        }

	uint16_t destination_len = 0;
	char *destination = uwsgi_get_var(wsgi_req, "HTTP_DESTINATION", 16, &destination_len);
	if (destination_len == 0) {
		uwsgi_403(wsgi_req);
		return UWSGI_OK;
	}

	uint16_t overwrite_len = 0;
	int can_overwrite = 1;
	char *overwrite = uwsgi_get_var(wsgi_req, "HTTP_OVERWRITE", 14, &overwrite_len);
	if (overwrite) {
		if (overwrite[0] == 'F') {
			can_overwrite = 0;
		}
	}


	uint16_t scheme_len = wsgi_req->scheme_len;
	if (wsgi_req->scheme_len == 0) {
		// http
		scheme_len = 4;
	}
	uint16_t skip = scheme_len + 3 + wsgi_req->host_len;
	int already_exists = 0;
	size_t d_filename_len = uwsgi_webdav_expand_path(wsgi_req, destination + skip, destination_len - skip, d_filename);
	if (d_filename_len > 0) {
		already_exists = 1;
		if (!can_overwrite) {
			uwsgi_response_prepare_headers(wsgi_req, "412 Precondition Failed", 23);
                	return UWSGI_OK;
		}
	}
	else {
		d_filename_len = uwsgi_webdav_expand_fake_path(wsgi_req, destination + skip, destination_len - skip, d_filename);
	}
	
	if (d_filename_len == 0) {
        	uwsgi_response_prepare_headers(wsgi_req, "409 Conflict", 12);
                return UWSGI_OK;
	}
	
	if (rename(filename, d_filename)) {
		uwsgi_403(wsgi_req);
		return UWSGI_OK;
	}

	if (already_exists) {
		uwsgi_response_prepare_headers(wsgi_req, "204 No Content", 14);
	}
	else {
		uwsgi_response_prepare_headers(wsgi_req, "201 Created", 11);
	}

	return UWSGI_OK;
}

static int uwsgi_wevdav_manage_mkcol(struct wsgi_request *wsgi_req) {
	if (wsgi_req->post_cl > 0) {
		uwsgi_response_prepare_headers(wsgi_req, "415 Unsupported Media Type", 26);
		return UWSGI_OK;
	}
	char filename[PATH_MAX];
	size_t filename_len = uwsgi_webdav_expand_path(wsgi_req, wsgi_req->path_info, wsgi_req->path_info_len, filename);
	// the collection already exists
	if (filename_len > 0) {
		uwsgi_response_prepare_headers(wsgi_req, "405 Method Not Allowed", 22);
		return UWSGI_OK;
	}

	// remove the last slash (if needed)
	if (wsgi_req->path_info_len > 1 && wsgi_req->path_info[wsgi_req->path_info_len-1] == '/') {
		wsgi_req->path_info_len--;
	}

	filename_len = uwsgi_webdav_expand_fake_path(wsgi_req, wsgi_req->path_info, wsgi_req->path_info_len, filename);
        if (!filename_len) {
        	uwsgi_response_prepare_headers(wsgi_req, "409 Conflict", 12);
                return UWSGI_OK;
        }
	// mkdir, if it fails, return a 409 (Conflict)
	if (mkdir(filename, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)) {
		uwsgi_response_prepare_headers(wsgi_req, "409 Conflict", 12);
	}
	uwsgi_response_prepare_headers(wsgi_req, "201 Created", 11);
	return UWSGI_OK;
}

static int uwsgi_wevdav_manage_mkcalendar(struct wsgi_request *wsgi_req, xmlDoc *doc) {
        char filename[PATH_MAX];
        size_t filename_len = uwsgi_webdav_expand_path(wsgi_req, wsgi_req->path_info, wsgi_req->path_info_len, filename);
        // the collection already exists
        if (filename_len > 0) {
                uwsgi_response_prepare_headers(wsgi_req, "405 Method Not Allowed", 22);
                return UWSGI_OK;
        }

        // remove the last slash (if needed)
        if (wsgi_req->path_info_len > 1 && wsgi_req->path_info[wsgi_req->path_info_len-1] == '/') {
                wsgi_req->path_info_len--;
        }

        filename_len = uwsgi_webdav_expand_fake_path(wsgi_req, wsgi_req->path_info, wsgi_req->path_info_len, filename);
        if (!filename_len) {
                uwsgi_response_prepare_headers(wsgi_req, "409 Conflict", 12);
                return UWSGI_OK;
        }
        // mkdir, if it fails, return a 409 (Conflict)
        if (mkdir(filename, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)) {
                uwsgi_response_prepare_headers(wsgi_req, "409 Conflict", 12);
		return UWSGI_OK;
        }

	xmlNode *element = xmlDocGetRootElement(doc);
        if (!element) return -1;

        if (!element || (strcmp((char *) element->name, "mkcalendar"))) return -1;

        xmlDoc *rdoc = xmlNewDoc(BAD_CAST "1.0");
        xmlNode *foobar = xmlNewNode(NULL, BAD_CAST "foobar");
        xmlDocSetRootElement(rdoc, foobar);

        // propfind can be "set" or "remove"
        xmlNode *node;
        for (node = element->children; node; node = node->next) {
                if (node->type == XML_ELEMENT_NODE) {
                        if (node->ns && !strcmp((char *) node->ns->href, "DAV:")) {
                                if (!strcmp((char *) node->name, "set")) {
                                        uwsgi_webdav_manage_prop_update(wsgi_req, node, foobar, filename, 0);
                                }
                        }
                }
        }

	uwsgi_response_prepare_headers(wsgi_req, "201 Created", 11);
        xmlFreeDoc(rdoc);
        return UWSGI_OK;
}


static int uwsgi_wevdav_manage_lock(struct wsgi_request *wsgi_req) {
	uwsgi_response_prepare_headers(wsgi_req, "201 Created", 11);
        return UWSGI_OK;
}

static int uwsgi_webdav_request(struct wsgi_request *wsgi_req) {

	if (!udav.mountpoints) {
		uwsgi_500(wsgi_req);
		return -1;
	}

	if (uwsgi_parse_vars(wsgi_req)) {
		return -1;
	}

	if (wsgi_req->path_info_len == 0) {
		uwsgi_403(wsgi_req);
		return UWSGI_OK;
	}

	wsgi_req->app_id = uwsgi_get_app_id(wsgi_req, wsgi_req->appid, wsgi_req->appid_len, webdav_plugin.modifier1);
        if (wsgi_req->app_id == -1) {
                uwsgi_403(wsgi_req);
                return UWSGI_OK;
        }

	// non lockables methods...

	if (!uwsgi_strncmp(wsgi_req->method, wsgi_req->method_len, "OPTIONS", 7)) {
		return uwsgi_wevdav_manage_options(wsgi_req);
	}

	if (!uwsgi_strncmp(wsgi_req->method, wsgi_req->method_len, "GET", 3)) {
		return uwsgi_wevdav_manage_get(wsgi_req, 1);
	}

	if (!uwsgi_strncmp(wsgi_req->method, wsgi_req->method_len, "HEAD", 4)) {
		return uwsgi_wevdav_manage_get(wsgi_req, 0);
	}

	if (!uwsgi_strncmp(wsgi_req->method, wsgi_req->method_len, "PROPFIND", 8)) {
		if (wsgi_req->post_cl > 0) {
			ssize_t body_len = 0;
			char *body = uwsgi_request_body_read(wsgi_req, wsgi_req->post_cl, &body_len);
#ifdef UWSGI_DEBUG
			uwsgi_log("%.*s\n", body_len, body);
#endif
			xmlDoc *doc = xmlReadMemory(body, body_len, NULL, NULL, 0);
			if (!doc) goto end;
			uwsgi_wevdav_manage_propfind(wsgi_req, doc);
			xmlFreeDoc(doc);
		}
		else {
			uwsgi_wevdav_manage_propfind(wsgi_req, NULL);
		}
	}

	if (!uwsgi_strncmp(wsgi_req->method, wsgi_req->method_len, "REPORT", 6)) {
                if (wsgi_req->post_cl > 0) {
                        ssize_t body_len = 0;
                        char *body = uwsgi_request_body_read(wsgi_req, wsgi_req->post_cl, &body_len);
#ifdef UWSGI_DEBUG
                        uwsgi_log("%.*s\n", body_len, body);
#endif
                        xmlDoc *doc = xmlReadMemory(body, body_len, NULL, NULL, 0);
                        if (!doc) goto end;
                        xmlFreeDoc(doc);
                }
        }


	// lockable methods ...
	// check for locking

	if (!uwsgi_strncmp(wsgi_req->method, wsgi_req->method_len, "PUT", 3)) {
		return uwsgi_wevdav_manage_put(wsgi_req);
	}

	if (!uwsgi_strncmp(wsgi_req->method, wsgi_req->method_len, "DELETE", 6)) {
		return uwsgi_wevdav_manage_delete(wsgi_req);
	}

	if (!uwsgi_strncmp(wsgi_req->method, wsgi_req->method_len, "MKCOL", 5)) {
		return uwsgi_wevdav_manage_mkcol(wsgi_req);
	}

	if (!uwsgi_strncmp(wsgi_req->method, wsgi_req->method_len, "MKCALENDAR", 10)) {
		if (wsgi_req->post_cl == 0)
                        goto end;
                ssize_t body_len = 0;
                char *body = uwsgi_request_body_read(wsgi_req, wsgi_req->post_cl, &body_len);
#ifdef UWSGI_DEBUG
                uwsgi_log("%.*s\n", body_len, body);
#endif
                xmlDoc *doc = xmlReadMemory(body, body_len, NULL, NULL, 0);
                if (!doc) goto end;
                uwsgi_wevdav_manage_mkcalendar(wsgi_req, doc);
                xmlFreeDoc(doc);
	}

	if (!uwsgi_strncmp(wsgi_req->method, wsgi_req->method_len, "COPY", 4)) {
		return uwsgi_wevdav_manage_copy(wsgi_req);
	}

	if (!uwsgi_strncmp(wsgi_req->method, wsgi_req->method_len, "MOVE", 4)) {
		return uwsgi_wevdav_manage_move(wsgi_req);
	}

	if (!uwsgi_strncmp(wsgi_req->method, wsgi_req->method_len, "LOCK", 4)) {
		if (wsgi_req->post_cl > 0) {
			ssize_t body_len = 0;
                	char *body = uwsgi_request_body_read(wsgi_req, wsgi_req->post_cl, &body_len);
#ifdef UWSGI_DEBUG
                	uwsgi_log("%.*s\n", body_len, body);
#endif
			xmlDoc *doc = xmlReadMemory(body, body_len, NULL, NULL, 0);
			if (!doc) goto end;
                	xmlFreeDoc(doc);
		}	
		return uwsgi_wevdav_manage_lock(wsgi_req);
	}

	if (!uwsgi_strncmp(wsgi_req->method, wsgi_req->method_len, "PROPPATCH", 9)) {
                if (wsgi_req->post_cl == 0)
                        goto end;
                ssize_t body_len = 0;
                char *body = uwsgi_request_body_read(wsgi_req, wsgi_req->post_cl, &body_len);
#ifdef UWSGI_DEBUG
                uwsgi_log("%.*s\n", body_len, body);
#endif
                xmlDoc *doc = xmlReadMemory(body, body_len, NULL, NULL, 0);
                if (!doc) goto end;
		uwsgi_wevdav_manage_proppatch(wsgi_req, doc);
                xmlFreeDoc(doc);
        }

end:
	return UWSGI_OK;
}

static void uwsgi_webdav_mount() {
	struct uwsgi_string_list *usl = udav.mountpoints;
	while(usl) {
		if (uwsgi_apps_cnt >= uwsgi.max_apps) {
                        uwsgi_log("ERROR: you cannot load more than %d apps in a worker\n", uwsgi.max_apps);
                        exit(1);
                }
                int id = uwsgi_apps_cnt;
		char *mountpoint = "";
		int mountpoint_len = 0;
		char *docroot = usl->value;

		char *equal = strchr(usl->value, '=');
		
		if (equal) {
			*equal = 0;
			docroot = equal+1;
			mountpoint = usl->value;
			mountpoint_len = strlen(mountpoint);
		}

		char *wd_docroot = uwsgi_calloc(PATH_MAX);
		if (!realpath(docroot, wd_docroot)) {
			uwsgi_error("uwsgi_webdav_mount()/realpath()");
			exit(1);
		}
		if (equal) {
			*equal = '=';
		}
                struct uwsgi_app *ua = uwsgi_add_app(id, webdav_plugin.modifier1, mountpoint, mountpoint_len, wd_docroot, wd_docroot);
                uwsgi_emulate_cow_for_apps(id);
                uwsgi_log("WebDAV mountpoint \"%.*s\" (%d) added: docroot=%s\n", ua->mountpoint_len, ua->mountpoint, id, wd_docroot );
		usl = usl->next;
	}
}

static void uwsgi_webdav_after_request(struct wsgi_request *wsgi_req) {
	if (!udav.mountpoints) return;
	log_request(wsgi_req);
}

struct uwsgi_plugin webdav_plugin = {
	.modifier1 = 35,
	.name = "webdav",
	.options = uwsgi_webdav_options,
	.init_apps = uwsgi_webdav_mount,
	.request = uwsgi_webdav_request,
	.after_request = uwsgi_webdav_after_request,
};
