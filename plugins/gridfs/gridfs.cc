#include <uwsgi.h>

#include <client/dbclient.h>
#include <client/gridfs.h>

struct uwsgi_gridfs_mountpoint {
	char *mountpoint;
	uint16_t mountpoint_len;
	char *server;
	char *db;
	char *timeout_str;
	int timeout;
	char *no_mime;
	char *orig_filename;
	char *md5;
	char *etag;
	char *prefix;
	char *itemname;
	uint16_t itemname_len;
	char *skip_slash;
	uint16_t prefix_len;
	char *username;
	char *password;
};

struct uwsgi_gridfs {
	int debug;
	struct uwsgi_string_list *mountpoints;
} ugridfs;

struct uwsgi_option uwsgi_gridfs_options[] = {
	{(char *)"gridfs-mount", required_argument, 0, (char *)"mount a gridfs db on the specified mountpoint", uwsgi_opt_add_string_list, &ugridfs.mountpoints, UWSGI_OPT_MIME},
	{(char *)"gridfs-debug", no_argument, 0, (char *)"report gridfs mountpoint and itemname for each request (debug)", uwsgi_opt_true, &ugridfs.debug, UWSGI_OPT_MIME},
	{0, 0, 0, 0, 0, 0, 0},
};

extern struct uwsgi_server uwsgi;
extern struct uwsgi_plugin gridfs_plugin;

static void uwsgi_gridfs_do(struct wsgi_request *wsgi_req, struct uwsgi_gridfs_mountpoint *ugm, char *itemname, int need_free) {

	try {
		mongo::scoped_ptr<mongo::ScopedDbConnection> conn( mongo::ScopedDbConnection::getScopedDbConnection(ugm->server, ugm->timeout) );
		try {
			if (ugm->username && ugm->password) {
				std::string errmsg;
				if ((*conn).conn().auth(ugm->db, ugm->username, ugm->password, errmsg)) {
					uwsgi_log("[uwsgi-gridfs]: %s\n", errmsg.c_str());
					(*conn).done();
					uwsgi_403(wsgi_req);
					return;
				}
			}
			mongo::GridFS gridfs((*conn).conn(), ugm->db);
			mongo::GridFile gfile = gridfs.findFile(itemname);
			if (need_free) {
				free(itemname);
				itemname = NULL;
			}
			if (!gfile.exists()) {
				(*conn).done();
				uwsgi_404(wsgi_req);
				return;
			}
			uwsgi_response_prepare_headers(wsgi_req, (char *)"200 OK", 6);
			// first get the content_type (if possibile)
			std::string filename = gfile.getFilename();
			if (!ugm->no_mime) {
				size_t mime_type_len = 0;
				char *mime_type = uwsgi_get_mime_type((char *)filename.c_str(), filename.length(), &mime_type_len);
				if (mime_type) {
					uwsgi_response_add_content_type(wsgi_req, mime_type, mime_type_len);
				}
			}
			if (ugm->orig_filename) {
				char *filename_header = uwsgi_concat3((char *)"inline; filename=\"", (char *)filename.c_str(), (char *)"\"");
				uwsgi_response_add_header(wsgi_req, (char *)"Content-Disposition", 19, filename_header, 19 + filename.length());
				free(filename_header);
			}
			uwsgi_response_add_content_length(wsgi_req, gfile.getContentLength());

			char http_last_modified[49];
			time_t t = gfile.getUploadDate().toTimeT();
			int size = uwsgi_http_date(t, http_last_modified);
                	uwsgi_response_add_header(wsgi_req, (char *)"Last-Modified", 13, http_last_modified, size);

			if (ugm->etag) {
				std::string g_md5 = gfile.getMD5();
				if (!g_md5.empty()) {
					char *etag = uwsgi_concat3((char *)"\"", (char *)g_md5.c_str(), (char *)"\"");
					uwsgi_response_add_header(wsgi_req, (char *)"ETag", 4, etag, 2+g_md5.length());
					free(etag);
				}	
			}

			if (ugm->md5) {
				std::string g_md5 = gfile.getMD5();
				size_t base64_len = 0;
				char *base64 = uwsgi_base64_encode((char *)g_md5.c_str(), g_md5.length(), &base64_len);
				uwsgi_response_add_header(wsgi_req, (char *) "Content-MD5", 11, base64, base64_len);
				free(base64);
			}

			if (uwsgi_strncmp(wsgi_req->method, wsgi_req->method_len, (char *)"HEAD", 4)) {
				int nc = gfile.getNumChunks();
				int i;
				for(i=0;i<nc;i++) {
					mongo::GridFSChunk gchunk = gfile.getChunk(i);
					int chunk_len = 0;	
					const char *chunk = gchunk.data(chunk_len);
					uwsgi_response_write_body_do(wsgi_req, (char *) chunk, chunk_len);
				}
			}
			(*conn).done();
		}
		catch ( mongo::DBException &e ) {
			uwsgi_log("[uwsgi-gridfs]: %s\n", e.what());
			(*conn).done();
			if (need_free && itemname) {
				free(itemname);
				itemname = NULL;
			}
		}
	}	
	catch ( mongo::DBException &e ) {
		uwsgi_log("[uwsgi-gridfs]: %s\n", e.what());
		if (need_free && itemname) {
			free(itemname);
			itemname = NULL;
		}
	}
}


static struct uwsgi_gridfs_mountpoint *uwsgi_gridfs_add_mountpoint(char *arg, size_t arg_len) {
	struct uwsgi_gridfs_mountpoint *ugm = (struct uwsgi_gridfs_mountpoint *) uwsgi_calloc(sizeof(struct uwsgi_gridfs_mountpoint));
	if (uwsgi_kvlist_parse(arg, arg_len, ',', '=',
                        "mountpoint", &ugm->mountpoint,
                        "server", &ugm->server,
                        "db", &ugm->db,
                        "prefix", &ugm->prefix,
                        "no_mime", &ugm->no_mime,
                        "timeout", &ugm->timeout_str,
                        "orig_filename", &ugm->orig_filename,
                        "skip_slash", &ugm->skip_slash,
                        "md5", &ugm->md5,
                        "etag", &ugm->etag,
                        "itemname", &ugm->itemname,
                        "item", &ugm->itemname,
                        "username", &ugm->username,
                        "password", &ugm->password,
                        NULL)) {
                        uwsgi_log("invalid gridfs mountpoint syntax\n");
			free(ugm);
			return NULL;
        }

	if (!ugm->db) {
		uwsgi_log("you need to specify a \"db\" name for gridfs\n");
		free(ugm);
		return NULL;
	}

	if (!ugm->mountpoint) {
		ugm->mountpoint = (char *)"";
	}
	ugm->mountpoint_len = strlen(ugm->mountpoint);

	if (!ugm->server) {
		ugm->server = (char *)"127.0.0.1:27017";
	}

	if (ugm->timeout_str) {
		ugm->timeout = atoi(ugm->timeout_str);
	}
	else {
		ugm->timeout = uwsgi.socket_timeout;
	}

	if (ugm->prefix) {
		ugm->prefix_len = strlen(ugm->prefix);
	}

	if (ugm->itemname) {
		ugm->itemname_len = strlen(ugm->itemname);
	}

	return ugm;
}

extern "C" int uwsgi_gridfs_request(struct wsgi_request *wsgi_req) {
        // this is the gridfs file
        char *itemname = NULL;

        /* Standard GridFS request */
        if (!wsgi_req->uh->pktsize) {
                uwsgi_log( "Empty GridFS request. skip.\n");
                return -1;
        }

        if (uwsgi_parse_vars(wsgi_req)) {
                return -1;
        }

        wsgi_req->app_id = uwsgi_get_app_id(wsgi_req, wsgi_req->appid, wsgi_req->appid_len, gridfs_plugin.modifier1);
        if (ugridfs.debug) {
                uwsgi_log("[uwsgi-gridfs-debug] app_id = %d\n", wsgi_req->app_id);
        }

        if (wsgi_req->app_id == -1) {
                uwsgi_404(wsgi_req);
                return UWSGI_OK;
        }

        struct uwsgi_app *ua = &uwsgi_apps[wsgi_req->app_id];

        struct uwsgi_gridfs_mountpoint *ugm = (struct uwsgi_gridfs_mountpoint *) ua->interpreter;

        if (ugm->skip_slash && (wsgi_req->path_info_len > 0 && wsgi_req->path_info[0] == '/')) {
                itemname = uwsgi_concat2n(ugm->prefix, ugm->prefix_len, wsgi_req->path_info+1, wsgi_req->path_info_len-1);
        }
        else {
                itemname = uwsgi_concat2n(ugm->prefix, ugm->prefix_len, wsgi_req->path_info, wsgi_req->path_info_len);
        }

        if (ugridfs.debug) {
                uwsgi_log("[uwsgi-gridfs-debug] itemname = %s\n", itemname);
        }

        // itemname will be freed here
        uwsgi_gridfs_do(wsgi_req, ugm, itemname, 1);

        return UWSGI_OK;

}


extern "C" void uwsgi_gridfs_mount() {
	if (!uwsgi.skip_atexit) {
		uwsgi_log("*** WARNING libmongoclient could have a bug with atexit() hooks, if you get segfault on end/reload, add --skip-atexit ***\n");
	}
	struct uwsgi_string_list *usl = ugridfs.mountpoints;
	while(usl) {
		if (uwsgi_apps_cnt >= uwsgi.max_apps) {
                	uwsgi_log("ERROR: you cannot load more than %d apps in a worker\n", uwsgi.max_apps);
			exit(1);
        	}
        	int id = uwsgi_apps_cnt;
		struct uwsgi_gridfs_mountpoint *ugm = uwsgi_gridfs_add_mountpoint(uwsgi_str(usl->value), usl->len);
		if (!ugm) exit(1);
                uwsgi_add_app(id, gridfs_plugin.modifier1, ugm->mountpoint, ugm->mountpoint_len, ugm, ugm);
		uwsgi_emulate_cow_for_apps(id);
		uwsgi_log("GridFS mountpoint \"%.*s\" (%d) added: server=%s db=%s\n", ugm->mountpoint_len, ugm->mountpoint, id, ugm->server, ugm->db);
		usl = usl->next;
	}
}

#ifdef UWSGI_ROUTING
static int uwsgi_routing_func_gridfs(struct wsgi_request *wsgi_req, struct uwsgi_route *ur){

        struct uwsgi_gridfs_mountpoint *ugm = (struct uwsgi_gridfs_mountpoint *) ur->data2;

        char **subject = (char **) (((char *)(wsgi_req))+ur->subject);
        uint16_t *subject_len = (uint16_t *) (((char *)(wsgi_req))+ur->subject_len);

        struct uwsgi_buffer *ub_itemname = uwsgi_routing_translate(wsgi_req, ur, *subject, *subject_len, ugm->itemname, ugm->itemname_len);
        if (!ub_itemname) return UWSGI_ROUTE_BREAK;
	if (ugridfs.debug) {
		 uwsgi_log("[uwsgi-gridfs-debug] itemname = %s\n", ub_itemname->buf);
	}
	uwsgi_gridfs_do(wsgi_req, ugm, ub_itemname->buf, 0);
	uwsgi_buffer_destroy(ub_itemname);
        return UWSGI_ROUTE_BREAK;
}

extern "C" int uwsgi_router_gridfs(struct uwsgi_route *ur, char *args) {
	ur->func = uwsgi_routing_func_gridfs;
        ur->data = args;
        ur->data_len = strlen(args);
        ur->data2 = uwsgi_gridfs_add_mountpoint((char *)ur->data, ur->data_len);
	if (!ur->data2) {
		exit(1);
	}
        return 0;
}
#endif
