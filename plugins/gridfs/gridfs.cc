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
	char *skip_slash;
	uint16_t prefix_len;
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

	if (wsgi_req->appid_len == 0) {
                if (!uwsgi.ignore_script_name) {
                        wsgi_req->appid = wsgi_req->script_name;
                        wsgi_req->appid_len = wsgi_req->script_name_len;
                }
	}

	wsgi_req->app_id = uwsgi_get_app_id(wsgi_req->appid, wsgi_req->appid_len, gridfs_plugin.modifier1);
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

	try {
		mongo::scoped_ptr<mongo::ScopedDbConnection> conn( mongo::ScopedDbConnection::getScopedDbConnection(ugm->server, ugm->timeout) );
		try {
			mongo::GridFS gridfs((*conn).conn(), ugm->db);
			mongo::GridFile gfile = gridfs.findFile(itemname);
			free(itemname);
			itemname = NULL;
			if (!gfile.exists()) {
				(*conn).done();
				uwsgi_404(wsgi_req);
				return UWSGI_OK;
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
			if (itemname) {
				free(itemname);
				itemname = NULL;
			}
		}
	}	
	catch ( mongo::DBException &e ) {
		uwsgi_log("[uwsgi-gridfs]: %s\n", e.what());
		if (itemname) {
			free(itemname);
			itemname = NULL;
		}
	}

	return UWSGI_OK;

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
		ugm->timeout = uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT];
	}

	if (ugm->prefix) {
		ugm->prefix_len = strlen(ugm->prefix);
	}

	return ugm;
}

extern "C" void uwsgi_gridfs_mount() {
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
