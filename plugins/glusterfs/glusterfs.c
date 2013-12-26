#include <uwsgi.h>
#include <api/glfs.h>

extern struct uwsgi_server uwsgi;

/*

	Author: Roberto De Ioris

	--glusterfs-mount mountpoint=/foo,server=192.168.173.13:24007;192.168.173.17:0,volfile=foo.vol;volume=unbit001

*/

struct uwsgi_plugin glusterfs_plugin;

struct uwsgi_glusterfs {
	int timeout;
	struct uwsgi_string_list *mountpoints;
} uglusterfs;

static struct uwsgi_option uwsgi_glusterfs_options[] = {
	{"glusterfs-mount", required_argument, 0, "virtual mount the specified glusterfs volume in a uri", uwsgi_opt_add_string_list, &uglusterfs.mountpoints, UWSGI_OPT_MIME},
	{"glusterfs-timeout", required_argument, 0, "timeout for glusterfs async mode", uwsgi_opt_set_int, &uglusterfs.timeout, 0},
        {0, 0, 0, 0, 0, 0, 0},
};


static int uwsgi_glusterfs_read_sync(struct wsgi_request *wsgi_req, glfs_fd_t *fd, size_t remains) {
	while(remains > 0) {
        	char buf[8192];
                ssize_t rlen = glfs_read (fd, buf, UMIN(remains, 8192), 0);
                if (rlen <= 0) return -1;
                if (uwsgi_response_write_body_do(wsgi_req, buf, rlen)) return -1;
                remains -= rlen;
	}
	return 0;
}

/*
	async read of a resource
	the uwsgi_glusterfs_async_io structure is passed between threads
	the callback simply signal the main core about the availability of data
*/
struct uwsgi_glusterfs_async_io {
	int fd[2];
	ssize_t rlen;
};

static void uwsgi_glusterfs_read_async_cb(glfs_fd_t *fd, ssize_t rlen, void *data) {
	struct uwsgi_glusterfs_async_io *aio = (struct uwsgi_glusterfs_async_io *) data;
#ifdef UWSGI_DEBUG
	uwsgi_log("[glusterfs-cb] rlen = %d\n", rlen);
#endif
	aio->rlen = rlen;
	// signal the core
	if (write(aio->fd[1], "\1", 1) <= 0) {
		uwsgi_error("uwsgi_glusterfs_read_async_cb()/write()");
	}
}

static int uwsgi_glusterfs_read_async(struct wsgi_request *wsgi_req, glfs_fd_t *fd, size_t remains) {
	char buf[8192];
	struct uwsgi_glusterfs_async_io aio;
	int ret = -1;
	if (pipe(aio.fd)) {
		uwsgi_error("uwsgi_glusterfs_read_async()/pipe()");
		return -1;
	}
	aio.rlen = -1;
	while(remains > 0) {
		// trigger an async read
		if (glfs_read_async(fd, buf, 8192, 0, uwsgi_glusterfs_read_async_cb, &aio)) goto end;
		// wait for the callback to be executed
		if (uwsgi.wait_read_hook(aio.fd[0], uglusterfs.timeout) <= 0) goto end;
		if (aio.rlen <= 0) goto end;	
		if (uwsgi_response_write_body_do(wsgi_req, buf, aio.rlen)) goto end;
		remains -= aio.rlen;
	}
	ret = 0;
end:
	close(aio.fd[0]);
	close(aio.fd[1]);
	return ret;	
}


static int uwsgi_glusterfs_try(struct uwsgi_app *ua, char *node) {
	int ret = -1;
	char *colon = strchr(node, ':');
	// unix socket
	if (!colon) {
		if (glfs_set_volfile_server((glfs_t *)ua->interpreter, "unix", node, 0)) {
			uwsgi_error("[glusterfs] glfs_set_volfile_server()");
			return -1;
		}
		goto connect;
	}

	*colon = 0;
	if (glfs_set_volfile_server((glfs_t *)ua->interpreter, "tcp", node, atoi(colon+1))) {
		uwsgi_error("[glusterfs] glfs_set_volfile_server()");
                return -1;
	}
connect:
	ret = glfs_init((glfs_t *)ua->interpreter);
        if (ret) { uwsgi_error("[glusterfs] glfs_init()"); }
	else {
		if (colon) *colon = ':';
		uwsgi_log("[glusterfs] worker %d connected to %s\n", uwsgi.mywid, node);
	}
        return ret;
}

static void uwsgi_glusterfs_connect_do(struct uwsgi_app *ua) {
	char *servers = uwsgi_str(ua->callable);
	char *p, *ctx = NULL;
	uwsgi_foreach_token(servers, ";", p, ctx) {
		uwsgi_log("[glusterfs] try connect to %s for mountpoint %.*s on worker %d ...\n", p, ua->mountpoint_len, ua->mountpoint, uwsgi.mywid);
		if (uwsgi_glusterfs_try(ua, p)) {
			goto end;
		}
	}
end:
	free(servers);
}

static void uwsgi_glusterfs_connect() {
	int i;
	// search for all of the glusterfs apps and connect to the server-based ones
	for (i = 0; i < uwsgi_apps_cnt; i++) {
		if (uwsgi_apps[i].modifier1 != glusterfs_plugin.modifier1) continue;
		if (!uwsgi_apps[i].callable) {
			if (glfs_init((glfs_t *)uwsgi_apps[i].interpreter)) {
				uwsgi_error("[glusterfs] glfs_init()");
				exit(1);
			}
			uwsgi_log("[glusterfs] worker %d connected using volfile\n", uwsgi.mywid);
			continue;
		}
		uwsgi_glusterfs_connect_do(&uwsgi_apps[i]);
	}

}

static void uwsgi_glusterfs_add_mountpoint(char *arg, size_t arg_len) {
	char *ugfs_mountpoint = NULL;
	char *ugfs_server = NULL;
	char *ugfs_volfile = NULL;
	char *ugfs_volume = NULL;
	if (uwsgi_kvlist_parse(arg, arg_len, ',', '=',
                        "mountpoint", &ugfs_mountpoint,
                        "server", &ugfs_server,
                        "servers", &ugfs_server,
                        "volfile", &ugfs_volfile,
                        "volume", &ugfs_volume,
                        NULL)) {
                        	uwsgi_log("unable to parse glusterfs mountpoint definition\n");
                        	exit(1);
                }

	if (!ugfs_mountpoint || (!ugfs_server && !ugfs_volfile) || !ugfs_volume) {
		uwsgi_log("[glusterfs] mount requires a mountpoint, a volume and at least one server or volfile\n");
		exit(1);
	}

	int id = uwsgi_apps_cnt;
	time_t now = uwsgi_now();
	uwsgi_log("[glusterfs] mounting %s ...\n", ugfs_mountpoint);
	// this should fail only if memory is not available
	glfs_t *volume = glfs_new(ugfs_volume);
	if (!volume) {
		uwsgi_error("unable to initialize glusterfs mountpoint: glfs_new()");
		exit(1);
	}

	if (ugfs_volfile) {
		if (glfs_set_volfile(volume, ugfs_volfile)) {
			uwsgi_error("unable to set glusterfs volfile: glfs_set_volfile\n");
			exit(1);
		}
	}
	/*
		here we pass ugfs_server as the callable field.
		After fork() if this field is defined we will start trying to connect to each one of the configuratio nodes
		This is required to have fallback management
	*/
        struct uwsgi_app *ua = uwsgi_add_app(id, glusterfs_plugin.modifier1, ugfs_mountpoint, strlen(ugfs_mountpoint), volume, ugfs_server);
	if (!ua) {
		uwsgi_log("[glusterfs] unable to mount %s\n", ugfs_mountpoint);
		exit(1);
	}

	ua->started_at = now;
        ua->startup_time = uwsgi_now() - now;
	uwsgi_log("GlusterFS app/mountpoint %d (%s) loaded in %d seconds at %p\n", id, ugfs_mountpoint, (int) ua->startup_time, volume);
}

// we translate the string list to an app representation
// this happens before fork() if not in lazy/lazy-apps mode
static void uwsgi_glusterfs_setup() {

	if (!uglusterfs.timeout) {
		uglusterfs.timeout = uwsgi.socket_timeout;
	}

	struct uwsgi_string_list *usl = uglusterfs.mountpoints;
	while(usl) {
		uwsgi_glusterfs_add_mountpoint(usl->value, usl->len);
		usl = usl->next;
	}
}

static int uwsgi_glusterfs_request(struct wsgi_request *wsgi_req) {
	char filename[PATH_MAX+1];
	/* Standard GlusterFS request */
        if (!wsgi_req->uh->pktsize) {
                uwsgi_log( "Empty GlusterFS request. skip.\n");
                return -1;
        }

        if (uwsgi_parse_vars(wsgi_req)) {
                return -1;
        }

	// blocks empty paths
	if (wsgi_req->path_info_len == 0 || wsgi_req->path_info_len > PATH_MAX) {
                uwsgi_403(wsgi_req);
                return UWSGI_OK;
	}

        wsgi_req->app_id = uwsgi_get_app_id(wsgi_req, wsgi_req->appid, wsgi_req->appid_len, glusterfs_plugin.modifier1);
	if (wsgi_req->app_id == -1 && !uwsgi.no_default_app && uwsgi.default_app > -1) {
        	if (uwsgi_apps[uwsgi.default_app].modifier1 == glusterfs_plugin.modifier1) {
                	wsgi_req->app_id = uwsgi.default_app;
                }
        }
        if (wsgi_req->app_id == -1) {
                uwsgi_404(wsgi_req);
                return UWSGI_OK;
        }

        struct uwsgi_app *ua = &uwsgi_apps[wsgi_req->app_id];

	memcpy(filename, wsgi_req->path_info, wsgi_req->path_info_len);
	filename[wsgi_req->path_info_len] = 0;

	glfs_fd_t *fd = glfs_open((glfs_t *) ua->interpreter, filename, O_RDONLY);
	if (!fd) {
                uwsgi_404(wsgi_req);
                return UWSGI_OK;
	}
	

	struct stat st;
	if (glfs_fstat(fd, &st)) {
		uwsgi_403(wsgi_req);
                return UWSGI_OK;
	}	

	if (uwsgi_response_prepare_headers(wsgi_req, "200 OK", 6)) goto end;
	size_t mime_type_len = 0;
        char *mime_type = uwsgi_get_mime_type(wsgi_req->path_info, wsgi_req->path_info_len, &mime_type_len);
        if (mime_type) {
        	if (uwsgi_response_add_content_type(wsgi_req, mime_type, mime_type_len)) goto end;
        }

        if (uwsgi_response_add_last_modified(wsgi_req, (uint64_t) st.st_mtime)) goto end;
	if (uwsgi_response_add_content_length(wsgi_req, st.st_size)) goto end;

	// skip body on HEAD
	if (uwsgi_strncmp(wsgi_req->method, wsgi_req->method_len, "HEAD", 4)) {
		size_t remains = st.st_size;
		if (uwsgi.async > 1) {
			if (uwsgi_glusterfs_read_async(wsgi_req, fd, remains)) goto end;
		}
		else {
			if (uwsgi_glusterfs_read_sync(wsgi_req, fd, remains)) goto end;
		}
	}

end:
	glfs_close(fd);
	return UWSGI_OK;
}

struct uwsgi_plugin glusterfs_plugin = {
	.name = "glusterfs",
	.modifier1 = 27,
	.options = uwsgi_glusterfs_options,
	.post_fork = uwsgi_glusterfs_setup,
	.fixup = uwsgi_glusterfs_connect,
	.request = uwsgi_glusterfs_request,
	.after_request = log_request,
};
