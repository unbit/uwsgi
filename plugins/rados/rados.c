#include <uwsgi.h>
#include <rados/librados.h>

extern struct uwsgi_server uwsgi;

/*

	Author: Javier Guerra

	based on the uWSGI GlusterFS plugin by Roberto De Ioris

	--rados-mount mountpoint=/foo,pool=unbit001,config=/etc/ceph.conf

*/

struct uwsgi_plugin rados_plugin;

struct uwsgi_rados {
	int timeout;
	struct uwsgi_string_list *mountpoints;
} urados;

static struct uwsgi_option uwsgi_rados_options[] = {
	{"rados-mount", required_argument, 0, "virtual mount the specified rados volume in a uri", uwsgi_opt_add_string_list, &urados.mountpoints, UWSGI_OPT_MIME},
	{"rados-timeout", required_argument, 0, "timeout for async operations", uwsgi_opt_set_int, &urados.timeout, 0},
	{0, 0, 0, 0, 0, 0, 0},
};

static int uwsgi_rados_read_sync(struct wsgi_request *wsgi_req, rados_ioctx_t *ctx, const char *key, size_t remains) {
	uint64_t off = 0;
	while(remains > 0) {
		char buf[8192];
		int rlen = rados_read(ctx, key, buf, UMIN(remains, 8192), off);
		if (rlen <= 0) return -1;
		if (uwsgi_response_write_body_do(wsgi_req, buf, rlen)) return -1;
		remains -= rlen;
		off += rlen;
	}
	return 0;
}

/*
	async read of a resource
	the uwsgi_rados_async_io structure is passed between threads
	the callback simply signal the main core about the availability of data
*/
struct uwsgi_rados_async_io {
	int fd[2];
	ssize_t rlen;
};

static void uwsgi_rados_read_async_cb(rados_completion_t comp, void *data) {
	struct uwsgi_rados_async_io *aio = (struct uwsgi_rados_async_io *) data;
#ifdef UWSGI_DEBUG
	uwsgi_log("[rados-cb] rlen = %d\n", rlen);
#endif
	aio->rlen = rados_aio_get_return_value(comp);
	// signal the core
	if (write(aio->fd[1], "\1", 1) <= 0) {
		uwsgi_error("uwsgi_rados_read_async_cb()/write()");
	}
}


static int uwsgi_rados_read_async(struct wsgi_request *wsgi_req, rados_ioctx_t *ctx, const char *key, size_t remains) {
	uint64_t off = 0;
	char buf[8192];
	struct uwsgi_rados_async_io aio;
	int ret = -1;
	if (pipe(aio.fd)) {
		uwsgi_error("uwsgi_rados_read_async()/pipe()");
		return -1;
	}
	aio.rlen = -1;
	rados_completion_t comp;
	if (rados_aio_create_completion(&aio, uwsgi_rados_read_async_cb, NULL, &comp) < 0) goto end;
	
	while(remains > 0) {
		// trigger an async read
		if (rados_aio_read(ctx, key, comp, buf, 8192, off) < 0) goto end;
		// wait for the callback to be executed
		if (uwsgi.wait_read_hook(aio.fd[0], urados.timeout) <= 0) goto end;
		if (aio.rlen <= 0) goto end;	
		if (uwsgi_response_write_body_do(wsgi_req, buf, aio.rlen)) goto end;
		remains -= aio.rlen;
	}
	ret = 0;
end:
	rados_aio_release(&comp);
	close(aio.fd[0]);
	close(aio.fd[1]);
	return ret;	
}


static void uwsgi_rados_add_mountpoint(char *arg, size_t arg_len) {
	char *rad_mountpoint = NULL;
	char *rad_config = NULL;
	char *rad_poolname = NULL;
	if (uwsgi_kvlist_parse(arg, arg_len, ',', '=',
			"mountpoint", &rad_mountpoint,
			"config", &rad_config,
			"pool", &rad_poolname,
			NULL)) {
				uwsgi_log("unable to parse rados mountpoint definition\n");
				exit(1);
		}

	if (!rad_mountpoint|| !rad_poolname) {
		uwsgi_log("[rados] mount requires a mountpoint, and a pool name.\n");
		exit(1);
	}
	time_t now = uwsgi_now();
	uwsgi_log("[rados] mounting %s ...\n", rad_mountpoint);
	
	rados_t cluster;
	if (rados_create(&cluster, NULL) < 0) {
		uwsgi_error("Can't create Ceph cluster handle");
		exit(1);
	}
	if (rad_config)
		uwsgi_log("Using Ceph conf:%s\n", rad_config);
	else
		uwsgi_log("Using default Ceph conf.\n");
	if (rados_conf_read_file(cluster, rad_config) < 0) {
		uwsgi_error("Can't configure Ceph cluster handle");
		exit(1);
	}
	if (rados_connect(cluster) < 0) {
		uwsgi_error("Can't connect with Ceph cluster");
		exit(1);
	}
	
	rados_ioctx_t ctx;
	uwsgi_log("Ceph pool: %s\n", rad_poolname);
	if (rados_ioctx_create(cluster, rad_poolname, &ctx) < 0) {
		uwsgi_error("Can't open rados pool")
		rados_shutdown(cluster);
		exit(1);
	}
	
	int id = uwsgi_apps_cnt;
	struct uwsgi_app *ua = uwsgi_add_app(id, rados_plugin.modifier1, rad_mountpoint, strlen(rad_mountpoint), NULL, NULL);
	if (!ua) {
		uwsgi_log("[rados] unable to mount %s\n", rad_mountpoint);
		rados_shutdown(cluster);
		exit(1);
	}

	ua->responder0 = cluster;
	ua->responder1 = ctx;
	ua->started_at = now;
	ua->startup_time = uwsgi_now() - now;
	uwsgi_log("Rados app/mountpoint %d (%s) loaded in %d seconds at %p\n", id, rad_mountpoint, (int) ua->startup_time, ctx);
}

// we translate the string list to an app representation
// this happens before fork() if not in lazy/lazy-apps mode
static void uwsgi_rados_setup() {
	if (!urados.timeout) {
		urados.timeout = uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT];
	}
	
	struct uwsgi_string_list *usl = urados.mountpoints;
	while(usl) {
		uwsgi_rados_add_mountpoint(usl->value, usl->len);
		usl = usl->next;
	}
}

static int uwsgi_rados_request(struct wsgi_request *wsgi_req) {
	char filename[PATH_MAX+1];
	if (!wsgi_req->uh->pktsize) {
		uwsgi_log( "Empty request. skip.\n");
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

	wsgi_req->app_id = uwsgi_get_app_id(wsgi_req, wsgi_req->appid, wsgi_req->appid_len, rados_plugin.modifier1);
	if (wsgi_req->app_id == -1 && !uwsgi.no_default_app && uwsgi.default_app > -1) {
		if (uwsgi_apps[uwsgi.default_app].modifier1 == rados_plugin.modifier1) {
			wsgi_req->app_id = uwsgi.default_app;
		}
	}
	if (wsgi_req->app_id == -1) {
		uwsgi_404(wsgi_req);
		return UWSGI_OK;
	}

	struct uwsgi_app *ua = &uwsgi_apps[wsgi_req->app_id];

	if (wsgi_req->path_info_len > ua->mountpoint_len &&
		memcmp(wsgi_req->path_info, ua->mountpoint, ua->mountpoint_len) == 0) 
	{
		memcpy(filename, wsgi_req->path_info+ua->mountpoint_len, wsgi_req->path_info_len-ua->mountpoint_len);
	} else {
		memcpy(filename, wsgi_req->path_info, wsgi_req->path_info_len);
	}
	filename[wsgi_req->path_info_len] = 0;
	
	struct {
		uint64_t size;
		time_t mtime;
	} st;
	rados_ioctx_t ctx = ua->responder1;
	
	int r = rados_stat(ctx, filename, &st.size, &st.mtime);
	if (r < 0) {
		if (r == -ENOENT)
			uwsgi_404(wsgi_req);
		else
			uwsgi_403(wsgi_req);
		return UWSGI_OK;
	}
	

	if (uwsgi_response_prepare_headers(wsgi_req, "200 OK", 6)) goto end;
	size_t mime_type_len = 0;
	char *mime_type = uwsgi_get_mime_type(wsgi_req->path_info, wsgi_req->path_info_len, &mime_type_len);
	if (mime_type) {
		if (uwsgi_response_add_content_type(wsgi_req, mime_type, mime_type_len)) goto end;
	}

	if (uwsgi_response_add_last_modified(wsgi_req, (uint64_t) st.mtime)) goto end;
	if (uwsgi_response_add_content_length(wsgi_req, st.size)) goto end;

	// skip body on HEAD
	if (uwsgi_strncmp(wsgi_req->method, wsgi_req->method_len, "HEAD", 4)) {
		size_t remains = st.size;
		if (uwsgi.async > 1) {
			if (uwsgi_rados_read_async(wsgi_req, ctx, filename, remains)) goto end;
		}
		else {
			if (uwsgi_rados_read_sync(wsgi_req, ctx, filename, remains)) goto end;
		}
	}

end:
	return UWSGI_OK;
}

struct uwsgi_plugin rados_plugin = {
	.name = "rados",
	.modifier1 = 28,
	.options = uwsgi_rados_options,
	.post_fork = uwsgi_rados_setup,
	.request = uwsgi_rados_request,
	.after_request = log_request,
};
