#include <uwsgi.h>
#include <rados/librados.h>

extern struct uwsgi_server uwsgi;

/*

	Author: Javier Guerra
	Author: Marcin Deranek
	Author: Roberto De Ioris

	--rados-mount mountpoint=/foo,pool=unbit001,config=/etc/ceph.conf,timeout=30,allow_put=1,allow_delete=1

*/

struct uwsgi_plugin rados_plugin;

// this structure is preallocated (only the pipe part is per-request)
struct uwsgi_rados_io {
        int fds[2];
        // this is increased at every usage (in locked context)
        uint64_t rid;
        pthread_mutex_t mutex;
};

// this structure is allocated for each async transaction
struct uwsgi_rados_cb {
        // this is copied from the current uwsgi_rados_io->rid
        uint64_t rid;
        struct uwsgi_rados_io *urio;
};

static struct uwsgi_rados {
	int timeout;
	struct uwsgi_string_list *mountpoints;
	struct uwsgi_rados_io *urio;
} urados;

struct uwsgi_rados_mountpoint {
	rados_t cluster;
	char *mountpoint;
	char *config;
	char *pool;
	char *str_timeout;
	int timeout;
	char *allow_put;
	char *allow_delete;
	char *allow_mkcol;
};

static struct uwsgi_option uwsgi_rados_options[] = {
	{"rados-mount", required_argument, 0, "virtual mount the specified rados volume in a uri", uwsgi_opt_add_string_list, &urados.mountpoints, UWSGI_OPT_MIME},
	{"rados-timeout", required_argument, 0, "timeout for async operations", uwsgi_opt_set_int, &urados.timeout, 0},
	{0, 0, 0, 0, 0, 0, 0},
};

static int uwsgi_rados_read_sync(struct wsgi_request *wsgi_req, rados_ioctx_t ctx, const char *key, size_t remains) {
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

// callback used to asynchronously signal the completion
static void uwsgi_rados_read_async_cb(rados_completion_t comp, void *data) {
	struct uwsgi_rados_cb *urcb = (struct uwsgi_rados_cb *) data;
	struct uwsgi_rados_io *urio = urcb->urio;

	pthread_mutex_lock(&urio->mutex);
	if (urcb->rid != urio->rid) {
		uwsgi_log_verbose("[uwsgi-rados] callback %llu woke up too late\n", (unsigned long long) urcb->rid);
	}
	else {
		// signal the core
		if (write(urio->fds[1], "\1", 1) <= 0) {
			uwsgi_error("uwsgi_rados_read_async_cb()/write()");
		}
	}

	pthread_mutex_unlock(&urio->mutex);

	free(urcb);
}

static int uwsgi_rados_delete(struct wsgi_request *wsgi_req, rados_ioctx_t ctx, char *key, int timeout) {
	if (uwsgi.async <= 1) {
		return rados_remove(ctx, key); 
	}
	struct uwsgi_rados_io *urio = &urados.urio[wsgi_req->async_id];
	int ret = -1;
        // increase request counter
        pthread_mutex_lock(&urio->mutex);
        urio->rid++;
        pthread_mutex_unlock(&urio->mutex);

        struct uwsgi_rados_cb *urcb = uwsgi_malloc(sizeof(struct uwsgi_rados_cb));
        // map the current request id to the callback
        urcb->rid = urio->rid;
        // map urio to the callback
        urcb->urio = urio;

        rados_completion_t comp;
	// we use the safe cb here
        if (rados_aio_create_completion(urcb, NULL, uwsgi_rados_read_async_cb, &comp) < 0) {
                free(urcb);
                goto end;
        }
        if (rados_aio_remove(ctx, key, comp) < 0) {
                free(urcb);
                rados_aio_release(comp);
                goto end;
        }

        // wait for the callback to be executed
        if (uwsgi.wait_read_hook(urio->fds[0], timeout) <= 0) {
                rados_aio_release(comp);
                goto end;
        }
        char ack = 1;
        if (read(urio->fds[0], &ack, 1) != 1) {
                rados_aio_release(comp);
                uwsgi_error("uwsgi_rados_delete()/read()");
                goto end;
        }

        if (rados_aio_is_safe_and_cb(comp)) {
                ret = rados_aio_get_return_value(comp);
        }
        rados_aio_release(comp);

end:
      	return ret;
}

static int uwsgi_rados_put(struct wsgi_request *wsgi_req, rados_ioctx_t ctx, char *key, int timeout) {
	struct uwsgi_rados_io *urio = &urados.urio[wsgi_req->async_id];
	size_t remains = wsgi_req->post_cl;
	uint64_t off = 0;
        while(remains > 0) {
                ssize_t body_len = 0;
                char *body =  uwsgi_request_body_read(wsgi_req, UMIN(remains, 32768) , &body_len);
                if (!body || body == uwsgi.empty) goto error;
		if (uwsgi.async <= 1) {
			if (rados_write_full(ctx, key, body, body_len) < 0) {
				return -1;
			}
		}
		else {
			// increase request counter
        		pthread_mutex_lock(&urio->mutex);
        		urio->rid++;
        		pthread_mutex_unlock(&urio->mutex);

			struct uwsgi_rados_cb *urcb = uwsgi_malloc(sizeof(struct uwsgi_rados_cb));
        		// map the current request id to the callback
        		urcb->rid = urio->rid;
        		// map urio to the callback
        		urcb->urio = urio;

        		rados_completion_t comp;
			// use safe for write
        		if (rados_aio_create_completion(urcb, NULL, uwsgi_rados_read_async_cb, &comp) < 0) {
                		free(urcb);
                		goto error;
        		}
        		if (rados_aio_write_full(ctx, key, comp, body, body_len) < 0) {
                		free(urcb);
                		rados_aio_release(comp);
                		goto error;
        		}

        		// wait for the callback to be executed
        		if (uwsgi.wait_read_hook(urio->fds[0], timeout) <= 0) {
                		rados_aio_release(comp);
                		goto error;
        		}
        		char ack = 1;
        		if (read(urio->fds[0], &ack, 1) != 1) {
                		rados_aio_release(comp);
                		uwsgi_error("uwsgi_rados_read_async()/read()");
                		goto error;
        		}

        		if (rados_aio_is_safe_and_cb(comp)) {
                		if (rados_aio_get_return_value(comp) < 0) {
                			rados_aio_release(comp);
					goto error;
				}
				
        		}
        		rados_aio_release(comp);
		}
		remains -= body_len;
		off += body_len;
        }	

	return 0;

error:
	return -1;
}

// async stat
static int uwsgi_rados_async_stat(struct uwsgi_rados_io *urio, rados_ioctx_t ctx, const char *key, uint64_t *stat_size, time_t *stat_mtime, int timeout) {
	int ret = -1;
        // increase request counter
        pthread_mutex_lock(&urio->mutex);
        urio->rid++;
        pthread_mutex_unlock(&urio->mutex);

	struct uwsgi_rados_cb *urcb = uwsgi_malloc(sizeof(struct uwsgi_rados_cb));
        // map the current request id to the callback
        urcb->rid = urio->rid;
        // map urio to the callback
        urcb->urio = urio;

	rados_completion_t comp;
	if (rados_aio_create_completion(urcb, uwsgi_rados_read_async_cb, NULL, &comp) < 0) {
        	free(urcb);
		goto end;
	}
	if (rados_aio_stat(ctx, key, comp, stat_size, stat_mtime) < 0) {
		free(urcb);
                rados_aio_release(comp);
		goto end;
	}	

	// wait for the callback to be executed
        if (uwsgi.wait_read_hook(urio->fds[0], timeout) <= 0) {
        	rados_aio_release(comp);
		goto end;
        }
        char ack = 1;
        if (read(urio->fds[0], &ack, 1) != 1) {
        	rados_aio_release(comp);
                uwsgi_error("uwsgi_rados_read_async()/read()");
		goto end;
        }

	if (rados_aio_is_complete_and_cb(comp)) {
        	ret = rados_aio_get_return_value(comp);
        }
        rados_aio_release(comp);

end:
	return ret;
}

static int uwsgi_rados_read_async(struct wsgi_request *wsgi_req, rados_ioctx_t ctx, const char *key, size_t remains, int timeout) {
	uint64_t off = 0;
	int ret = -1;
	char buf[8192];

	struct uwsgi_rados_io *urio = &urados.urio[wsgi_req->async_id];
	// increase request counter
	pthread_mutex_lock(&urio->mutex);
	urio->rid++;
	pthread_mutex_unlock(&urio->mutex);

	while(remains > 0) {
		struct uwsgi_rados_cb *urcb = uwsgi_malloc(sizeof(struct uwsgi_rados_cb));
		// map the current request id to the callback
		urcb->rid = urio->rid;
		// map urio to the callback
		urcb->urio = urio;


		rados_completion_t comp;
		if (rados_aio_create_completion(urcb, uwsgi_rados_read_async_cb, NULL, &comp) < 0) {
			free(urcb);
			break;
		}
		// trigger an async read
		if (rados_aio_read(ctx, key, comp, buf, UMIN(remains, 8192), off) < 0) {
			free(urcb);
			rados_aio_release(comp);
			break;
		}
		// wait for the callback to be executed
		if (uwsgi.wait_read_hook(urio->fds[0], timeout) <= 0) {
			rados_aio_release(comp);
			break;
		}
		char ack = 1;
		if (read(urio->fds[0], &ack, 1) != 1) {
			rados_aio_release(comp);
			uwsgi_error("uwsgi_rados_read_async()/read()");
			break;
		}
		int rlen = -1;	
		if (rados_aio_is_complete_and_cb(comp)) {
			rlen = rados_aio_get_return_value(comp);
		}
		rados_aio_release(comp);
		if (rlen <= 0) break;
		if (uwsgi_response_write_body_do(wsgi_req, buf, rlen)) break;
		remains -= rlen;
		off += rlen;
	}

	if (remains == 0) ret = 0;

	pthread_mutex_lock(&urio->mutex);
	// increase the counter again
	urio->rid++;
	pthread_mutex_unlock(&urio->mutex);
	return ret;	
}


static void uwsgi_rados_add_mountpoint(char *arg, size_t arg_len) {
	struct uwsgi_rados_mountpoint *urmp = uwsgi_calloc(sizeof(struct uwsgi_rados_mountpoint));
	if (uwsgi_kvlist_parse(arg, arg_len, ',', '=',
			"mountpoint", &urmp->mountpoint,
			"config", &urmp->config,
			"pool", &urmp->pool,
			"timeout", &urmp->str_timeout,
			"allow_put", &urmp->allow_put,
			"allow_delete", &urmp->allow_delete,
			"allow_mkcol", &urmp->allow_mkcol,
			NULL)) {
				uwsgi_log("unable to parse rados mountpoint definition\n");
				exit(1);
		}

	if (!urmp->mountpoint|| !urmp->pool) {
		uwsgi_log("[rados] mount requires a mountpoint, and a pool name.\n");
		exit(1);
	}

	if (urmp->str_timeout) {
		urmp->timeout = atoi(urmp->str_timeout);
	}

	time_t now = uwsgi_now();
	uwsgi_log("[rados] mounting %s ...\n", urmp->mountpoint);
	
	rados_t cluster;
	if (rados_create(&cluster, NULL) < 0) {
		uwsgi_error("can't create Ceph cluster handle");
		exit(1);
	}
	urmp->cluster = cluster;

	if (urmp->config)
		uwsgi_log("using Ceph conf:%s\n", urmp->config);
	else
		uwsgi_log("using default Ceph conf.\n");

	if (rados_conf_read_file(cluster, urmp->config) < 0) {
		uwsgi_error("can't configure Ceph cluster handle");
		exit(1);
	}

	int timeout = urmp->timeout ? urmp->timeout : urados.timeout;
	char *timeout_str = uwsgi_num2str(timeout);

	rados_conf_set(cluster, "client_mount_timeout", timeout_str);
	rados_conf_set(cluster, "rados_mon_op_timeout", timeout_str);
	rados_conf_set(cluster, "rados_osd_op_timeout", timeout_str);

	free(timeout_str);


	if (rados_connect(cluster) < 0) {
		uwsgi_error("can't connect with Ceph cluster");
		exit(1);
	}


	void *ctx_ptr;

	if (uwsgi.threads > 1) {
		int i;
		rados_ioctx_t *ctxes = uwsgi_calloc(sizeof(rados_ioctx_t) * uwsgi.threads);
		for(i=0;i<uwsgi.threads;i++) {
			if (rados_ioctx_create(cluster, urmp->pool, &ctxes[i]) < 0) {
                        	uwsgi_error("can't open rados pool")
                        	rados_shutdown(cluster);
                        	exit(1);
			}
                }
		ctx_ptr = ctxes;
	}
	else {
		rados_ioctx_t ctx;
		if (rados_ioctx_create(cluster, urmp->pool, &ctx) < 0) {
			uwsgi_error("can't open rados pool")
			rados_shutdown(cluster);
			exit(1);
		}
		ctx_ptr = ctx;
	}

	char fsid[37];
	rados_cluster_fsid(cluster, fsid, 37);
	uwsgi_log("connected to Ceph pool: %s on cluster %.*s\n", urmp->pool, 37, fsid);
	
	int id = uwsgi_apps_cnt;
	struct uwsgi_app *ua = uwsgi_add_app(id, rados_plugin.modifier1, urmp->mountpoint, strlen(urmp->mountpoint), NULL, NULL);
	if (!ua) {
		uwsgi_log("[rados] unable to mount %s\n", urmp->mountpoint);
		rados_shutdown(cluster);
		exit(1);
	}

	ua->responder0 = ctx_ptr;
	ua->responder1 = urmp;
	ua->started_at = now;
	ua->startup_time = uwsgi_now() - now;
	uwsgi_log("Rados app/mountpoint %d (%s) loaded in %d seconds at %p\n", id, urmp->mountpoint, (int) ua->startup_time, ctx_ptr);
}

// we translate the string list to an app representation
// this happens before fork() if not in lazy/lazy-apps mode
static void uwsgi_rados_setup() {
	if (!urados.timeout) {
		urados.timeout = uwsgi.socket_timeout;
	}
	
	struct uwsgi_string_list *usl = urados.mountpoints;
	while(usl) {
		uwsgi_rados_add_mountpoint(usl->value, usl->len);
		usl = usl->next;
	}

	// now initialize a pthread_mutex for each async core
	if (uwsgi.async > 1) {
		int i;
		urados.urio = uwsgi_calloc(sizeof(struct uwsgi_rados_io) * uwsgi.async);
		for(i=0;i<uwsgi.async;i++) {
			urados.urio[i].fds[0] = -1;
			urados.urio[i].fds[1] = -1;
			if (pthread_mutex_init(&urados.urio[i].mutex, NULL)) {
				uwsgi_error("uwsgi_rados_setup()/pthread_mutex_init()");
				exit(1);
			}
		}
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
		memcmp(wsgi_req->path_info, ua->mountpoint, ua->mountpoint_len) == 0) {

		memcpy(filename, wsgi_req->path_info+ua->mountpoint_len, wsgi_req->path_info_len-ua->mountpoint_len);
		filename[wsgi_req->path_info_len-ua->mountpoint_len] = 0;

	} else {
		memcpy(filename, wsgi_req->path_info, wsgi_req->path_info_len);
		filename[wsgi_req->path_info_len] = 0;
	}
	
	// in multithread mode the memory is different (as we need a ctx for each thread) !!!
	rados_ioctx_t ctx;
	if (uwsgi.threads > 1) {
		rados_ioctx_t *ctxes = (rados_ioctx_t *) ua->responder0;
		ctx = ctxes[wsgi_req->async_id];
	}
	else {
		ctx = (rados_ioctx_t) ua->responder0;
	}
	struct uwsgi_rados_mountpoint *urmp = (struct uwsgi_rados_mountpoint *) ua->responder1;
	uint64_t stat_size = 0;
	time_t stat_mtime = 0;

	struct uwsgi_rados_io *urio = &urados.urio[wsgi_req->async_id];

	if (uwsgi.async > 1) {
	// no need to lock here (the rid protect us)
        	if (pipe(urio->fds)) {
                	uwsgi_error("uwsgi_rados_read_async()/pipe()");
			uwsgi_500(wsgi_req);
			return UWSGI_OK;
        	}
	}
	
	int ret = -1;
	int timeout = urmp->timeout ? urmp->timeout : urados.timeout;

	if (!uwsgi_strncmp(wsgi_req->method, wsgi_req->method_len, "OPTIONS", 7)) {
		if (uwsgi_response_prepare_headers(wsgi_req, "200 OK", 6)) goto end;
		if (uwsgi_response_add_header(wsgi_req, "Dav", 3, "1", 1)) goto end;	
		struct uwsgi_buffer *ub_allow = uwsgi_buffer_new(64);
		if (uwsgi_buffer_append(ub_allow, "OPTIONS, GET, HEAD", 18)) {
			uwsgi_buffer_destroy(ub_allow);
			goto end;
		}
		if (urmp->allow_put) {
			if (uwsgi_buffer_append(ub_allow, ", PUT", 5)) {
				uwsgi_buffer_destroy(ub_allow);
				goto end;
			}
		}
		if (urmp->allow_delete) {
			if (uwsgi_buffer_append(ub_allow, ", DELETE", 8)) {
				uwsgi_buffer_destroy(ub_allow);
				goto end;
			}
		}
		if (urmp->allow_mkcol) {
			if (uwsgi_buffer_append(ub_allow, ", MKCOL", 7)) {
				uwsgi_buffer_destroy(ub_allow);
				goto end;
			}
		}

		uwsgi_response_add_header(wsgi_req, "Allow", 5, ub_allow->buf, ub_allow->pos);
		uwsgi_buffer_destroy(ub_allow);
                goto end;
	}

	// MKCOL does not require stat
	if (!uwsgi_strncmp(wsgi_req->method, wsgi_req->method_len, "MKCOL", 5)) {
                if (!urmp->allow_mkcol) {
                        uwsgi_405(wsgi_req);
                        goto end;
                }
                ret = rados_pool_create(urmp->cluster, filename);
		if (ret < 0) {
			if (ret == -EEXIST) {
                        	uwsgi_405(wsgi_req);
			}
			else {
                        	uwsgi_500(wsgi_req);
			}
                        goto end;
                }
                uwsgi_response_prepare_headers(wsgi_req, "201 Created", 11);
                goto end;
	}

	if (uwsgi.async > 1) {
		ret = uwsgi_rados_async_stat(urio, ctx, filename, &stat_size, &stat_mtime, timeout);	
	}
	else {
		ret = rados_stat(ctx, filename, &stat_size, &stat_mtime);
	}

	// PUT AND MKCOL can be used for non-existent objects
	if (!uwsgi_strncmp(wsgi_req->method, wsgi_req->method_len, "PUT", 3)) {
		if (!urmp->allow_put) {
			uwsgi_405(wsgi_req);
			goto end;
		}
		if (ret == 0) {
			if (uwsgi_rados_delete(wsgi_req, ctx, filename, timeout)) {
				uwsgi_500(wsgi_req);
				goto end;
			}
		}	
		if (uwsgi_rados_put(wsgi_req, ctx, filename, timeout)) {
			uwsgi_500(wsgi_req);
			goto end;
		}
		uwsgi_response_prepare_headers(wsgi_req, "201 Created", 11);	
		goto end;
	}
	else if (ret < 0) {
		if (ret == -ENOENT)
			uwsgi_404(wsgi_req);
		else
			uwsgi_403(wsgi_req);
		goto end;
	}

	if (!uwsgi_strncmp(wsgi_req->method, wsgi_req->method_len, "DELETE", 6)) {
		if (!urmp->allow_delete) {
			uwsgi_405(wsgi_req);
                        goto end;
		}
		if (uwsgi_rados_delete(wsgi_req, ctx, filename, timeout)) {
			uwsgi_403(wsgi_req);
                        goto end;
		}
		uwsgi_response_prepare_headers(wsgi_req, "200 OK", 6);
		goto end;
	}

	if (uwsgi_strncmp(wsgi_req->method, wsgi_req->method_len, "HEAD", 4) && uwsgi_strncmp(wsgi_req->method, wsgi_req->method_len, "GET", 3)) {
		uwsgi_405(wsgi_req);
		goto end;
	}

	if (uwsgi_response_prepare_headers(wsgi_req, "200 OK", 6)) goto end;
	size_t mime_type_len = 0;
	char *mime_type = uwsgi_get_mime_type(wsgi_req->path_info, wsgi_req->path_info_len, &mime_type_len);
	if (mime_type) {
		if (uwsgi_response_add_content_type(wsgi_req, mime_type, mime_type_len)) goto end;
	}

	if (uwsgi_response_add_last_modified(wsgi_req, (uint64_t) stat_mtime)) goto end;
	if (uwsgi_response_add_content_length(wsgi_req, stat_size)) goto end;

	// skip body on HEAD
	if (uwsgi_strncmp(wsgi_req->method, wsgi_req->method_len, "HEAD", 4)) {
		size_t remains = stat_size;
		if (uwsgi.async > 1) {
			if (uwsgi_rados_read_async(wsgi_req, ctx, filename, remains, timeout)) goto end;
		}
		else {
			if (uwsgi_rados_read_sync(wsgi_req, ctx, filename, remains)) goto end;
		}
	}

end:
	if (uwsgi.async > 1) {
		close(urio->fds[0]);
		close(urio->fds[1]);
	}
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
