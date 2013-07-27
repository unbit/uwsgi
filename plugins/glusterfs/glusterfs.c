#include <uwsgi.h>
#include <api/glfs.h>

extern struct uwsgi_server uwsgi;

/*

	Author: Roberto De Ioris

	--glusterfs-mount mountpoint=/foo,server=192.168.173.13:24007;192.168.173.17:0,volfile=foo.vol;volume=unbit001

*/

struct uwsgi_plugin glusterfs_plugin;

struct uwsgi_glusterfs {
	struct uwsgi_string_list *mountpoints;
} uglusterfs;

static struct uwsgi_option uwsgi_glusterfs_options[] = {
	{"glusterfs-mount", required_argument, 0, "virtual mount the specified glusterfs volume in a uri", uwsgi_opt_add_string_list, &uglusterfs.mountpoints, UWSGI_OPT_MIME},
        {0, 0, 0, 0, 0, 0, 0},
};

static void uwsgi_glusterfs_connect() {
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
	// update the application on all of the processes
	uwsgi_emulate_cow_for_apps(id);

	ua->started_at = now;
        ua->startup_time = uwsgi_now() - now;
	uwsgi_log("GlusterFS app/mountpoint %d (%s) loaded in %d seconds at %p\n", id, ugfs_mountpoint, (int) ua->startup_time, volume);
}

// we translate the string list to an app representation
// this happens before fork() if not in lazy/lazy-apps mode
static void uwsgi_glusterfs_setup() {
	struct uwsgi_string_list *usl = uglusterfs.mountpoints;
	while(usl) {
		uwsgi_glusterfs_add_mountpoint(usl->value, usl->len);
		usl = usl->next;
	}
}

struct uwsgi_plugin glusterfs_plugin = {
	.name = "glusterfs",
	.modifier1 = 27,
	.options = uwsgi_glusterfs_options,
	.init_apps = uwsgi_glusterfs_setup,
	.post_fork = uwsgi_glusterfs_connect,
};
