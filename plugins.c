#include "uwsgi.h"

void embed_plugins(struct uwsgi_server *uwsgi) {

#ifdef UWSGI_EMBED_PLUGIN_PSGI
	if (uwsgi->plugin_arg_psgi)
		ret = uwsgi_load_plugin(uwsgi, 5, "psgi_plugin.so", uwsgi->plugin_arg_psgi, 0);
#endif

#ifdef UWSGI_EMBED_PLUGIN_LUA
	if (uwsgi->plugin_arg_lua)
		ret = uwsgi_load_plugin(uwsgi, 6, "lua_plugin.so", uwsgi->plugin_arg_lua, 0);
#endif

#ifdef UWSGI_EMBED_PLUGIN_RACK
	if (uwsgi->plugin_arg_rack)
		ret = uwsgi_load_plugin(uwsgi, 7, "rack_plugin.so", uwsgi->plugin_arg_rack, 0);
#endif

}

int uwsgi_load_plugin(struct uwsgi_server *uwsgi, int modifier, char *plugin, char *pargs, int absolute) {

	char *plugin_name ;

	void *plugin_handle;
        int (*plugin_init) (struct uwsgi_server *, char *);
        int (*plugin_request) (struct uwsgi_server *, struct wsgi_request *);
        void (*plugin_after_request) (struct uwsgi_server *, struct wsgi_request *);
	
	if (absolute) {
		plugin_name = malloc(strlen(plugin) + 1);
		memcpy(plugin_name, plugin, strlen(plugin) + 1);
	}	
	else {
		plugin_name = malloc(strlen(UWSGI_PLUGIN_DIR) + 1 + strlen(plugin) + 1);
		if (!plugin_name) {
			uwsgi_error("malloc()");
			return -1 ;
		}
		memcpy(plugin_name, UWSGI_PLUGIN_DIR, strlen(UWSGI_PLUGIN_DIR));
		memcpy(plugin_name + strlen(UWSGI_PLUGIN_DIR) , "/", 1);
		memcpy(plugin_name + strlen(UWSGI_PLUGIN_DIR) + 1, plugin, strlen(plugin) + 1);
	}
	plugin_handle = dlopen(plugin_name, RTLD_NOW | RTLD_GLOBAL);
	free(plugin_name);

        if (!plugin_handle) {
                uwsgi_log( "%s\n", dlerror());
        }
        else {
                plugin_init = dlsym(plugin_handle, "uwsgi_init");
                if (plugin_init) {
                        if ((*plugin_init) (uwsgi, pargs)) {
                                uwsgi_log( "plugin initialization returned error\n");
                                if (dlclose(plugin_handle)) {
                                        uwsgi_log( "unable to unload plugin\n");
                                }

				return -1;
                        }
                }

                plugin_request = dlsym(plugin_handle, "uwsgi_request");
                if (plugin_request) {
                        uwsgi->shared->hooks[modifier] = plugin_request;
                        plugin_after_request = dlsym(plugin_handle, "uwsgi_after_request");
                        if (plugin_after_request) {
                                uwsgi->shared->after_hooks[modifier] = plugin_after_request;
                        }
			return 0;

                }
                else {
                        uwsgi_log( "%s\n", dlerror());
                }
        }


	return -1;
}
