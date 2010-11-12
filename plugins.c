#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

void embed_plugins() {

#ifdef UWSGI_EMBED_PLUGIN_PSGI
	if (uwsgi.plugin_arg_psgi)
		uwsgi_load_plugin(5, "psgi_plugin.so", uwsgi.plugin_arg_psgi, 0);
#endif

#ifdef UWSGI_EMBED_PLUGIN_LUA
	if (uwsgi.plugin_arg_lua)
		uwsgi_load_plugin(6, "lua_plugin.so", uwsgi.plugin_arg_lua, 0);
#endif

#ifdef UWSGI_EMBED_PLUGIN_RACK
	if (uwsgi.plugin_arg_rack)
		uwsgi_load_plugin(7, "rack_plugin.so", uwsgi.plugin_arg_rack, 0);
#endif

}

int uwsgi_load_plugin(int modifier, char *plugin, char *pargs, int absolute) {

	void *plugin_handle;

	char *plugin_name;
	char *plugin_entry_symbol;
	struct uwsgi_plugin *up;

	if (absolute) {
		plugin_name = malloc(strlen(plugin) + 1);
		memcpy(plugin_name, plugin, strlen(plugin) + 1);
	}	
	else {
		plugin_name = uwsgi_concat4(UWSGI_PLUGIN_DIR, "/", plugin, "_plugin.so");
	}
	plugin_handle = dlopen(plugin_name, RTLD_NOW | RTLD_GLOBAL);
	free(plugin_name);

        if (!plugin_handle) {
                uwsgi_log( "%s\n", dlerror());
        }
        else {
		plugin_entry_symbol = uwsgi_concat2(plugin, "_plugin");
                up = dlsym(plugin_handle, plugin_entry_symbol);
                if (up) {
			if (modifier != -1) {
				fill_plugin_table(modifier, up);			
			}
			else {
				fill_plugin_table(up->modifier1, up);			
			}
			return 1;
                }
                uwsgi_log( "%s\n", dlerror());
        }

	return 0;


	return -1;
}
