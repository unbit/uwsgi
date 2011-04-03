#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

int uwsgi_load_plugin(int modifier, char *plugin, char *pargs, int absolute) {

	void *plugin_handle;

	char *plugin_name;
	char *plugin_entry_symbol;
	struct uwsgi_plugin *up;
	int i;

	for (i = 0; i < 0xFF; i++) {
		if (uwsgi.p[i]->name) {
			if (!strcmp(plugin, uwsgi.p[i]->name)) {
				uwsgi_log("%s plugin already available\n", plugin);
				return 0;
			}	
		}
		if (uwsgi.p[i]->alias) {
			if (!strcmp(plugin, uwsgi.p[i]->alias)) {
				uwsgi_log("%s plugin already available\n", plugin);
				return 0;
			}	
		}
	}

	for(i=0;i<uwsgi.gp_cnt;i++) {

		if (uwsgi.gp[i]->name) {
                        if (!strcmp(plugin, uwsgi.gp[i]->name)) {
                                uwsgi_log("%s plugin already available\n", plugin);
                                return 0;
                        }       
                }
                if (uwsgi.gp[i]->alias) {
                        if (!strcmp(plugin, uwsgi.gp[i]->alias)) {
                                uwsgi_log("%s plugin already available\n", plugin);
                                return 0;
                        }
                }
        }

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
}
