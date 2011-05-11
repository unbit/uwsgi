#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

void *uwsgi_load_plugin(int modifier, char *plugin, char *has_option, int absolute) {

	void *plugin_handle;

	char *plugin_name;
	char *plugin_entry_symbol;
	struct uwsgi_plugin *up;
	char linkpath_buf[1024], linkpath[1024];
	int linkpath_size;
	int i;

	char *colon = strchr(plugin, ':');
	if (colon) {
		colon[0] = 0;
	}

check:
	for (i = 0; i < 0xFF; i++) {
		if (uwsgi.p[i]->name) {
			if (!strcmp(plugin, uwsgi.p[i]->name)) {
#ifdef UWSGI_DEBUG
				uwsgi_log("%s plugin already available\n", plugin);
#endif
				return NULL;
			}	
		}
		if (uwsgi.p[i]->alias) {
			if (!strcmp(plugin, uwsgi.p[i]->alias)) {
#ifdef UWSGI_DEBUG
				uwsgi_log("%s plugin already available\n", plugin);
#endif
				return NULL;
			}	
		}
	}

	for(i=0;i<uwsgi.gp_cnt;i++) {

		if (uwsgi.gp[i]->name) {
                        if (!strcmp(plugin, uwsgi.gp[i]->name)) {
#ifdef UWSGI_DEBUG
                                uwsgi_log("%s plugin already available\n", plugin);
#endif
                                return NULL;
                        }       
                }
                if (uwsgi.gp[i]->alias) {
                        if (!strcmp(plugin, uwsgi.gp[i]->alias)) {
#ifdef UWSGI_DEBUG
                                uwsgi_log("%s plugin already available\n", plugin);
#endif
                                return NULL;
                        }
                }
        }

	if (colon) {
		plugin = colon+1;
		colon[0] = ':';
		colon = NULL;
		goto check;
	}

	if (absolute == 1) {
		plugin_name = uwsgi_concat2(plugin, "");
		// need to fix this... postpone until needed
		plugin_entry_symbol = uwsgi_concat2n(plugin, strlen(plugin)-3 ,"", 0);
	}	
	else if (absolute == 2) {
		plugin_name = uwsgi_concat3(UWSGI_PLUGIN_DIR, "/", plugin);
		plugin_entry_symbol = uwsgi_concat2n(plugin, strlen(plugin)-3 ,"", 0);
	}
	else {
		plugin_name = uwsgi_concat4(UWSGI_PLUGIN_DIR, "/", plugin, "_plugin.so");
		plugin_entry_symbol = uwsgi_concat2(plugin, "_plugin");
	}
	plugin_handle = dlopen(plugin_name, RTLD_NOW | RTLD_GLOBAL);

        if (!plugin_handle) {
                uwsgi_log( "%s\n", dlerror());
        }
        else {
                up = dlsym(plugin_handle, plugin_entry_symbol);
		if (!up) {
			// is it a link ?
			memset(linkpath_buf, 0, 1024);
			memset(linkpath, 0, 1024);
			if ((linkpath_size = readlink(plugin_name, linkpath_buf, 1023)) > 0) {
				do {
					linkpath_buf[linkpath_size] = '\0';
					strcpy(linkpath, linkpath_buf);
				} while ((linkpath_size = readlink(linkpath, linkpath_buf, 1023)) > 0);
				uwsgi_log("%s\n", linkpath);
				free(plugin_entry_symbol);
				up = dlsym(plugin_handle, plugin_entry_symbol);
				char *slash = uwsgi_get_last_char(linkpath, '/');
				if (!slash) {
					slash = linkpath;
				}
				else {
					slash++;
				}
				plugin_entry_symbol = uwsgi_concat2n(slash, strlen(slash)-3, "",0);
				up = dlsym(plugin_handle, plugin_entry_symbol);
			}
		}
                if (up) {
			if (has_option) {
				struct option *lopt = up->options, *aopt;
				int found = 0;
				while ((aopt = lopt)) {
                			if (!aopt->name)
                        			break;
					if (!strcmp(has_option, aopt->name)) {
						found = 1;
						break;
					}	
                			lopt++;
				}
				if (!found) {
					if (dlclose(plugin_handle)) {
						uwsgi_error("dlclose()");
					}
					free(plugin_name);
					free(plugin_entry_symbol);
					return NULL;
				}
				
			}
			if (modifier != -1) {
				fill_plugin_table(modifier, up);			
			}
			else {
				fill_plugin_table(up->modifier1, up);			
			}
			free(plugin_name);
			free(plugin_entry_symbol);
			return plugin_handle;
                }
                uwsgi_log( "%s\n", dlerror());
        }

	free(plugin_name);

	return NULL;
}
