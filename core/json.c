#ifdef UWSGI_JSON

#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

#include <jansson.h>


/*
	I really love the jansson library...
   */

void uwsgi_json_config(char *file, char *magic_table[]) {

	int len = 0;
	char *json_data;


	const char *key;

	json_t *root;
	json_error_t error;
	json_t *config;
	json_t *config_value, *config_array_item;

	void *config_iter;

	char *object_asked = "uwsgi";
	char *colon;
	int i;

	if (uwsgi_check_scheme(file)) {
		colon = uwsgi_get_last_char(file, '/');
		colon = uwsgi_get_last_char(colon, ':');
	}
	else {
		colon = uwsgi_get_last_char(file, ':');
	}

	if (colon) {
		colon[0] = 0;
		if (colon[1] != 0) {
			object_asked = colon + 1;
		}
	}

	uwsgi_log_initial("[uWSGI] getting JSON configuration from %s\n", file);

	json_data = uwsgi_open_and_read(file, &len, 1, magic_table);

#ifdef JANSSON_MAJOR_VERSION
	root = json_loads(json_data, 0, &error);
#else
	root = json_loads(json_data, &error);
#endif

	if (!root) {
		uwsgi_log("error parsing JSON data: line %d %s\n", error.line, error.text);
		exit(1);
	}

	config = json_object_get(root, object_asked);

	if (!json_is_object(config)) {
		uwsgi_log("you must define a object named %s in your JSON data\n", object_asked);
		exit(1);
	}

	config_iter = json_object_iter(config);

	while (config_iter) {
		key = json_object_iter_key(config_iter);
		config_value = json_object_iter_value(config_iter);

		if (json_is_string(config_value)) {
			add_exported_option((char *) key, (char *) json_string_value(config_value), 0);
		}
		else if (json_is_true(config_value)) {
			add_exported_option((char *) key, strdup("1"), 0);
		}
		else if (json_is_false(config_value) || json_is_null(config_value)) {
			add_exported_option((char *) key, strdup("0"), 0);
		}
		else if (json_is_integer(config_value)) {
			add_exported_option((char *) key, uwsgi_num2str(json_integer_value(config_value)), 0);
		}
		else if (json_is_array(config_value)) {
			for (i = 0; i < (int) json_array_size(config_value); i++) {
				config_array_item = json_array_get(config_value, i);
				if (json_is_string(config_array_item)) {
					add_exported_option((char *) key, (char *) json_string_value(config_array_item), 0);
				}
				else if (json_is_true(config_array_item)) {
					add_exported_option((char *) key, strdup("1"), 0);
				}
				else if (json_is_false(config_array_item) || json_is_null(config_array_item)) {
					add_exported_option((char *) key, strdup("0"), 0);
				}
				else if (json_is_integer(config_array_item)) {
					add_exported_option((char *) key, uwsgi_num2str(json_integer_value(config_array_item)), 0);
				}
			}
		}

		config_iter = json_object_iter_next(config, config_iter);
	}

}

#endif
