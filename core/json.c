#ifdef UWSGI_JSON

#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

#if defined(UWSGI_JSON_YAJL_OLD)
#include <yajl/yajl_parse.h>

struct uwsgi_yajl_old_state {
	char *object;
	char *key;
	int in_object;
	int is_array;
};

static int uwsgi_yajl_cb_null(void *ctx) {
	struct uwsgi_yajl_old_state *uyos = (struct uwsgi_yajl_old_state *) ctx;
	if (!uyos->key) return 1;
	add_exported_option(uyos->key, strdup("0"), 0);
	return 1;
}

static int uwsgi_yajl_cb_boolean(void *ctx, int b) {
        struct uwsgi_yajl_old_state *uyos = (struct uwsgi_yajl_old_state *) ctx;
        if (!uyos->key) return 1;
	if (b) {
        	add_exported_option(uyos->key, strdup("1"), 0);
	}
	else {
        	add_exported_option(uyos->key, strdup("0"), 0);
	}
	return 1;
}

static int uwsgi_yajl_cb_integer(void *ctx, long n) {
        struct uwsgi_yajl_old_state *uyos = (struct uwsgi_yajl_old_state *) ctx;
        if (!uyos->key) return 1;
        add_exported_option(uyos->key, uwsgi_64bit2str((int64_t) n), 0);
	return 1;
}

static int uwsgi_yajl_cb_double(void *ctx, double n) {
	return uwsgi_yajl_cb_integer(ctx, (long) n);
}

static int uwsgi_yajl_cb_string(void *ctx, const unsigned char *s, unsigned int s_len) {
	struct uwsgi_yajl_old_state *uyos = (struct uwsgi_yajl_old_state *) ctx;
        if (!uyos->key) return 1;
        add_exported_option(uyos->key, uwsgi_concat2n((char *)s, (size_t)s_len, "", 0), 0);
	return 1;
}

static int uwsgi_yajl_cb_number(void *ctx, const char *n, unsigned int n_len) {
	return uwsgi_yajl_cb_string(ctx, (const unsigned char *)n, n_len);
}

static int uwsgi_yajl_cb_map_key(void *ctx, const unsigned char *s, unsigned int s_len) {
	struct uwsgi_yajl_old_state *uyos = (struct uwsgi_yajl_old_state *) ctx;
	if (!uyos->in_object) {
		if (!uwsgi_strncmp(uyos->object, strlen(uyos->object), (char *)s, (size_t)s_len)) {
			uyos->in_object = 1; 
		}
		return 1;
	}

	uyos->key = uwsgi_concat2n((char *)s, (size_t)s_len, "", 0);
	return 1;
}


static yajl_callbacks callbacks = {
	.yajl_null = uwsgi_yajl_cb_null,
	.yajl_boolean = uwsgi_yajl_cb_boolean,
	.yajl_integer = uwsgi_yajl_cb_integer,
	.yajl_double = uwsgi_yajl_cb_double,
	.yajl_number = uwsgi_yajl_cb_number,
	.yajl_string = uwsgi_yajl_cb_string,
	.yajl_start_map = NULL,
	.yajl_map_key = uwsgi_yajl_cb_map_key,
	.yajl_end_map = NULL,
	.yajl_start_array = NULL,
	.yajl_end_array = NULL,
};

void uwsgi_json_config(char *file, char *magic_table[]) {
        size_t len = 0;

        char *object_asked = "uwsgi";
        char *colon;

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

	struct uwsgi_yajl_old_state uyos;
	memset(&uyos, 0, sizeof(struct uwsgi_yajl_old_state));
	uyos.object = object_asked;
        uwsgi_log_initial("[uWSGI] getting JSON configuration from %s\n", file);

        char *json_data = uwsgi_open_and_read(file, &len, 1, magic_table);

	yajl_handle hand = yajl_alloc(&callbacks, NULL, NULL, &uyos);

	yajl_status s = yajl_parse(hand, (const unsigned char *)json_data, len);
	if (s != yajl_status_ok) {
		uwsgi_log("%s\n", yajl_get_error(hand, 1, (const unsigned char *)json_data, len));
		exit(1);
	}
}


#elif defined(UWSGI_JSON_YAJL)
#include <yajl/yajl_tree.h>

void uwsgi_json_config(char *file, char *magic_table[]) {
	size_t len = 0;

        char *object_asked = "uwsgi";
        char *colon;

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

        char *json_data = uwsgi_open_and_read(file, &len, 1, magic_table);

	char errbuf[1024];
	yajl_val node = yajl_tree_parse((const char *)json_data, errbuf, sizeof(errbuf));

	if (!node) {
		uwsgi_log("error parsing JSON data: %s\n", errbuf);
                exit(1);
	}

	const char * path[] = { object_asked, NULL };
	yajl_val v = yajl_tree_get(node, path, yajl_t_any);
	if (!YAJL_IS_OBJECT(v)) {
		uwsgi_log("you must define a object named %s in your JSON data\n", object_asked);
		exit(1);
	}

	size_t i;
	for(i=0;i<v->u.object.len;i++) {
		char *key = (char *) v->u.object.keys[i];
		yajl_val o = v->u.object.values[i];
		if (YAJL_IS_STRING(o)) {
                        add_exported_option(key, YAJL_GET_STRING(o) , 0);
                }
                else if (YAJL_IS_TRUE(o)) {
                        add_exported_option(key, strdup("1"), 0);
                }
                else if (YAJL_IS_FALSE(o) || YAJL_IS_NULL(o)) {
                        add_exported_option(key, strdup("0"), 0);
                }
		else if (YAJL_IS_NUMBER(o) || YAJL_IS_INTEGER(o)) {
                        add_exported_option(key, YAJL_GET_NUMBER(o), 0);
		}
                else if (YAJL_IS_ARRAY(o)) {
			size_t j;
			for(j=0;j<o->u.array.len;j++) {	
				yajl_val a_o = o->u.array.values[j];		
				if (YAJL_IS_STRING(a_o)) {
                        		add_exported_option(key, YAJL_GET_STRING(a_o) , 0);
                		}
                		else if (YAJL_IS_TRUE(a_o)) {
                        		add_exported_option(key, strdup("1"), 0);
                		}
                		else if (YAJL_IS_FALSE(a_o) || YAJL_IS_NULL(a_o)) {
                        		add_exported_option(key, strdup("0"), 0);
                		}
                		else if (YAJL_IS_NUMBER(a_o) || YAJL_IS_INTEGER(a_o)) {
                        		add_exported_option(key, YAJL_GET_NUMBER(a_o), 0);
                		}
			}
                }
	}
}
#else

#include <jansson.h>


void uwsgi_json_config(char *file, char *magic_table[]) {

	size_t len = 0;
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

	if (colon) colon[0] = ':';

}

#endif
#endif
