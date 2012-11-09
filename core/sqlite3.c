#ifdef UWSGI_SQLITE3

#include "uwsgi.h"
#include <sqlite3.h>

extern struct uwsgi_server uwsgi;

static int uwsgi_sqlite3_config_callback(void *magic_table, int field_count, char **fields, char **col) {
	// make a copy of the string
	if (field_count >= 2) {
		int value_len = strlen(fields[1]) + 1;
		char *value = magic_sub(fields[1], value_len, &value_len, (char **) magic_table);
		add_exported_option(uwsgi_strncopy(fields[0], strlen(fields[0])), value, 0);
	}

	return 0;
}


void uwsgi_sqlite3_config(char *file, char *magic_table[]) {

	sqlite3 *db;
	char *err = NULL;
	char *query = "SELECT * FROM uwsgi";

	char *colon = uwsgi_get_last_char(file, ':');

	if (colon) {
		colon[0] = 0;
		if (colon[1] != 0) {
			query = colon + 1;
		}
	}

	uwsgi_log("[uWSGI] getting sqlite3 configuration from %s\n", file);

#ifdef sqlite3_open_v2
	if (sqlite3_open_v2(file, &db, SQLITE_OPEN_READONLY, NULL)) {
#else
	if (sqlite3_open(file, &db)) {
#endif
		uwsgi_log("unable to open sqlite3 db: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		exit(1);
	}

	if (sqlite3_exec(db, query, uwsgi_sqlite3_config_callback, (void *) magic_table, &err)) {
		uwsgi_log("sqlite3 error: %s\n", err);
		sqlite3_close(db);
		exit(1);
	}

	sqlite3_close(db);

}

#endif
