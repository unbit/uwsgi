#include "../../uwsgi.h"
#include <libpq-fe.h>

extern struct uwsgi_server uwsgi;

void uwsgi_imperial_monitor_pg_init(char *);
void uwsgi_imperial_monitor_pg(char *);
void emperor_pg_init(void);
void emperor_pg_do(char *, char *, time_t, uid_t, gid_t);

void emperor_pg_init(void) {
	uwsgi_register_imperial_monitor("pg", uwsgi_imperial_monitor_pg_init, uwsgi_imperial_monitor_pg);
}

void uwsgi_imperial_monitor_pg_init(char *arg) {
	uwsgi_log("[emperor] enabled emperor PostgreSQL monitor\n");
}

void emperor_pg_do(char *name, char *config, time_t ts, uid_t uid, gid_t gid) {

	if (!uwsgi_emperor_is_valid(name))
		return;

	struct uwsgi_instance *ui_current = emperor_get(name);

	if (ui_current) {
		// check if uid or gid are changed, in such case, stop the instance
		if (uwsgi.emperor_tyrant) {
			if (uid != ui_current->uid || gid != ui_current->gid) {
				uwsgi_log("[emperor-tyrant] !!! permissions of vassal %s changed. stopping the instance... !!!\n", name);
				emperor_stop(ui_current);
				return;
			}
		}
		// check if mtime is changed and the uWSGI instance must be reloaded
		if (ts > ui_current->last_mod) {
			emperor_respawn(ui_current, ts);
		}
	}
	else {
		emperor_add(name, ts, config, strlen(config), uid, gid);
	}
}


void uwsgi_imperial_monitor_pg(char *arg) {

	PGconn *conn = NULL;
	PGresult *res = NULL;
	const char *query = "SELECT name,config,EXTRACT(epoch FROM ts) FROM vassals";

	char *conn_string = uwsgi_str(arg + 5);

	char *semicolon = strchr(conn_string, ';');
	if (semicolon) {
		query = semicolon + 1;
		*semicolon = '\0';
	}
#ifdef UWSGI_DEBUG
	uwsgi_log("connecting to PgSQL %s\n", conn_string);
#endif
	conn = PQconnectdb(conn_string);
	if (!conn || PQstatus(conn) != CONNECTION_OK) {
		uwsgi_log("libpq-error: %s", PQerrorMessage(conn));
		goto end;
	}

	res = PQexec(conn, query);
	if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
		uwsgi_log("libpq-error: %s\n", PQerrorMessage(conn));
		goto end;
	}

	int i;

	for (i = 0; i < PQntuples(res); i++) {
		if (PQnfields(res) >= 3) {
			char *name = PQgetvalue(res, i, 0);
			char *config = PQgetvalue(res, i, 1);
			char *ts = PQgetvalue(res, i, 2);
			int len = strlen(ts);
			char *dot = strchr(ts, '.');
			if (dot) {
				len = dot - ts;
			}
			uid_t vassal_uid = 0;
			gid_t vassal_gid = 0;
			if (uwsgi.emperor_tyrant) {
				if (PQnfields(res) < 5) {
					uwsgi_log("[emperor-pg] missing uid and gid for vassal %s\n", name);
					continue;
				}
				char *q_uid = PQgetvalue(res, i, 3);
				char *q_gid = PQgetvalue(res, i, 4);
				vassal_uid = uwsgi_str_num(q_uid, strlen(q_uid));
				vassal_gid = uwsgi_str_num(q_gid, strlen(q_gid));
			}
			emperor_pg_do(name, config, uwsgi_str_num(ts, len), vassal_uid, vassal_gid);
		}
	}

end:
	if (res)
		PQclear(res);
	if (conn)
		PQfinish(conn);
}


struct uwsgi_plugin emperor_pg_plugin = {

	.name = "emperor_pg",
	.on_load = emperor_pg_init,
};
