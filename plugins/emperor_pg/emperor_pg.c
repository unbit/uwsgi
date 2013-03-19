#include "../../uwsgi.h"
#include <libpq-fe.h>

extern struct uwsgi_server uwsgi;
extern struct uwsgi_instance *ui;

void uwsgi_imperial_monitor_pg_init(struct uwsgi_emperor_scanner *);
void uwsgi_imperial_monitor_pg(struct uwsgi_emperor_scanner *);
void emperor_pg_init(void);

void emperor_pg_init(void) {
	uwsgi_register_imperial_monitor("pg", uwsgi_imperial_monitor_pg_init, uwsgi_imperial_monitor_pg);
}

void uwsgi_imperial_monitor_pg_init(struct uwsgi_emperor_scanner *ues) {
	uwsgi_log("[emperor] enabled emperor PostgreSQL monitor\n");
}

void uwsgi_imperial_monitor_pg(struct uwsgi_emperor_scanner *ues) {

	PGconn *conn = NULL;
	PGresult *res = NULL;
	const char *query = "SELECT name,config,EXTRACT(epoch FROM ts) FROM vassals";

	char *conn_string = uwsgi_str(ues->arg + 5);

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
			char *socket_name = NULL;
			if (PQnfields(res) > 5) {
				socket_name = PQgetvalue(res, i, 5);	
			}
			uwsgi_emperor_simple_do(ues, name, config, uwsgi_str_num(ts, len), vassal_uid, vassal_gid, socket_name);
		}
	}

	// now check for removed instances
        struct uwsgi_instance *c_ui = ui->ui_next;

        while (c_ui) {
                if (c_ui->scanner == ues) {
			int found = 0;
			for (i = 0; i < PQntuples(res); i++) {
				if (PQnfields(res) >= 3) {
					if (!strcmp(PQgetvalue(res, i, 0), c_ui->name)) {
						found = 1;
						break;
					}
				}
			}
			if (!found) {
                                emperor_stop(c_ui);
                        }
                }
                c_ui = c_ui->ui_next;
        }


end:
	free(conn_string);

	if (res)
		PQclear(res);
	if (conn)
		PQfinish(conn);
}


struct uwsgi_plugin emperor_pg_plugin = {

	.name = "emperor_pg",
	.on_load = emperor_pg_init,
};
