#include <uwsgi.h>

#include "client/dbclient.h"

extern struct uwsgi_server uwsgi;
extern struct uwsgi_instance *ui;

// one for each mongodb imperial monitor
struct uwsgi_emperor_mongodb_state {
	char *address;
	char *collection;
	char *json;
};


extern "C" void uwsgi_imperial_monitor_mongodb(struct uwsgi_emperor_scanner *ues) {

	struct uwsgi_emperor_mongodb_state *uems = (struct uwsgi_emperor_mongodb_state *) ues->data;

	try {

		// requested fields
        	mongo::BSONObj p = BSON( "name" << 1 << "config" << 1 << "ts" << 1 << "uid" << 1 << "gid" << 1 );
		mongo::BSONObj q = mongo::fromjson(uems->json);
		// the connection object (will be automatically destroyed at each cycle)
		mongo::DBClientConnection c;
		// set the socket timeout
		c.setSoTimeout(uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
		// connect
		c.connect(uems->address);

		// run the query
		std::auto_ptr<mongo::DBClientCursor> cursor = c.query(uems->collection, q, 0, 0, &p);
		while( cursor->more() ) {
                	mongo::BSONObj p = cursor->next();

			// checking for an empty string is not required, but we reduce the load
			// in case of badly strctured databases
			const char *name = p.getStringField("name");
			if (strlen(name) == 0) continue;

			const char *config = p.getStringField("config");

			time_t vassal_ts = 0;
			// ts must be a Date object !!!
			mongo::BSONElement ts = p.getField("ts");
			if (ts.type() == mongo::Date) {
				vassal_ts = ts.date();
			}

			uid_t vassal_uid = 0;
			gid_t vassal_gid = 0;
			// check for tyrant mode
			if (uwsgi.emperor_tyrant) {
				int tmp_uid = p.getIntField("uid");
				int tmp_gid = p.getIntField("gid");
				if (tmp_uid < 0) tmp_uid = 0;
				if (tmp_gid < 0) tmp_gid = 0;
				vassal_uid = tmp_uid;
				vassal_gid = tmp_gid;
			} 

			const char *socket_name = p.getStringField("socket");

			uwsgi_emperor_simple_do(ues, (char *) name, (char *) config, vassal_ts/1000, vassal_uid, vassal_gid, (char *) socket_name);
		}


		// now check for removed instances
        	struct uwsgi_instance *c_ui = ui->ui_next;

        	while (c_ui) {
                	if (c_ui->scanner == ues) {
				mongo::BSONObjBuilder b;
				b.appendElements(q);
				b.append("name", c_ui->name);
				mongo::BSONObj q2 = b.obj();
				cursor = c.query(uems->collection, q2, 0, 0, &p);
#ifdef UWSGI_DEBUG
				uwsgi_log("JSON: %s\n", q2.toString().c_str());
#endif
				if (!cursor->more()) {
                                	emperor_stop(c_ui);
				}
                	}
                	c_ui = c_ui->ui_next;
        	}


	}	
	catch ( mongo::DBException &e ) {
		uwsgi_log("[emperor-mongodb] ERROR(%s/%s): %s\n", uems->address, uems->collection, e.what());
	}

}

// setup a new mongodb imperial monitor
extern "C" void uwsgi_imperial_monitor_mongodb_init(struct uwsgi_emperor_scanner *ues) {

	// allocate a new state
        ues->data = uwsgi_calloc(sizeof(struct uwsgi_emperor_mongodb_state));
	size_t arg_len = strlen(ues->arg);
	struct uwsgi_emperor_mongodb_state *uems = (struct uwsgi_emperor_mongodb_state *) ues->data;

	// parse args/ set defaults
	uems->address = (char *) "127.0.0.1:27017";
	uems->collection = (char *) "uwsgi.emperor.vassals";
	uems->json = (char *) "";
	if (arg_len > 10) {
		uems->address = uwsgi_str(ues->arg+10);
		char *comma = strchr(uems->address, ',');
		if (!comma) goto done;
		*comma = 0;
		uems->collection = comma+1;
		comma = strchr(uems->collection, ',');
		if (!comma) goto done;
		*comma = 0;
		uems->json = comma+1;
	}
done:
        uwsgi_log("[emperor] enabled emperor MongoDB monitor for %s on collection %s\n", uems->address, uems->collection);
}

