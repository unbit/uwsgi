#include <uwsgi.h>

#include "client/dbclient.h"

extern struct uwsgi_server uwsgi;

// one for each mongodb stats pusher
struct stats_pusher_mongodb_conf {
	char *address;
	char *collection;
	char *freq;
};


extern "C" void stats_pusher_mongodb(struct uwsgi_stats_pusher_instance *uspi, time_t now, char *json, size_t json_len) {

	struct stats_pusher_mongodb_conf *spmc = (struct stats_pusher_mongodb_conf *) uspi->data;
	if (!uspi->configured) {
		spmc = (struct stats_pusher_mongodb_conf *) uwsgi_calloc(sizeof(struct stats_pusher_mongodb_conf));
		if (uspi->arg) {
			if (uwsgi_kvlist_parse(uspi->arg, strlen(uspi->arg), ',', '=',
                                "addr", &spmc->address,
                                "address", &spmc->address,
                                "collection", &spmc->collection,
                                "freq", &spmc->freq, NULL)) {
                                free(spmc);
                                return;
                        }
		}
		if (!spmc->address) spmc->address = (char *) "127.0.0.1:27017";
		if (!spmc->collection) spmc->collection = (char *) "uwsgi.statistics";
		if (spmc->freq) uspi->freq = atoi(spmc->freq);
		uspi->data = spmc;
		uspi->configured = 1;
	}

	try {
		int j_len = (int) json_len;
		mongo::BSONObj b = mongo::fromjson(json, &j_len);
		// the connection object (will be automatically destroyed at each cycle)
		mongo::DBClientConnection c;
		// set the socket timeout
		c.setSoTimeout(uwsgi.socket_timeout);
		// connect
		c.connect(spmc->address);
		c.insert(spmc->collection, b);
	}	
	catch ( mongo::DBException &e ) {
		uwsgi_log("[stats-pusher-mongodb] ERROR(%s/%s): %s\n", spmc->address, spmc->collection, e.what());
	}

}
