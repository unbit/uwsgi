#include <uwsgi.h>

#include "client/dbclient.h"

extern "C" int uwsgi_mongodb_version() {
	// this is only a hack to force the linked to embed libmongoclient.a
	mongo::DBClientConnection c;
	return 0;
}
