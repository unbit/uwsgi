#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

uint32_t djb33x_hash(char *key, int keylen) {

	register uint32_t hash = 5381;
	int i;

	for(i=0;i<keylen;i++) {
		hash = ((hash << 5) + hash) ^ key[i];
	}

	return hash;
}

inline uint32_t uwsgi_cache_get_index(char *key, uint16_t keylen) {

	uint32_t hash = djb33x_hash(key, keylen);
	uint32_t i;

	for(i=1;i< uwsgi.cache_max_items;i++) {
		// end of table ?
		//uwsgi_log("cache item %d -> %d %d %d %.*s %d\n", i, uwsgi.cache_items[i].used, uwsgi.cache_items[i].djbhash, uwsgi.cache_items[i].keysize, uwsgi.cache_items[i].keysize, uwsgi.cache_items[i].key, uwsgi.cache_items[i].valsize);
		if (uwsgi.cache_items[i].used == 0) break;

		// hash comparison
		if (uwsgi.cache_items[i].djbhash != hash) continue;

		// keysize comparison
		if (uwsgi.cache_items[i].keysize != keylen) continue ;

		// key comparison
		if (!memcmp(uwsgi.cache_items[i].key, key, keylen)) return i;

	}

	return 0;
}

uint32_t uwsgi_cache_exists(char *key, uint16_t keylen) {

	return uwsgi_cache_get_index(key, keylen);
}

char *uwsgi_cache_get(char *key, uint16_t keylen, uint16_t *valsize) {

	uint32_t index = uwsgi_cache_get_index(key, keylen);

	/* is locking needed for reading ?
	   I do not think so:

	   case1 => reading during delete -> the worst case is receiving corrupted data for a item that must not exists
	   case2 => reading during set -> the worst case is receiving corrupted data for an incomplete item

	*/
	
	if (index) {
		*valsize = uwsgi.cache_items[index].valsize;
		// no locking needed, as this is only an hint
		uwsgi.cache_items[index].hits++;
		return uwsgi.cache+(index*0xffff);
	}

	return NULL;
}

int uwsgi_cache_del(char *key, uint16_t keylen) {

	uint32_t index = 0;
	struct uwsgi_cache_item *uci;
	int ret = -1;

	uwsgi_lock(uwsgi.cache_lock);

	index = uwsgi_cache_get_index(key, keylen);
	if (index) {
		uci = &uwsgi.cache_items[index] ;
		uci->keysize = 0;
		uwsgi.shared->cache_first_available_item_tmp = uwsgi.shared->cache_first_available_item;
		uwsgi.shared->cache_first_available_item = index;
		ret = 0;
	}

	uwsgi_unlock(uwsgi.cache_lock);

	return ret;
}

int uwsgi_cache_set(char *key, uint16_t keylen, char *val, uint16_t vallen, uint64_t expires) {

	uint32_t index = 0 ;
	struct uwsgi_cache_item *uci;
	int ret = -1;
	if (!keylen || !vallen) return -1;
	if (keylen > UWSGI_CACHE_MAX_KEY_SIZE) return -1;	

	uwsgi_lock(uwsgi.cache_lock);
	if (uwsgi.shared->cache_first_available_item >= uwsgi.cache_max_items) goto end;

	//uwsgi_log("putting cache data in key %.*s %d\n", keylen, key, vallen);
	index = uwsgi_cache_get_index(key, keylen);
	if (!index) {
		index = uwsgi.shared->cache_first_available_item;	
		uci = &uwsgi.cache_items[index] ;
		uci->expires = expires;
		uci->djbhash = djb33x_hash(key, keylen);
		uci->hits = 0;
		uci->used = 1;
		memcpy(uci->key, key, keylen);
		memcpy(uwsgi.cache+(index*0xffff), val, vallen);
		// set this as late as possibile (to minimize locking)
		uci->valsize = vallen;
		uci->keysize = keylen;	
		ret = 0;
		if (uwsgi.shared->cache_first_available_item_tmp) {
			uwsgi.shared->cache_first_available_item = uwsgi.shared->cache_first_available_item_tmp ;
			uwsgi.shared->cache_first_available_item_tmp = 0;
		}
		else {
			uwsgi.shared->cache_first_available_item++;
		}
	}

end:
	uwsgi_unlock(uwsgi.cache_lock);

	return ret;
	
}

void cache_command(char *key, uint16_t keylen, char *val, uint16_t vallen, void *data) {

	struct wsgi_request *wsgi_req = (struct wsgi_request *) data;

	if (vallen > 0) {
		if (!uwsgi_strncmp(key, keylen, "key", 3)) {
			val = uwsgi_cache_get(val, vallen, &vallen);
                        if (val && vallen > 0) {
                        	wsgi_req->response_size = write(wsgi_req->poll.fd, val, vallen);
                        }

		}		
	}
}

int uwsgi_cache_request(struct wsgi_request *wsgi_req) {

	uint16_t vallen = 0;
	char *value;
	char *argv[3];
	uint8_t argc = 0;

	switch(wsgi_req->uh.modifier2) {
		case 0:
			// get
			if (wsgi_req->uh.pktsize > 0) {
				value = uwsgi_cache_get(wsgi_req->buffer, wsgi_req->uh.pktsize, &vallen);
				if (value && vallen > 0) {
					wsgi_req->uh.pktsize = vallen;
					wsgi_req->response_size = write(wsgi_req->poll.fd, &wsgi_req->uh, 4);
					wsgi_req->response_size += write(wsgi_req->poll.fd, value, vallen);
				}
			}
			break;		
		case 1:
			// set
			if (wsgi_req->uh.pktsize > 0) {
				argc = 3;
				if (!uwsgi_parse_array(wsgi_req->buffer, wsgi_req->uh.pktsize, argv, &argc)) {
					if (argc > 1) {
						uwsgi_cache_set(argv[0], strlen(argv[0]), argv[1], strlen(argv[1]), 0);
					}
				}
			}
			break;
		case 2:
			// del
			if (wsgi_req->uh.pktsize > 0) {
				uwsgi_cache_del(wsgi_req->buffer, wsgi_req->uh.pktsize);
			}
			break;
		case 4:
			// dict
			if (wsgi_req->uh.pktsize > 0) {
				uwsgi_hooked_parse(wsgi_req->buffer, wsgi_req->uh.pktsize, cache_command, (void *) wsgi_req);
			}
			break;
	}

	return 0;
}

struct uwsgi_plugin uwsgi_cache_plugin = {

        .name = "cache",
        .modifier1 = 111, 
        .request = uwsgi_cache_request,

};

