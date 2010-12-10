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

inline uint16_t uwsgi_cache_get_index(char *key, uint16_t keylen) {

	uint32_t hash = djb33x_hash(key, keylen);
	int i;

	for(i=1;i<uwsgi.cache_max_items;i++) {
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


char *uwsgi_cache_get(char *key, uint16_t keylen, uint16_t *valsize) {

	uint16_t index = uwsgi_cache_get_index(key, keylen);

	/* is locking needed for reading ?
	   I do not think so:

	   case1 => reading during delete -> the worst case is receiving corrupted data for a item that must not exists
	   case2 => reading during set -> the worst case is receiving corrupted data for an incomplete item

	*/
	
	if (index) {
		*valsize = uwsgi.cache_items[index].valsize;
		// no locking needed, as this is only an hint
		uwsgi.cache_items[index].hits++;
		return uwsgi.cache+(index*32768);
	}

	return NULL;
}

int uwsgi_cache_del(char *key, uint16_t keylen) {

	uint16_t index = 0;
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

	uint16_t index = 0 ;
	struct uwsgi_cache_item *uci;
	int ret = -1;
	if (!keylen || !vallen) return -1;
	if (keylen > UWSGI_CACHE_MAX_KEY_SIZE) return -1;	

	uwsgi_lock(uwsgi.cache_lock);
	if (uwsgi.shared->cache_first_available_item >= uwsgi.cache_max_items) goto end;

	index = uwsgi_cache_get_index(key, keylen);
	if (!index) {
		index = uwsgi.shared->cache_first_available_item;	
		uci = &uwsgi.cache_items[index] ;
		uci->expires = expires;
		uci->djbhash = djb33x_hash(key, keylen);
		uci->hits = 0;
		uci->used = 1;
		memcpy(uci->key, key, keylen);
		memcpy(uwsgi.cache+(index*32768), val, vallen);
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
