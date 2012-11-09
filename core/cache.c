#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

void uwsgi_init_cache() {

	if (!uwsgi.cache_blocksize)
		uwsgi.cache_blocksize = UMAX16;

	uwsgi.cache_hashtable = (uint64_t *) mmap(NULL, sizeof(uint64_t) * UMAX16, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
	if (!uwsgi.cache_hashtable) {
		uwsgi_error("mmap()");
		exit(1);
	}

	memset(uwsgi.cache_hashtable, 0, sizeof(uint64_t) * UMAX16);

	uwsgi.cache_unused_stack = (uint64_t *) mmap(NULL, sizeof(uint64_t) * uwsgi.cache_max_items, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
	if (!uwsgi.cache_unused_stack) {
		uwsgi_error("mmap()");
		exit(1);
	}

	memset(uwsgi.cache_unused_stack, 0, sizeof(uint64_t) * uwsgi.cache_max_items);

	// the first cache item is always zero
	uwsgi.shared->cache_first_available_item = 1;
	uwsgi.shared->cache_unused_stack_ptr = 0;

	//uwsgi.cache_items = (struct uwsgi_cache_item *) mmap(NULL, sizeof(struct uwsgi_cache_item) * uwsgi.cache_max_items, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
	if (uwsgi.cache_store) {
		uwsgi.cache_filesize = (sizeof(struct uwsgi_cache_item) * uwsgi.cache_max_items) + (uwsgi.cache_blocksize * uwsgi.cache_max_items);
		int cache_fd;
		struct stat cst;

		if (stat(uwsgi.cache_store, &cst)) {
			uwsgi_log("creating a new cache store file: %s\n", uwsgi.cache_store);
			cache_fd = open(uwsgi.cache_store, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
			if (cache_fd >= 0) {
				// fill the caching store
				if (ftruncate(cache_fd, uwsgi.cache_filesize)) {
					uwsgi_log("ftruncate()");
					exit(1);
				}
			}
		}
		else {
			if ((size_t) cst.st_size != uwsgi.cache_filesize || !S_ISREG(cst.st_mode)) {
				uwsgi_log("invalid cache store file. Please remove it or fix cache blocksize/items to match its size\n");
				exit(1);
			}
			cache_fd = open(uwsgi.cache_store, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
			uwsgi_log("recovered cache from backing store file: %s\n", uwsgi.cache_store);
		}

		if (cache_fd < 0) {
			uwsgi_error_open(uwsgi.cache_store);
			exit(1);
		}
		uwsgi.cache_items = (struct uwsgi_cache_item *) mmap(NULL, uwsgi.cache_filesize, PROT_READ | PROT_WRITE, MAP_SHARED, cache_fd, 0);
		uwsgi_cache_fix();

	}
	else {
		uwsgi.cache_items = (struct uwsgi_cache_item *) mmap(NULL, (sizeof(struct uwsgi_cache_item) * uwsgi.cache_max_items) + (uwsgi.cache_blocksize * uwsgi.cache_max_items), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
		int i;
		for (i = 0; i < (int) uwsgi.cache_max_items; i++) {
			memset(&uwsgi.cache_items[i], 0, sizeof(struct uwsgi_cache_item));
		}
	}
	if (!uwsgi.cache_items) {
		uwsgi_error("mmap()");
		exit(1);
	}

	/*
	   uwsgi.cache = mmap(NULL, uwsgi.cache_blocksize * uwsgi.cache_max_items, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
	   if (!uwsgi.cache) {
	   uwsgi_error("mmap()");
	   exit(1);
	   }
	 */

	uwsgi.cache = ((void *) uwsgi.cache_items) + (sizeof(struct uwsgi_cache_item) * uwsgi.cache_max_items);

	uwsgi.cache_lock = uwsgi_rwlock_init("cache");

	uwsgi_log("*** Cache subsystem initialized: %lluMB (key: %llu bytes, keys: %llu bytes, data: %llu bytes) preallocated ***\n", (unsigned long long) ((uwsgi.cache_blocksize * uwsgi.cache_max_items) + (sizeof(struct uwsgi_cache_item) * uwsgi.cache_max_items)) / (1024 * 1024), (unsigned long long) sizeof(struct uwsgi_cache_item), (unsigned long long) (sizeof(struct uwsgi_cache_item) * uwsgi.cache_max_items), (unsigned long long) (uwsgi.cache_blocksize * uwsgi.cache_max_items));
}

uint32_t djb33x_hash(char *key, int keylen) {

	register uint32_t hash = 5381;
	int i;

	for (i = 0; i < keylen; i++) {
		hash = ((hash << 5) + hash) ^ key[i];
	}

	return hash;
}


static inline uint64_t uwsgi_cache_get_index(char *key, uint16_t keylen) {

	uint32_t hash = djb33x_hash(key, keylen);

	int hash_key = hash % 0xffff;

	uint64_t slot = uwsgi.cache_hashtable[hash_key];

	struct uwsgi_cache_item *uci;
	uint64_t rounds = 0;

	//uwsgi_log("found slot %d for key %d\n", slot, hash_key);

	uci = &uwsgi.cache_items[slot];

	// first round
	if (uci->djbhash != hash)
		return 0;
	if (uci->keysize != keylen)
		goto cycle;
	if (memcmp(uci->key, key, keylen))
		goto cycle;

	return slot;

cycle:
	while (uci->next) {
		slot = uci->next;
		uci = &uwsgi.cache_items[slot];
		rounds++;
		if (rounds > uwsgi.cache_max_items) {
			uwsgi_log("ALARM !!! cache-loop (and potential deadlock) detected slot = %llu prev = %llu next = %llu\n", uci->next, slot, uci->prev, uci->next);
			// terrible case: the whole uWSGI stack can deadlock, leaving only the master alive
			// if the master is avalable, trigger a brutal reload
			if (uwsgi.master_process) {
				kill(uwsgi.workers[0].pid, SIGTERM);
			}
			// otherwise kill the current worker (could be pretty useless...)
			else {
				exit(1);
			}
		}
		if (uci->djbhash != hash)
			return 0;
		if (uci->keysize != keylen)
			continue;
		if (!memcmp(uci->key, key, keylen))
			return slot;
	}

	return 0;
}

uint32_t uwsgi_cache_exists(char *key, uint16_t keylen) {

	return uwsgi_cache_get_index(key, keylen);
}

char *uwsgi_cache_get(char *key, uint16_t keylen, uint64_t * valsize) {

	uint64_t index = uwsgi_cache_get_index(key, keylen);

	if (index) {
		if (uwsgi.cache_items[index].flags & UWSGI_CACHE_FLAG_UNGETTABLE)
			return NULL;
		*valsize = uwsgi.cache_items[index].valsize;
		uwsgi.cache_items[index].hits++;
		return uwsgi.cache + (index * uwsgi.cache_blocksize);
	}

	return NULL;
}

int uwsgi_cache_del(char *key, uint16_t keylen, uint64_t index) {

	struct uwsgi_cache_item *uci;
	int ret = -1;

	if (!index)
		index = uwsgi_cache_get_index(key, keylen);

	if (index) {
		uci = &uwsgi.cache_items[index];
		uci->keysize = 0;
		uci->valsize = 0;
		uwsgi.shared->cache_unused_stack_ptr++;
		uwsgi.cache_unused_stack[uwsgi.shared->cache_unused_stack_ptr] = index;
		// try to return to initial condition...
		if (index == uwsgi.shared->cache_first_available_item - 1) {
			uwsgi.shared->cache_first_available_item--;
			//uwsgi_log("FACI: %llu STACK PTR: %llu\n", (unsigned long long) uwsgi.shared->cache_first_available_item, (unsigned long long) uwsgi.shared->cache_unused_stack_ptr);
		}
		ret = 0;
		// relink collisioned entry
		if (uci->prev) {
			uwsgi.cache_items[uci->prev].next = uci->next;
		}
		else {
			// set next as the new entry point (could be 0)
			uwsgi.cache_hashtable[uci->djbhash % 0xffff] = uci->next;
		}

		if (uci->next) {
			uwsgi.cache_items[uci->next].prev = uci->prev;
		}

		if (!uci->prev && !uci->next) {
			// reset hashtable entry
			//uwsgi_log("!!! resetted hashtable entry !!!\n");
			uwsgi.cache_hashtable[uci->djbhash % 0xffff] = 0;
		}
		uci->djbhash = 0;
		uci->prev = 0;
		uci->next = 0;
		uci->expires = 0;
	}

	return ret;
}

void uwsgi_cache_fix() {

	uint64_t i;

	for (i = 0; i < uwsgi.cache_max_items; i++) {
		// valid record ?
		if (uwsgi.cache_items[i].keysize) {
			if (!uwsgi.cache_items[i].prev) {
				// put value in hash_table
				uwsgi.cache_hashtable[uwsgi.cache_items[i].djbhash % 0xffff] = i;
			}
		}
		else {
			// put this record in unused stack
			uwsgi.shared->cache_first_available_item = i;
			uwsgi.shared->cache_unused_stack_ptr++;
			uwsgi.cache_unused_stack[uwsgi.shared->cache_unused_stack_ptr] = i;
		}
	}
}

int uwsgi_cache_set(char *key, uint16_t keylen, char *val, uint64_t vallen, uint64_t expires, uint16_t flags) {

	uint64_t index = 0, last_index = 0;

	struct uwsgi_cache_item *uci, *ucii;

	int ret = -1;

	if (!keylen || !vallen)
		return -1;

	if (keylen > UWSGI_CACHE_MAX_KEY_SIZE)
		return -1;

	if (uwsgi.shared->cache_first_available_item >= uwsgi.cache_max_items && !uwsgi.shared->cache_unused_stack_ptr) {
		uwsgi_log("*** DANGER cache is FULL !!! ***\n");
		goto end;
	}

	//uwsgi_log("putting cache data in key %.*s %d\n", keylen, key, vallen);
	index = uwsgi_cache_get_index(key, keylen);
	if (!index) {
		if (uwsgi.shared->cache_unused_stack_ptr) {
			//uwsgi_log("!!! REUSING CACHE SLOT !!! (faci: %llu)\n", (unsigned long long) uwsgi.shared->cache_first_available_item);
			index = uwsgi.cache_unused_stack[uwsgi.shared->cache_unused_stack_ptr];
			uwsgi.shared->cache_unused_stack_ptr--;
		}
		else {
			index = uwsgi.shared->cache_first_available_item;
			if (uwsgi.shared->cache_first_available_item < uwsgi.cache_max_items) {
				uwsgi.shared->cache_first_available_item++;
			}
		}
		uci = &uwsgi.cache_items[index];
		if (expires)
			expires += uwsgi_now();
		uci->expires = expires;
		uci->djbhash = djb33x_hash(key, keylen);
		uci->hits = 0;
		uci->flags = flags;
		memcpy(uci->key, key, keylen);
		memcpy(uwsgi.cache + (index * uwsgi.cache_blocksize), val, vallen);

		// set this as late as possibile (to reduce races risk)

		uci->valsize = vallen;
		uci->keysize = keylen;
		ret = 0;
		// now put the value in the 16bit hashtable
		int slot = uci->djbhash % 0xffff;
		// reset values
		uci->prev = 0;
		uci->next = 0;

		if (uwsgi.cache_hashtable[slot] == 0) {
			uwsgi.cache_hashtable[slot] = index;
		}
		else {
			//uwsgi_log("HASH COLLISION !!!!\n");
			// append to first available next
			last_index = uwsgi.cache_hashtable[slot];
			ucii = &uwsgi.cache_items[last_index];
			while (ucii->next) {
				last_index = ucii->next;
				ucii = &uwsgi.cache_items[last_index];
			}
			ucii->next = index;
			uci->prev = last_index;
		}
	}
	else if (flags & UWSGI_CACHE_FLAG_UPDATE) {
		uci = &uwsgi.cache_items[index];
		if (expires) {
			expires += uwsgi_now();
			uci->expires = expires;
		}
		memcpy(uwsgi.cache + (index * uwsgi.cache_blocksize), val, vallen);
		uci->valsize = vallen;
		ret = 0;
	}

end:
	return ret;

}

/* THIS PART IS HEAVILY OPTIMIZED: PERFORMANCE NOT ELEGANCE !!! */

void *cache_thread_loop(void *fd_ptr) {

	int *fd_tmp = (int *) fd_ptr;
	int fd = *fd_tmp;
	int i;
	ssize_t len;
	char uwsgi_packet[UMAX16 + 4];
	struct uwsgi_header *uh = (struct uwsgi_header *) uwsgi_packet;
	char *val;
	uint64_t vallen;
	char *key;
	uint16_t keylen;
	struct pollfd ctl_poll;
	char *watermark;
	struct sockaddr_un ctl_sun;
	socklen_t ctl_sun_len;

	ctl_poll.events = POLLIN;

	for (;;) {
		ctl_sun_len = sizeof(struct sockaddr_un);
		pthread_mutex_lock(&uwsgi.cache_server_lock);

		ctl_poll.fd = accept(fd, (struct sockaddr *) &ctl_sun, &ctl_sun_len);

		pthread_mutex_unlock(&uwsgi.cache_server_lock);

		if (ctl_poll.fd < 0) {
			uwsgi_error("cache accept()");
			continue;
		}
		i = 0;
		while (i < 4) {
			len = poll(&ctl_poll, 1, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
			if (len <= 0) {
				uwsgi_error("cache poll()");
				goto clear;
			}
			len = read(ctl_poll.fd, uwsgi_packet + i, 4 - i);
			if (len < 0) {
				uwsgi_error("cache read()");
				goto clear;
			}
			i += len;
		}

		if (uh->pktsize == 0)
			goto clear;

		while (i < 4 + uh->pktsize) {
			len = poll(&ctl_poll, 1, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
			if (len <= 0) {
				uwsgi_error("cache poll()");
				goto clear;
			}
			len = read(ctl_poll.fd, uwsgi_packet + i, (4 + uh->pktsize) - i);
			if (len < 0) {
				uwsgi_error("cache read()");
				goto clear;
			}
			i += len;
		}

		watermark = uwsgi_packet + 4 + uh->pktsize;

		// get first parameter
		memcpy(&keylen, uwsgi_packet + 4, 2);
#ifdef __BIG_ENDIAN__
		keylen = uwsgi_swap16(keylen);
#endif
		if (uwsgi_packet + 6 + keylen > watermark)
			goto clear;
		key = uwsgi_packet + 6 + keylen + 2;
		memcpy(&keylen, key - 2, 2);
#ifdef __BIG_ENDIAN__
		keylen = uwsgi_swap16(keylen);
#endif

		if (key + keylen > watermark)
			goto clear;

		val = uwsgi_cache_get(key, keylen, &vallen);
		if (val && vallen > 0) {
			if (write(ctl_poll.fd, val, vallen) < 0) {
				uwsgi_error("cache write()");
			}
		}

clear:
		close(ctl_poll.fd);
	}

	return NULL;
}

int uwsgi_cache_server(char *socket, int threads) {

	int *fd = uwsgi_malloc(sizeof(int));

	int i;
	pthread_t thread_id;
	char *tcp_port = strchr(socket, ':');
	if (tcp_port) {
		*fd = bind_to_tcp(socket, uwsgi.listen_queue, tcp_port);
	}
	else {
		*fd = bind_to_unix(socket, uwsgi.listen_queue, uwsgi.chmod_socket, uwsgi.abstract_socket);
	}

	pthread_mutex_init(&uwsgi.cache_server_lock, NULL);

	if (threads < 1)
		threads = 1;

	uwsgi_log("*** cache-optimized server enabled on fd %d (%d threads) ***\n", *fd, threads);

	for (i = 0; i < threads; i++) {
		pthread_create(&thread_id, NULL, cache_thread_loop, (void *) fd);
	}

	return *fd;
}

int uwsgi_cache_enabled() {
	if (uwsgi.cache_max_items > 0)
		return 1;
	return 0;
}

void uwsgi_cache_wlock() {
	uwsgi.lock_ops.wlock(uwsgi.cache_lock);
}

void uwsgi_cache_rlock() {
	uwsgi.lock_ops.rlock(uwsgi.cache_lock);
}

void uwsgi_cache_rwunlock() {
	uwsgi.lock_ops.rwunlock(uwsgi.cache_lock);
}
