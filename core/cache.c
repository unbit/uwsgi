#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

static void cache_send_udp_command(char *, uint16_t, char *, uint16_t, uint64_t, uint8_t);

void uwsgi_init_cache() {

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

	struct uwsgi_string_list *usl = uwsgi.cache_udp_node;
	while(usl) {
		char *port = strchr(usl->value, ':');
		if (!port) {
			uwsgi_log("[cache-udp-node] invalid udp address: %s\n", usl->value);
			exit(1);
		}
		// no need to zero the memory, socket_to_in_addr will do that
		struct sockaddr_in *sin = uwsgi_malloc(sizeof(struct sockaddr_in));
		usl->custom = socket_to_in_addr(usl->value, port, 0, sin);
		usl->custom_ptr = sin; 
		uwsgi_log("added cache udp node %s\n", usl->value);
		usl = usl->next;
	}

	uwsgi.cache_udp_node_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (uwsgi.cache_udp_node_socket < 0) {
		uwsgi_error("[cache-udp-node] socket()");
		exit(1);
	}
	uwsgi_socket_nb(uwsgi.cache_udp_node_socket);
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
			uwsgi_log("ALARM !!! cache-loop (and potential deadlock) detected slot = %lu prev = %lu next = %lu\n", slot, uci->prev, uci->next);
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
		ushared->cache_hits++;
		return uwsgi.cache + (index * uwsgi.cache_blocksize);
	}

	ushared->cache_miss++;

	return NULL;
}

int uwsgi_cache_del(char *key, uint16_t keylen, uint64_t index, uint16_t flags) {

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

		ushared->cache_items--;
	}

	if (uwsgi.cache_udp_node && ret == 0 && !(flags & UWSGI_CACHE_FLAG_LOCAL)) {
                cache_send_udp_command(key, keylen, NULL, 0, 0, 11);
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
		ushared->cache_full++;
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
		if (expires && !(flags & UWSGI_CACHE_FLAG_ABSEXPIRE))
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

		ushared->cache_items++ ;
	}
	else if (flags & UWSGI_CACHE_FLAG_UPDATE) {
		uci = &uwsgi.cache_items[index];
		if (expires && !(flags & UWSGI_CACHE_FLAG_ABSEXPIRE)) {
			expires += uwsgi_now();
			uci->expires = expires;
		}
		memcpy(uwsgi.cache + (index * uwsgi.cache_blocksize), val, vallen);
		uci->valsize = vallen;
		ret = 0;
	}
	
	if (uwsgi.cache_udp_node && ret == 0 && !(flags & UWSGI_CACHE_FLAG_LOCAL)) {
		cache_send_udp_command(key, keylen, val, vallen, expires, 10);
	}


end:
	return ret;

}


static void cache_send_udp_command(char *key, uint16_t keylen, char *val, uint16_t vallen, uint64_t expires, uint8_t cmd) {

		struct uwsgi_header uh;
		uint8_t u_k[2];
		uint8_t u_v[2];
		uint8_t u_e[2];
		uint16_t vallen16 = vallen;
		struct iovec iov[7];
		struct msghdr mh;

		memset(&mh, 0, sizeof(struct msghdr));
		mh.msg_iov = iov;
		mh.msg_iovlen = 3;

		if (cmd == 10) {
			mh.msg_iovlen = 7;
		}

		iov[0].iov_base = &uh;
		iov[0].iov_len = 4;

		u_k[0] = (uint8_t) (keylen & 0xff);
        	u_k[1] = (uint8_t) ((keylen >> 8) & 0xff);

		iov[1].iov_base = u_k;
		iov[1].iov_len = 2;

		iov[2].iov_base = key;
		iov[2].iov_len = keylen;

		uh.pktsize = 2 + keylen;

		if (cmd == 10) {
			u_v[0] = (uint8_t) (vallen16 & 0xff);
        		u_v[1] = (uint8_t) ((vallen16 >> 8) & 0xff);

			iov[3].iov_base = u_v;
			iov[3].iov_len = 2;

			iov[4].iov_base = val;
			iov[4].iov_len = vallen16;

			char es[sizeof(UMAX64_STR) + 1];
        		uint16_t es_size = uwsgi_long2str2n(expires, es, sizeof(UMAX64_STR));

			u_e[0] = (uint8_t) (es_size & 0xff);
        		u_e[1] = (uint8_t) ((es_size >> 8) & 0xff);

			iov[5].iov_base = u_e;
                	iov[5].iov_len = 2;

                	iov[6].iov_base = es;
                	iov[6].iov_len = es_size;

			uh.pktsize += 2 + vallen16 + 2 + es_size;
		}

		uh.modifier1 = 111;
		uh.modifier2 = cmd;

		struct uwsgi_string_list *usl = uwsgi.cache_udp_node;
		while(usl) {
			mh.msg_name = usl->custom_ptr;
			mh.msg_namelen = usl->custom;
			if (sendmsg(uwsgi.cache_udp_node_socket, &mh, 0) <= 0) {
				uwsgi_error("[cache-udp-node] sendmsg()");
			}
			usl = usl->next;
		}

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

void *cache_udp_server_loop(void *noarg) {
        // block all signals
        sigset_t smask;
        sigfillset(&smask);
        pthread_sigmask(SIG_BLOCK, &smask, NULL);

        int queue = event_queue_init();
        struct uwsgi_string_list *usl = uwsgi.cache_udp_server;
        while(usl) {
                if (strchr(usl->value, ':')) {
                        int fd = bind_to_udp(usl->value, 0, 0);
                        if (fd < 0) {
                                uwsgi_log("[cache-udp-server] cannot bind to %s\n", usl->value);
                                exit(1);
                        }
                        uwsgi_socket_nb(fd);
                        event_queue_add_fd_read(queue, fd);
                        uwsgi_log("*** cache udp server running on %s ***\n", usl->value);
                }
                usl = usl->next;
        }

        // allocate 64k chunk to receive messages
        char *buf = uwsgi_malloc(UMAX16);
	
	for(;;) {
                uint16_t pktsize = 0, ss = 0;
                int interesting_fd = -1;
                int rlen = event_queue_wait(queue, -1, &interesting_fd);
                if (rlen <= 0) continue;
                if (interesting_fd < 0) continue;
                ssize_t len = read(interesting_fd, buf, UMAX16);
                if (len <= 7) {
                        uwsgi_error("[cache-udp-server] read()");
                }
                if (buf[0] != 111) continue;
                memcpy(&pktsize, buf+1, 2);
                if (pktsize != len-4) continue;

                memcpy(&ss, buf + 4, 2);
                if (4+ss > pktsize) continue;
                uint16_t keylen = ss;
                char *key = buf + 6;

                // cache set/update
                if (buf[3] == 10) {
                        if (keylen + 2 + 2 > pktsize) continue;
                        memcpy(&ss, buf + 6 + keylen, 2);
                        if (4+keylen+ss > pktsize) continue;
                        uint16_t vallen = ss;
                        char *val = buf + 8 + keylen;
                        uint64_t expires = 0;
                        if (2 + keylen + 2 + vallen + 2 < pktsize) {
                                memcpy(&ss, buf + 8 + keylen + vallen , 2);
                                if (6+keylen+vallen+ss > pktsize) continue;
                                expires = uwsgi_str_num(buf + 10 + keylen+vallen, ss);
                        }
                        uwsgi_wlock(uwsgi.cache_lock);
                        if (uwsgi_cache_set(key, keylen, val, vallen, expires, UWSGI_CACHE_FLAG_UPDATE|UWSGI_CACHE_FLAG_LOCAL|UWSGI_CACHE_FLAG_ABSEXPIRE)) {
                                uwsgi_log("[cache-udp-server] unable to update cache\n");
                        }
                        uwsgi_rwunlock(uwsgi.cache_lock);
                }
                // cache del
                else if (buf[3] == 11) {
                        uwsgi_wlock(uwsgi.cache_lock);
                        if (uwsgi_cache_del(key, keylen, 0, UWSGI_CACHE_FLAG_LOCAL)) {
                                uwsgi_log("[cache-udp-server] unable to update cache\n");
                        }
                        uwsgi_rwunlock(uwsgi.cache_lock);
                }
        }

        return NULL;
}

void *cache_sweeper_loop(void *noarg) {

        int i;
        // block all signals
        sigset_t smask;
        sigfillset(&smask);
        pthread_sigmask(SIG_BLOCK, &smask, NULL);

        if (!uwsgi.cache_expire_freq)
                uwsgi.cache_expire_freq = 3;

        // remove expired cache items TODO use rb_tree timeouts
        for (;;) {
                sleep(uwsgi.cache_expire_freq);
                uint64_t freed_items = 0;
                // skip the first slot
                for (i = 1; i < (int) uwsgi.cache_max_items; i++) {
                        uwsgi_wlock(uwsgi.cache_lock);
                        if (uwsgi.cache_items[i].expires) {
                                if (uwsgi.cache_items[i].expires < (uint64_t) uwsgi.current_time) {
                                        uwsgi_cache_del(NULL, 0, i, UWSGI_CACHE_FLAG_LOCAL);
                                        freed_items++;
                                }
                        }
                        uwsgi_rwunlock(uwsgi.cache_lock);
                }
                if (uwsgi.cache_report_freed_items && freed_items > 0) {
                        uwsgi_log("freed %llu cache items\n", (unsigned long long) freed_items);
                }
        };

        return NULL;
}

