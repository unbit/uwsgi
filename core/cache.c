#include <uwsgi.h>

extern struct uwsgi_server uwsgi;
#define cache_item(x) (struct uwsgi_cache_item *) (((char *)uc->items) + ((sizeof(struct uwsgi_cache_item)+uc->keysize) * x))

// block bitmap manager

/* how the cache bitmap works:

	a bitmap is a shared mempry area allocated when requested by the user with --cache2

	Each block maps to a bit in the bitmap. If the corresponding bit is cleared
	the block is usable otherwise the block scanner will search for the next one.

	Object can be placed only on consecutive blocks, fragmentation is not allowed.

	To increase the scan performance, a 64bit pointer to the last used bit + 1 is hold

	To search for free blocks you run

	uint64_t uwsgi_cache_find_free_block(struct uwsgi_cache *uc, size_t need)

	where need is the size of the object

*/

static uint64_t uwsgi_cache_find_free_blocks(struct uwsgi_cache *uc, uint64_t need) {
	// how many blocks we need ?
	uint64_t needed_blocks = need/uc->blocksize;
	if (need % uc->blocksize > 0) needed_blocks++;

	// which is the first free bit?
	uint64_t bitmap_byte = 0;
	uint8_t bitmap_bit = 0;

	if (uc->blocks_bitmap_pos > 0) {
		bitmap_byte = uc->blocks_bitmap_pos/8;
		bitmap_bit = uc->blocks_bitmap_pos % 8;
	}

	// ok we now have the start position, let's search for contiguous blocks
	uint8_t *bitmap = uc->blocks_bitmap;
	uint64_t base = 0xffffffffffffffffLLU;
	uint8_t base_bit = 0;
	uint64_t j;
	uint64_t found = 0;
	uint64_t need_to_scan = uc->blocks_bitmap_size;
	j = bitmap_byte;
	//uwsgi_log("start scanning %llu bytes starting from %llu need: %llu\n", (unsigned long long) need_to_scan, (unsigned long long) bitmap_byte, (unsigned long long) needed_blocks);
	while(need_to_scan) {
		uint8_t num = bitmap[j];
		uint8_t i;
		uint8_t bit_pos = 0;
		if (j == bitmap_byte) {
			i = 1 << (7-bitmap_bit);
			bit_pos = bitmap_bit;
		}
		else {
			i = 1 <<7;
		}	
		while(i > 0) {
			// used block
                	if (num & i) {
                                found = 0;
                                base = 0xffffffffffffffffLLU;
                                base_bit = 0;
                        }
			// free block
                        else {
                                if (base == 0xffffffffffffffffLLU ) {
                                        base = j;
					base_bit = bit_pos;
                                }
                                found++;
                                if (found == needed_blocks) {
                                        //printf("found %llu consecutive bit starting from byte %llu\n", found, base);
					return ((base*8) + base_bit);
                                }
                        }
                        i >>= 1;
			bit_pos++;
                }
		j++;
		need_to_scan--;
		// check for overlap
		if (j >= need_to_scan) {
			j = 0;
			found = 0;
			base = 0xffffffffffffffffLLU;
			base_bit = 0;
		}
	}

	
	// no more free blocks
	return 0xffffffffffffffffLLU;
}

static uint64_t cache_mark_blocks(struct uwsgi_cache *uc, uint64_t index, uint64_t len) {
	uint64_t needed_blocks = len/uc->blocksize;
	if (len % uc->blocksize > 0) needed_blocks++;

	uint64_t first_byte = index/8;
	uint8_t first_byte_bit = index % 8;
	uint64_t last_byte = (index+needed_blocks)/8;
	uint8_t last_byte_bit = (index+needed_blocks) % 8;

	//uwsgi_log("%llu %u %llu %u\n", first_byte, first_byte_bit, last_byte, last_byte_bit);

	uint8_t mask = 0xff >> first_byte_bit;
	uc->blocks_bitmap[first_byte] |= mask;

	uint64_t needed_bytes = (last_byte - first_byte)+1;

	if (needed_bytes > 1) {
		mask = 0xff << (8 - last_byte_bit);
		uc->blocks_bitmap[last_byte-1] |= mask;
	}

	if (needed_bytes > 2) {
		uint8_t *ptr = &uc->blocks_bitmap[first_byte+1];
		memset(ptr, 0xff, needed_bytes-2);
	}
	return needed_blocks;
}

static void cache_unmark_blocks(struct uwsgi_cache *uc, uint64_t index, uint64_t len) {
	uint64_t needed_blocks = len/uc->blocksize;
        if (len % uc->blocksize > 0) needed_blocks++;

        uint64_t first_byte = index/8;
        uint8_t first_byte_bit = index % 8;
        uint64_t last_byte = (index+needed_blocks)/8;
        uint8_t last_byte_bit = (index+needed_blocks) % 8;

	// here we use XOR (0+0 = 0 | 1+0 = 1 | 0+1 = 1| 1+1 = 0|

        uint8_t mask = 0xff >> first_byte_bit;
        uc->blocks_bitmap[first_byte] ^= mask;

        uint64_t needed_bytes = (last_byte - first_byte)+1;

        if (needed_bytes > 1) {
                mask = 0xff << (8 - last_byte_bit);
                uc->blocks_bitmap[last_byte-1] ^= mask;
        }

        if (needed_bytes > 2) {
                uint8_t *ptr = &uc->blocks_bitmap[first_byte+1];
                memset(ptr, 0, needed_bytes-2);
        }
}

static void cache_send_udp_command(struct uwsgi_cache *, char *, uint16_t, char *, uint16_t, uint64_t, uint8_t);

static void cache_sync_hook(char *k, uint16_t kl, char *v, uint16_t vl, void *data) {
	struct uwsgi_cache *uc = (struct uwsgi_cache *) data;
	if (!uwsgi_strncmp(k, kl, "items", 5)) {
		size_t num = uwsgi_str_num(v, vl);		
		if (num != uc->max_items) {
			uwsgi_log("[cache-sync] invalid cache size, expected %llu received %llu\n", (unsigned long long) uc->max_items, (unsigned long long) num);
			exit(1);
		}
	}
	if (!uwsgi_strncmp(k, kl, "blocksize", 9)) {
		size_t num = uwsgi_str_num(v, vl);		
		if (num != uc->blocksize) {
			uwsgi_log("[cache-sync] invalid cache block size, expected %llu received %llu\n", (unsigned long long) uc->blocksize, (unsigned long long) num);
			exit(1);
		}
	}
}

static void uwsgi_cache_load_files(struct uwsgi_cache *uc) {

	struct uwsgi_string_list *usl = uwsgi.load_file_in_cache;
	while(usl) {
		size_t len = 0;
		char *value = NULL;
		char *key = usl->value;
		uint16_t key_len = usl->len;
		char *space = strchr(usl->value, ' ');
		if (space) {
			// need to skip ?
			if (uwsgi_strncmp(uc->name, uc->name_len, usl->value, space-usl->value)) {
				goto next;
			}
			key = space+1;
			key_len = usl->len - ((space-usl->value)+1);
		}
		value = uwsgi_open_and_read(key, &len, 0, NULL);
		if (value) {
			uwsgi_wlock(uc->lock);
			if (!uwsgi_cache_set2(uc, key, key_len, value, len, 0, 0)) {
				uwsgi_log("[cache] stored \"%.*s\" in \"%s\"\n", key_len, key, uc->name);
			}		
			uwsgi_rwunlock(uc->lock);
			free(value);
		}
next:
		usl = usl->next;
	}
}



void uwsgi_cache_init(struct uwsgi_cache *uc) {

	uc->hashtable = uwsgi_calloc_shared(sizeof(uint64_t) * uc->hashsize);
	uc->unused_blocks_stack = uwsgi_calloc_shared(sizeof(uint64_t) * uc->blocks);
	// the first cache item is always zero
	uc->first_available_block = 1;
	uc->unused_blocks_stack_ptr = 0;
	uc->filesize = ( (sizeof(struct uwsgi_cache_item)+uc->keysize) * uc->max_items) + (uc->blocksize * uc->blocks);

	if (uc->use_blocks_bitmap) {
		uc->blocks_bitmap_size = uc->blocks/8;
		if (uc->blocks % 8 > 0) uc->blocks_bitmap_size++;
		uc->blocks_bitmap = uwsgi_calloc_shared(uc->blocks_bitmap_size);
	}

	//uwsgi.cache_items = (struct uwsgi_cache_item *) mmap(NULL, sizeof(struct uwsgi_cache_item) * uwsgi.cache_max_items, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
	if (uc->store) {
		int cache_fd;
		struct stat cst;

		if (stat(uc->store, &cst)) {
			uwsgi_log("creating a new cache store file: %s\n", uc->store);
			cache_fd = open(uc->store, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
			if (cache_fd >= 0) {
				// fill the caching store
				if (ftruncate(cache_fd, uc->filesize)) {
					uwsgi_log("ftruncate()");
					exit(1);
				}
			}
		}
		else {
			if ((size_t) cst.st_size != uc->filesize || !S_ISREG(cst.st_mode)) {
				uwsgi_log("invalid cache store file. Please remove it or fix cache blocksize/items to match its size\n");
				exit(1);
			}
			cache_fd = open(uc->store, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
			uwsgi_log("recovered cache from backing store file: %s\n", uc->store);
		}

		if (cache_fd < 0) {
			uwsgi_error_open(uc->store);
			exit(1);
		}
		uc->items = (struct uwsgi_cache_item *) mmap(NULL, uc->filesize, PROT_READ | PROT_WRITE, MAP_SHARED, cache_fd, 0);
		if (!uc->items) {
			uwsgi_error("uwsgi_cache_init()/mmap() [with store]");
			exit(1);
		}

		uwsgi_cache_fix(uc);
		close(cache_fd);
	}
	else {
		uc->items = (struct uwsgi_cache_item *) mmap(NULL, uc->filesize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
		if (!uc->items) {
			uwsgi_error("uwsgi_cache_init()/mmap()");
			exit(1);
		}
		uint64_t i;
		for (i = 0; i < uc->max_items; i++) {
			// here we only need to clear the item header
			memset(cache_item(i), 0, sizeof(struct uwsgi_cache_item));
		}
	}

	uc->data = ((char *)uc->items) + ((sizeof(struct uwsgi_cache_item)+uc->keysize) * uc->max_items);

	if (uc->name) {
		// can't free that until shutdown
		char *lock_name = uwsgi_concat2("cache_", uc->name);
		uc->lock = uwsgi_rwlock_init(lock_name);
	}
	else {
		uc->lock = uwsgi_rwlock_init("cache");
	}

	uwsgi_log("*** Cache \"%s\" initialized: %lluMB (key: %llu bytes, keys: %llu bytes, data: %llu bytes, bitmap: %llu bytes) preallocated ***\n",
			uc->name,
			(unsigned long long) uc->filesize / (1024 * 1024),
			(unsigned long long) sizeof(struct uwsgi_cache_item)+uc->keysize,
			(unsigned long long) ((sizeof(struct uwsgi_cache_item)+uc->keysize) * uc->max_items), (unsigned long long) (uc->blocksize * uc->max_items),
			(unsigned long long) uc->blocks_bitmap_size);


	struct uwsgi_string_list *usl = uc->nodes;
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
		uwsgi_log("added udp node %s for cache \"%s\"\n", usl->value, uc->name);
		usl = usl->next;
	}

	uc->udp_node_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (uc->udp_node_socket < 0) {
		uwsgi_error("[cache-udp-node] socket()");
		exit(1);
	}
	uwsgi_socket_nb(uc->udp_node_socket);

	usl = uc->sync_nodes;
	while(usl) {
		uwsgi_log("[cache-sync] getting cache dump from %s ...\n", usl->value);
		int fd = uwsgi_connect(usl->value, 0, 0);
		if (fd < 0) {
			uwsgi_log("[cache-sync] unable to connect to the cache server\n");
			goto next;
		}
		struct uwsgi_header cuh;
		cuh.modifier1 = 111;
		cuh.modifier2 = 6;
		cuh.pktsize = 0;
		if (write(fd, &cuh, 4) != 4) {
			uwsgi_log("[cache-sync] unable to write to the cache server\n");
			goto next;
		}

		int ret = uwsgi_read_uh(fd, &cuh, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
		if (ret) {
			uwsgi_log("[cache-sync] unable to read from the cache server\n");
			goto next;
		}

		if (cuh.modifier1 != 111 || cuh.modifier2 != 7) {
			uwsgi_log("[cache-sync] invalid uwsgi packet received from the cache server\n");
			goto next;
		}
	
		char *dump_buf = uwsgi_malloc(cuh.pktsize);
		ret = uwsgi_read_nb(fd, dump_buf, cuh.pktsize, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
		if (ret) {
                        uwsgi_log("[cache-sync] unable to read from the cache server\n");
			goto next;
                }

		uwsgi_hooked_parse(dump_buf, cuh.pktsize, cache_sync_hook, NULL);

		ret = uwsgi_read_nb(fd, (char *) uc->items, uc->filesize, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
		if (ret) {
                        uwsgi_log("[cache-sync] unable to read from the cache server\n");
			goto next;
                }

		// reset the hashtable
		memset(uc->hashtable, 0, sizeof(uint64_t) * UMAX16);
		// re-fill the hashtable
                uwsgi_cache_fix(uc);
		break;
next:
		if (!usl->next) {
			exit(1);
		}
		uwsgi_log("[cache-sync] trying with the next sync node...\n");
		usl = usl->next;
	}

	uwsgi_cache_load_files(uc);
}

static uint64_t uwsgi_cache_get_index(struct uwsgi_cache *uc, char *key, uint16_t keylen) {

	uint32_t hash = uc->hash->func(key, keylen);
	uint32_t hash_key = hash % uc->hashsize;

	uint64_t slot = uc->hashtable[hash_key];

	// optimization
	if (slot == 0) return 0;

	//uwsgi_log("hash_key = %lu slot = %llu\n", hash_key, (unsigned long long) slot);

	struct uwsgi_cache_item *uci = cache_item(slot);
	uint64_t rounds = 0;

	// first round
	if (uci->hash % uc->hashsize != hash_key)
		return 0;
	if (uci->hash != hash)
		goto cycle;
	if (uci->keysize != keylen)
		goto cycle;
	if (memcmp(uci->key, key, keylen))
		goto cycle;

	return slot;

cycle:
	while (uci->next) {
		slot = uci->next;
		uci = cache_item(slot);
		rounds++;
		if (rounds > uc->max_items) {
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
		if (uci->hash != hash)
			continue;
		if (uci->keysize != keylen)
			continue;
		if (!memcmp(uci->key, key, keylen))
			return slot;
	}

	return 0;
}

uint32_t uwsgi_cache_exists2(struct uwsgi_cache *uc, char *key, uint16_t keylen) {

	return uwsgi_cache_get_index(uc, key, keylen);
}

char *uwsgi_cache_get2(struct uwsgi_cache *uc, char *key, uint16_t keylen, uint64_t * valsize) {

	uint64_t index = uwsgi_cache_get_index(uc, key, keylen);

	if (index) {
		struct uwsgi_cache_item *uci = cache_item(index);
		if (uci->flags & UWSGI_CACHE_FLAG_UNGETTABLE)
			return NULL;
		*valsize = uci->valsize;
		uci->hits++;
		uc->hits++;
		return uc->data + (uci->first_block * uc->blocksize);
	}

	uc->miss++;

	return NULL;
}

int uwsgi_cache_del2(struct uwsgi_cache *uc, char *key, uint16_t keylen, uint64_t index, uint16_t flags) {

	struct uwsgi_cache_item *uci;
	int ret = -1;

	if (!index)
		index = uwsgi_cache_get_index(uc, key, keylen);

	if (index) {
		uci = cache_item(index);
		uci->keysize = 0;
		uci->valsize = 0;
		uc->unused_blocks_stack_ptr++;
		uc->unused_blocks_stack[uc->unused_blocks_stack_ptr] = index;
		// unmark blocks
		if (uc->blocks_bitmap) {
			cache_unmark_blocks(uc, uci->first_block, uci->valsize);
		}
		ret = 0;
		// relink collisioned entry
		if (uci->prev) {
			struct uwsgi_cache_item *ucii = cache_item(uci->prev);
			ucii->next = uci->next;
		}
		else {
			// set next as the new entry point (could be 0)
			uc->hashtable[uci->hash % uc->hashsize] = uci->next;
		}

		if (uci->next) {
			struct uwsgi_cache_item *ucii = cache_item(uci->next);
			ucii->prev = uci->prev;
		}

		if (!uci->prev && !uci->next) {
			// reset hashtable entry
			//uwsgi_log("!!! resetted hashtable entry !!!\n");
			uc->hashtable[uci->hash % uc->hashsize] = 0;
		}
		uci->hash = 0;
		uci->prev = 0;
		uci->next = 0;
		uci->expires = 0;

		uc->n_items--;
	}

	if (uc->nodes && ret == 0 && !(flags & UWSGI_CACHE_FLAG_LOCAL)) {
                cache_send_udp_command(uc, key, keylen, NULL, 0, 0, 11);
        }

	return ret;
}

void uwsgi_cache_fix(struct uwsgi_cache *uc) {

	uint64_t i;
	unsigned long long restored = 0;

	for (i = 0; i < uc->max_items; i++) {
		// valid record ?
		struct uwsgi_cache_item *uci = cache_item(i);
		if (uci->keysize) {
			if (!uci->prev) {
				// put value in hash_table
				uc->hashtable[uci->hash % uc->hashsize] = i;
				restored++;
			}
		}
		else {
			// put this record in unused stack
			uc->first_available_block = i;
			uc->unused_blocks_stack_ptr++;
			uc->unused_blocks_stack[uc->unused_blocks_stack_ptr] = i;
		}
	}

	uwsgi_log("[uwsgi-cache] restored %llu items\n", restored);
}

int uwsgi_cache_set2(struct uwsgi_cache *uc, char *key, uint16_t keylen, char *val, uint64_t vallen, uint64_t expires, uint64_t flags) {

	uint64_t index = 0, last_index = 0;

	struct uwsgi_cache_item *uci, *ucii;

	// used to reset key allocation in bitmap mode
	uint8_t rollback_mode = 0;

	int ret = -1;

	if (!keylen || !vallen)
		return -1;

	if (keylen > uc->keysize)
		return -1;

	if (!uc->blocks_bitmap && vallen > uc->blocksize) return -1;

	//uwsgi_log("putting cache data in key %.*s %d\n", keylen, key, vallen);
	index = uwsgi_cache_get_index(uc, key, keylen);
	if (!index) {
		if (uc->first_available_block >= uc->max_items && !uc->unused_blocks_stack_ptr) {
			uwsgi_log("*** DANGER cache \"%s\" is FULL !!! ***\n", uc->name);
			uc->full++;
			goto end;
		}
		if (uc->unused_blocks_stack_ptr) {
			//uwsgi_log("!!! REUSING CACHE SLOT !!! (faci: %llu)\n", (unsigned long long) uwsgi.shared->cache_first_available_block);
			index = uc->unused_blocks_stack[uc->unused_blocks_stack_ptr];
			uc->unused_blocks_stack_ptr--;
		}
		else {
			rollback_mode = 1;
			index = uc->first_available_block;
			if (uc->first_available_block < uc->max_items) {
				rollback_mode = 2;
				uc->first_available_block++;
			}
		}

		uci = cache_item(index);
		if (!uc->blocks_bitmap) {
			uci->first_block = index;
		}
		else {
			uci->first_block = uwsgi_cache_find_free_blocks(uc, vallen);
			//uwsgi_log("first block = %llu\n", uci->first_block);
			if (uci->first_block == 0xffffffffffffffffLLU) {
				uwsgi_log("*** DANGER cache \"%s\" is FULL !!! ***\n", uc->name);
                                uc->full++;
				if (rollback_mode == 0) {
					uc->unused_blocks_stack_ptr++;
				}
				else if (rollback_mode == 2) {
					uc->first_available_block--;	
				}
                                goto end;
			}
			// mark used blocks;
			uint64_t needed_blocks = cache_mark_blocks(uc, uci->first_block, vallen);	
			// optimize teh scan
			if (uc->blocks_bitmap_pos + (needed_blocks+1) > uc->blocks) {
                        	uc->blocks_bitmap_pos = 0;
                        }
                        else {
                        	uc->blocks_bitmap_pos = uci->first_block + needed_blocks + 1;
                        }
		}
		if (expires && !(flags & UWSGI_CACHE_FLAG_ABSEXPIRE))
			expires += uwsgi_now();
		uci->expires = expires;
		uci->hash = uc->hash->func(key, keylen);
		uci->hits = 0;
		uci->flags = flags;
		memcpy(uci->key, key, keylen);
		memcpy(((char *) uc->data) + (uci->first_block * uc->blocksize), val, vallen);

		// set this as late as possibile (to reduce races risk)

		uci->valsize = vallen;
		uci->keysize = keylen;
		ret = 0;
		// now put the value in the hashtable
		uint32_t slot = uci->hash % uc->hashsize;
		// reset values
		uci->prev = 0;
		uci->next = 0;

		last_index = uc->hashtable[slot];
		if (last_index == 0) {
			uc->hashtable[slot] = index;
		}
		else {
			// append to first available next
			ucii = cache_item(last_index);
			while (ucii->next) {
				last_index = ucii->next;
				ucii = cache_item(last_index);
			}
			ucii->next = index;
			uci->prev = last_index;
		}

		uc->n_items++ ;
	}
	else if (flags & UWSGI_CACHE_FLAG_UPDATE) {
		uci = cache_item(index);
		if (expires && !(flags & UWSGI_CACHE_FLAG_ABSEXPIRE)) {
			expires += uwsgi_now();
			uci->expires = expires;
		}
		if (uc->blocks_bitmap) {
			// we have a special case here, as we need to find a new series of free blocks
			uint64_t old_first_block = uci->first_block;
			uci->first_block = uwsgi_cache_find_free_blocks(uc, vallen);
                        if (uci->first_block == 0xffffffffffffffffLLU) {
                                uwsgi_log("*** DANGER cache \"%s\" is FULL !!! ***\n", uc->name);
                                uc->full++;
				uci->first_block = old_first_block;
                                goto end;
                        }
                        // mark used blocks;
                        uint64_t needed_blocks = cache_mark_blocks(uc, uci->first_block, vallen);
                        // optimize teh scan
                        if (uc->blocks_bitmap_pos + (needed_blocks+1) > uc->blocks) {
                                uc->blocks_bitmap_pos = 0;
                        }
                        else {
                                uc->blocks_bitmap_pos = uci->first_block + needed_blocks + 1;
                        }
			// unmark the old blocks
			cache_unmark_blocks(uc, uci->first_block, uci->valsize);
		}
		memcpy(uc->data + (uci->first_block * uc->blocksize), val, vallen);
		uci->valsize = vallen;
		ret = 0;
	}
	
	if (uc->nodes && ret == 0 && !(flags & UWSGI_CACHE_FLAG_LOCAL)) {
		cache_send_udp_command(uc, key, keylen, val, vallen, expires, 10);
	}


end:
	return ret;

}


static void cache_send_udp_command(struct uwsgi_cache *uc, char *key, uint16_t keylen, char *val, uint16_t vallen, uint64_t expires, uint8_t cmd) {

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

		struct uwsgi_string_list *usl = uc->nodes;
		while(usl) {
			mh.msg_name = usl->custom_ptr;
			mh.msg_namelen = usl->custom;
			if (sendmsg(uc->udp_node_socket, &mh, 0) <= 0) {
				uwsgi_error("[cache-udp-node] sendmsg()");
			}
			usl = usl->next;
		}

}

/* THIS PART IS HEAVILY OPTIMIZED: PERFORMANCE NOT ELEGANCE !!! */

void *cache_thread_loop(void *ucache) {

	struct uwsgi_cache *uc = (struct uwsgi_cache *) ucache;
	int fd = uc->thread_server_fd;
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

		uwsgi_rlock(uc->lock);
		val = uwsgi_cache_get2(uc, key, keylen, &vallen);
		if (val && vallen > 0) {
			if (write(ctl_poll.fd, val, vallen) != (int64_t) vallen) {
				uwsgi_error("cache write()");
			}
		}
		uwsgi_rwunlock(uc->lock);

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

void uwsgi_cache_wlock(struct uwsgi_cache *uc) {
	uwsgi.lock_ops.wlock(uc->lock);
}

void uwsgi_cache_rlock(struct uwsgi_cache *uc) {
	uwsgi.lock_ops.rlock(uc->lock);
}

void uwsgi_cache_rwunlock(struct uwsgi_cache *uc) {
	uwsgi.lock_ops.rwunlock(uc->lock);
}

void *cache_udp_server_loop(void *ucache) {
        // block all signals
        sigset_t smask;
        sigfillset(&smask);
        pthread_sigmask(SIG_BLOCK, &smask, NULL);

	struct uwsgi_cache *uc = (struct uwsgi_cache *) ucache;

        int queue = event_queue_init();
        struct uwsgi_string_list *usl = uc->udp_servers;
        while(usl) {
                if (strchr(usl->value, ':')) {
                        int fd = bind_to_udp(usl->value, 0, 0);
                        if (fd < 0) {
                                uwsgi_log("[cache-udp-server] cannot bind to %s\n", usl->value);
                                exit(1);
                        }
                        uwsgi_socket_nb(fd);
                        event_queue_add_fd_read(queue, fd);
                        uwsgi_log("*** udp server for cache \"%s\" running on %s ***\n", uc->name, usl->value);
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
                        uwsgi_wlock(uc->lock);
                        if (uwsgi_cache_set(key, keylen, val, vallen, expires, UWSGI_CACHE_FLAG_UPDATE|UWSGI_CACHE_FLAG_LOCAL|UWSGI_CACHE_FLAG_ABSEXPIRE)) {
                                uwsgi_log("[cache-udp-server] unable to update cache\n");
                        }
                        uwsgi_rwunlock(uc->lock);
                }
                // cache del
                else if (buf[3] == 11) {
                        uwsgi_wlock(uc->lock);
                        if (uwsgi_cache_del(key, keylen, 0, UWSGI_CACHE_FLAG_LOCAL)) {
                                uwsgi_log("[cache-udp-server] unable to update cache\n");
                        }
                        uwsgi_rwunlock(uc->lock);
                }
        }

        return NULL;
}

static void *cache_sweeper_loop(void *ucache) {

        uint64_t i;
        // block all signals
        sigset_t smask;
        sigfillset(&smask);
        pthread_sigmask(SIG_BLOCK, &smask, NULL);

	struct uwsgi_cache *uc = (struct uwsgi_cache *) ucache;

        if (!uwsgi.cache_expire_freq)
                uwsgi.cache_expire_freq = 3;

        // remove expired cache items TODO use rb_tree timeouts
        for (;;) {
		sleep(uwsgi.cache_expire_freq);
                uint64_t freed_items = 0;
                // skip the first slot
                for (i = 1; i < uc->max_items; i++) {
                        uwsgi_wlock(uc->lock);
			struct uwsgi_cache_item *uci = cache_item(i);
                        if (uci->expires) {
                                if (uci->expires < (uint64_t) uwsgi.current_time) {
                                        uwsgi_cache_del2(uc, NULL, 0, i, UWSGI_CACHE_FLAG_LOCAL);
                                        freed_items++;
                                }
                        }
                        uwsgi_rwunlock(uc->lock);
                }
                if (uwsgi.cache_report_freed_items && freed_items > 0) {
                        uwsgi_log("freed %llu items for cache \"%s\"\n", (unsigned long long) freed_items, uc->name);
                }
        };

        return NULL;
}

void uwsgi_cache_sync_all() {

	struct uwsgi_cache *uc = uwsgi.caches;
	while(uc) {
		if (uc->store && (uwsgi.master_cycles == 0 || (uc->store_sync > 0 && (uwsgi.master_cycles % uc->store_sync) == 0))) {
                	if (msync(uc->items, uc->filesize, MS_ASYNC)) {
                        	uwsgi_error("uwsgi_cache_sync_all()/msync()");
                        }
		}
		uc = uc->next;
	}
}

void uwsgi_cache_start_sweepers() {
	struct uwsgi_cache *uc = uwsgi.caches;
	while(uc) {
		pthread_t cache_sweeper;
		if (!uwsgi.cache_no_expire && !uc->no_expire) {
                	if (pthread_create(&cache_sweeper, NULL, cache_sweeper_loop, (void *) uc)) {
                        	uwsgi_error("pthread_create()");
                        	uwsgi_log("unable to run the sweeper for cache \"%s\" !!!\n", uc->name);
			}
                	else {
                        	uwsgi_log("sweeper thread enabled for cache \"%s\"\n", uc->name);
                	}
		}
		uc = uc->next;
        }
}

void uwsgi_cache_start_sync_servers() {

	struct uwsgi_cache *uc = uwsgi.caches;
	while(uc) {
		if (!uc->udp_servers) goto next;		
		pthread_t cache_udp_server;
                if (pthread_create(&cache_udp_server, NULL, cache_udp_server_loop, (void *) uc)) {
                        uwsgi_error("pthread_create()");
                        uwsgi_log("unable to run the cache udp server !!!\n");
                }
                else {
                        uwsgi_log("udp server thread enabled for cache \"%s\"\n", uc->name);
                }
next:
		uc = uc->next;
        }
}

struct uwsgi_cache *uwsgi_cache_create(char *arg) {
	struct uwsgi_cache *old_uc = NULL, *uc = uwsgi.caches;
	while(uc) {
		old_uc = uc;
		uc = uc->next;
	}

	uc = uwsgi_calloc_shared(sizeof(struct uwsgi_cache));
	if (old_uc) {
		old_uc->next = uc;
	}
	else {
		uwsgi.caches = uc;
	}

	// default (old-stye) cache ?
	if (!arg) {
		uc->name = "default";
		uc->name_len = strlen(uc->name);
		uc->blocksize = uwsgi.cache_blocksize;
		if (!uc->blocksize) uc->blocksize = UMAX16;
		uc->max_items = uwsgi.cache_max_items;
		uc->blocks = uwsgi.cache_max_items;
		uc->keysize = 2048;
		uc->hashsize = UMAX16;
		uc->hash = uwsgi_hash_algo_get("djb33x");
		uc->store = uwsgi.cache_store;
		uc->nodes = uwsgi.cache_udp_node;
		uc->udp_servers = uwsgi.cache_udp_server;
		uc->store_sync = uwsgi.cache_store_sync;

		if (uwsgi.cache_sync) {
			uwsgi_string_new_list(&uc->sync_nodes, uwsgi.cache_sync);
		}
	}
	else {
		char *c_name = NULL;
		char *c_max_items = NULL;
		char *c_blocksize = NULL;
		char *c_blocks = NULL;
		char *c_hash = NULL;
		char *c_hashsize = NULL;
		char *c_keysize = NULL;
		char *c_store = NULL;
		char *c_store_sync = NULL;
		char *c_nodes = NULL;
		char *c_sync = NULL;
		char *c_udp_servers = NULL;
		char *c_bitmap = NULL;

		if (uwsgi_kvlist_parse(arg, strlen(arg), ',', '=',
                        "name", &c_name,
                        "max_items", &c_max_items,
                        "maxitems", &c_max_items,
                        "items", &c_max_items,
                        "blocksize", &c_blocksize,
                        "blocks", &c_blocks,
                        "hash", &c_hash,
                        "hashsize", &c_hashsize,
                        "hash_size", &c_hashsize,
                        "keysize", &c_keysize,
                        "key_size", &c_keysize,
                        "store", &c_store,
                        "store_sync", &c_store_sync,
                        "storesync", &c_store_sync,
                        "node", &c_nodes,
                        "nodes", &c_nodes,
                        "sync", &c_sync,
                        "udp", &c_udp_servers,
                        "udp_servers", &c_udp_servers,
                        "udp_server", &c_udp_servers,
                        "udpservers", &c_udp_servers,
                        "udpserver", &c_udp_servers,
                        "bitmap", &c_bitmap,
                	NULL)) {
			uwsgi_log("unable to parse cache definition\n");
			exit(1);
        	}
		if (!c_name) {
			uwsgi_log("you have to specify a cache name\n");
			exit(1);
		}
		if (!c_max_items) {
			uwsgi_log("you have to specify the maximum number of cache items\n");
			exit(1);
		}

		uc->name = c_name;
		uc->name_len = strlen(c_name);
		uc->max_items = uwsgi_n64(c_max_items);
		if (!uc->max_items) {
			uwsgi_log("you have to specify the maximum number of cache items\n");
			exit(1);
		}
		
		// defaults
		uc->blocks = uc->max_items;
		uc->blocksize = UMAX16;
		uc->keysize = 2048;
		uc->hashsize = UMAX16;
		uc->hash = uwsgi_hash_algo_get("djb33x");

		// customize
		if (c_blocksize) uc->blocksize = uwsgi_n64(c_blocksize);
		if (!uc->blocksize) { uwsgi_log("invalid cache blocksize for \"%s\"\n", uc->name); exit(1); }
		if (c_blocks) uc->blocks = uwsgi_n64(c_blocks);
		if (!uc->blocks) { uwsgi_log("invalid cache blocks for \"%s\"\n", uc->name); exit(1); }
		if (c_hash) uc->hash = uwsgi_hash_algo_get(c_hash);
		if (!uc->hash) { uwsgi_log("invalid cache hash for \"%s\"\n", uc->name); exit(1); }
		if (c_hashsize) uc->hashsize = uwsgi_n64(c_hashsize);
		if (!uc->hashsize) { uwsgi_log("invalid cache hashsize for \"%s\"\n", uc->name); exit(1); }
		if (c_keysize) uc->keysize = uwsgi_n64(c_keysize);
		if (!uc->keysize) { uwsgi_log("invalid cache keysize for \"%s\"\n", uc->name); exit(1); }
		if (c_bitmap) uc->use_blocks_bitmap = 1; 

		uc->store_sync = uwsgi.cache_store_sync;
		if (c_store_sync) { uc->store_sync = uwsgi_n64(c_store_sync); }

		if (uc->blocks < uc->max_items) {
			uwsgi_log("invalid number of cache blocks for \"%s\", must be higher than max_items (%llu)\n", uc->name, uc->max_items);
			exit(1);
		}

		uc->store = c_store;

		if (c_nodes) {
			char *p = strtok(c_nodes, ";");
			while(p) {
				uwsgi_string_new_list(&uc->nodes, p);
				p = strtok(NULL, ";");
			}
		}

		if (c_sync) {
			char *p = strtok(c_sync, ";");
                        while(p) {
                                uwsgi_string_new_list(&uc->sync_nodes, p);
                                p = strtok(NULL, ";");
                        }
		}

		if (c_udp_servers) {
                        char *p = strtok(c_udp_servers, ";");
                        while(p) {
                                uwsgi_string_new_list(&uc->udp_servers, p);
                                p = strtok(NULL, ";");
                        }
                }
		
	}

	uwsgi_cache_init(uc);
	return uc;
}

struct uwsgi_cache *uwsgi_cache_by_name(char *name) {
	struct uwsgi_cache *uc = uwsgi.caches;
	if (!name || *name == 0) {
		return uwsgi.caches;
	}
	while(uc) {
		if (uc->name && !strcmp(uc->name, name)) {
			return uc;
		}
		uc = uc->next;
	}
	return NULL;
}

void uwsgi_cache_create_all() {

	if (uwsgi.cache_setup) return;

	// register embedded hash algorithms
        uwsgi_hash_algo_register_all();

        // setup default cache
        if (uwsgi.cache_max_items > 0) {
                uwsgi_cache_create(NULL);
        }

        // setup new generation caches
        struct uwsgi_string_list *usl = uwsgi.cache2;
        while(usl) {
                uwsgi_cache_create(usl->value);
                usl = usl->next;
        }

        // create the cache server
        if (uwsgi.master_process && uwsgi.cache_server) {
                uwsgi.cache_server_fd = uwsgi_cache_server(uwsgi.cache_server, uwsgi.cache_server_threads);
        }

	uwsgi.cache_setup = 1;
}

char *uwsgi_cache_safe_get2(struct uwsgi_cache *uc, char *key, uint16_t keylen, uint64_t * valsize) {
	uwsgi_rlock(uc->lock);
	char *value = uwsgi_cache_get2(uc, key, keylen, valsize);
	if (value && *valsize) {
		char *buf = uwsgi_malloc(*valsize);
		memcpy(buf, value, *valsize);
		uwsgi_rwunlock(uc->lock);
		return buf;
	}
	uwsgi_rwunlock(uc->lock);
	return NULL;
	
}

/*
 * uWSGI cache magic functions. They can be used by plugin to easily access local and remote caches
 *
 * they generate (when needed) a new memory buffer. Locking is automatically managed
 *
 * You have to free the returned memory !!!
 *
 */
char *uwsgi_cache_magic_get(char *key, uint16_t keylen, uint64_t *vallen, char *cachename) {
	struct uwsgi_cache *uc = NULL;
	char *cache_server = NULL;
	if (cachename) {
		char *at = strchr(cachename, '@');
		if (!at) {
			uc = uwsgi_cache_by_name(cachename);
		}
		else {
		}
	}
	// use default (local) cache
	else {
		uc = uwsgi.caches;
	}

	// we have a local cache !!!
	if (uc) {
		uwsgi_rlock(uc->lock);
		char *value = uwsgi_cache_get2(uc, key, keylen, vallen);
		if (!value) {
			uwsgi_rwunlock(uc->lock);
			return NULL;
		}
		char *buf = uwsgi_malloc(*vallen);
		memcpy(buf, value, *vallen);
		uwsgi_rwunlock(uc->lock);
		return buf;
	}

	// we have a remote one
	if (cache_server) {
	}

	return NULL;
}

