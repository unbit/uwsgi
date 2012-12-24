#include "../uwsgi.h"

/*

	Storage subsystem: filesystem-like abstraction

	struct uwsgi_storage_engine {
		char *name;
		uint16_t name_len;
		int64_t (*get)(char *, uint16_t, char *, uint64_t, uint64_t, uint64_t);
		int64_t (*set)(char *, uint16_t, char *, uint64_t, uint64_t, uint64_t);
	};

	struct uwsgi_storage {
		char *name;
		uint16_t name_len;
		struct uwsgi_storage_engine *engine;
	};



*/

struct uwsgi_storage* uwsgi_storage_by_name(char *name, uint16_t name_len) {
	if (!name_len) {
		name_len = strlen(name);
	}
	struct uwsgi_storage *s = uwsgi.virtualdisks;
	while(s) {
		if (!uwsgi_strncmp(s->name, s->name_len, name, name_len)) {
			return s;
		}
		s = s->next;
	}

	return NULL;
}

int64_t uwsgi_storage_get(struct uwsgi_storage *storage, char *key, uint16_t key_len, char *out_buf, uint64_t pos, uint64_t size, uint64_t flags) {
	if (!storage->get) return -1;
	return storage->get(key, key_len, out_buf, pos, size, flags);
}

int64_t uwsgi_storage_set(struct uwsgi_storage *storage, char *key, uint16_t key_len, char *in_buf, uint64_t pos, uint64_t size, uint64_t flags) {
	if (!storage->set) return -1;
	return storage->set(key, key_len, out_buf, pos, size, flags);
}
