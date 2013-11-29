#include <uwsgi.h>

extern struct uwsgi_server uwsgi;

/*

This is an high-performance memory area shared by all workers/cores/threads

Contrary to the caching subsystem it is 1-copy (caching for non-c apps is 2-copy)

Languages not allowing that kind of access should emulate it calling uwsgi_malloc and then copying it back to
the language object.

The memory areas could be monitored for changes (read: cores can be suspended while waiting for values)

You can configure multiple areas specifying multiple --sharedarea options

This is a very low-level api, try to use it to build higher-level primitives or rely on the caching subsystem

*/

struct uwsgi_sharedarea *uwsgi_sharedarea_get_by_id(int id, uint64_t pos) {
	if (id > uwsgi.sharedareas_cnt-1) return NULL;
	struct uwsgi_sharedarea *sa = uwsgi.sharedareas[id];
	if (pos > sa->max_pos) return NULL;
	return sa;
}

int uwsgi_sharedarea_read(int id, uint64_t pos, char *blob, uint64_t len) {
	struct uwsgi_sharedarea *sa = uwsgi_sharedarea_get_by_id(id, pos);
        if (!sa) return -1;
        if (pos + len > sa->max_pos + 1) return -1;
        uwsgi_rlock(sa->lock);
        memcpy(blob, sa->area + pos, len);
        sa->hits++;
        uwsgi_rwunlock(sa->lock);
        return 0;
} 

int uwsgi_sharedarea_write(int id, uint64_t pos, char *blob, uint64_t len) {
	struct uwsgi_sharedarea *sa = uwsgi_sharedarea_get_by_id(id, pos);
	if (!sa) return -1;
	if (pos + len > sa->max_pos + 1) return -1;
	uwsgi_wlock(sa->lock);
	memcpy(sa->area + pos, blob, len);	
	sa->updates++;
	uwsgi_rwunlock(sa->lock);
	return 0;
} 

int uwsgi_sharedarea_read64(int id, uint64_t pos, int64_t *value) {
	return -1;
}

int uwsgi_sharedarea_write64(int id, uint64_t pos, int64_t value) {
	return -1;
}

/*
	returns:
		0 -> on updates
		-1 -> on error
		-2 -> on timeout
*/
int uwsgi_sharedarea_wait(int id, int freq, int timeout) {
	int waiting = 0;
	struct uwsgi_sharedarea *sa = uwsgi_sharedarea_get_by_id(id, 0);
	if (!sa) return -1;
	uwsgi_rlock(sa->lock);
	uint64_t updates = sa->updates;
	uwsgi_rwunlock(sa->lock);
	while(timeout == 0 || (timeout > 0 && (waiting/1000) >= timeout)) {
		uwsgi.wait_milliseconds_hook(freq);
		waiting += freq;
		// lock sa
		uwsgi_rlock(sa->lock);
		if (sa->updates != updates) {
			uwsgi_rwunlock(sa->lock);
			return 0;
		}
		// unlock sa
		uwsgi_rwunlock(sa->lock);
	}
	return -2;
}

struct uwsgi_sharedarea *uwsgi_sharedarea_init(int id, int pages) {
	uwsgi.sharedareas[id] = uwsgi_calloc_shared(uwsgi.page_size * (pages + 1));
	uwsgi.sharedareas[id]->area = ((char *) uwsgi.sharedareas[id]) + uwsgi.page_size;
	uwsgi.sharedareas[id]->id = id;
	uwsgi.sharedareas[id]->fd = -1;
	uwsgi.sharedareas[id]->pages = pages;
	uwsgi.sharedareas[id]->max_pos = (uwsgi.page_size * pages) -1;
	char *id_str = uwsgi_num2str(id);
	uwsgi.sharedareas[id]->lock = uwsgi_rwlock_init(uwsgi_concat2("sharedarea", id_str));
	free(id_str);
	return uwsgi.sharedareas[id];
}

struct uwsgi_sharedarea *uwsgi_sharedarea_init_keyval(int id, char *arg) {
	char *s_pages = NULL;
	char *s_file = NULL;
	char *s_fd = NULL;
	char *s_size = NULL;
	if (uwsgi_kvlist_parse(arg, strlen(arg), ',', '=',
		"pages", &s_pages,
		"file", &s_file,
		"fd", &s_fd,
		"size", &s_size,
		NULL)) {
	}

	return NULL;
}


void uwsgi_sharedareas_init() {
	struct uwsgi_string_list *usl = NULL;
	uwsgi_foreach(usl, uwsgi.sharedareas_list) {
		uwsgi.sharedareas_cnt++;
	}
	uwsgi.sharedareas = uwsgi_calloc(sizeof(struct uwsgi_sharedarea *) * uwsgi.sharedareas_cnt);
	int id = 0;
	uwsgi_foreach(usl, uwsgi.sharedareas_list) {
		char *is_keyval = strchr(usl->value, '=');
		struct uwsgi_sharedarea *sa = NULL;
		if (!is_keyval) {
			sa = uwsgi_sharedarea_init(id, atoi(usl->value));
		}
		else {
			sa = uwsgi_sharedarea_init_keyval(id, usl->value);
		}
		if (sa) {
			uwsgi_log("sharedaread % initialized at %p\n", id, sa);
		}
		id++;
	}
}
