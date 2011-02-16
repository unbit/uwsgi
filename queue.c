#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

char *uwsgi_queue_get(uint64_t index, uint64_t *size) {

	struct uwsgi_queue_item *uqi;
	char *ptr = (char *) uwsgi.queue;

	if (index >= uwsgi.queue_size) return NULL;

	ptr = ptr + (uwsgi.queue_blocksize*index);

	uqi = (struct uwsgi_queue_item *) ptr;
	
	*size = uqi->size;

	return ptr + sizeof(struct uwsgi_queue_item);
	
}

char *uwsgi_queue_pull(uint64_t *size) {

	struct uwsgi_queue_item *uqi;
	char *ptr = (char *) uwsgi.queue;	

	ptr = ptr + (uwsgi.queue_blocksize*uwsgi.shared->queue_pull_pos);
	uqi = (struct uwsgi_queue_item *) ptr;

	if (!uqi->size) return NULL;

	*size = uqi->size;

	uwsgi.shared->queue_pull_pos++;

	if (uwsgi.shared->queue_pull_pos >= uwsgi.queue_size) uwsgi.shared->queue_pull_pos = 0;
	
	return ptr + sizeof(struct uwsgi_queue_item);

}

int uwsgi_queue_push(char *message, uint64_t size) {

	struct uwsgi_queue_item *uqi;
	char *ptr = (char *) uwsgi.queue;

	if (size > uwsgi.queue_blocksize + sizeof(struct uwsgi_queue_item))
		return 0;

	ptr = ptr + (uwsgi.queue_blocksize*uwsgi.shared->queue_pos);
	uqi = (struct uwsgi_queue_item *) ptr;

	ptr += sizeof(struct uwsgi_queue_item);

	uqi->size = size;
	uqi->ts = time(NULL);
	memcpy(ptr, message, size);

	uwsgi.shared->queue_pos++;
	
	if (uwsgi.shared->queue_pos >= uwsgi.queue_size) uwsgi.shared->queue_pos = 0;

	return 1;
}
