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

void uwsgi_queue_fix() {

        uint64_t i;
	char *value;
	uint64_t size;

        for(i=0;i< uwsgi.queue_size;i++) {
                // valid record ?
		value = uwsgi_queue_get(i, &size);
		if (value && size) {
			uwsgi.shared->queue_pos++;
		}
		else {
			return;
		}
        }
}


char *uwsgi_queue_pop(uint64_t *size) {

        struct uwsgi_queue_item *uqi;
        char *ptr = (char *) uwsgi.queue;

	if (uwsgi.shared->queue_pos > 0) uwsgi.shared->queue_pos--;

        ptr = ptr + (uwsgi.queue_blocksize*uwsgi.shared->queue_pos);
        uqi = (struct uwsgi_queue_item *) ptr;

        if (!uqi->size) return NULL;

        *size = uqi->size;
	// remove item
	uqi->size = 0;

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

	// remove item
	uqi->size = 0;
	
	return ptr + sizeof(struct uwsgi_queue_item);

}

int uwsgi_queue_push(char *message, uint64_t size) {

	struct uwsgi_queue_item *uqi;
	char *ptr = (char *) uwsgi.queue;

	if (size > uwsgi.queue_blocksize + sizeof(struct uwsgi_queue_item))
		return 0;

	if (!size) return 0;

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
