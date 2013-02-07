#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

int uwsgi_register_rpc(char *name, uint8_t modifier1, uint8_t args, void *func) {

	struct uwsgi_rpc *urpc;
	int ret = -1;

	if (uwsgi.mywid != 0) {
		uwsgi_log("you can register RPC functions only in the master\n");
		return -1;
	}

	uwsgi_lock(uwsgi.rpc_table_lock);

	if (uwsgi.shared->rpc_count < uwsgi.rpc_max) {
		urpc = &uwsgi.rpc_table[uwsgi.shared->rpc_count];

		memcpy(urpc->name, name, strlen(name));
		urpc->modifier1 = modifier1;
		urpc->args = args;
		urpc->func = func;

		uwsgi.shared->rpc_count++;

		ret = 0;
		uwsgi_log("registered RPC function %s\n", name);
	}

	uwsgi_unlock(uwsgi.rpc_table_lock);

	return ret;
}

uint16_t uwsgi_rpc(char *name, uint8_t argc, char *argv[], uint16_t argvs[], char *output) {

	struct uwsgi_rpc *urpc = NULL;
	uint64_t i;
	uint16_t ret = 0;

	for (i = 0; i < uwsgi.shared->rpc_count; i++) {
		if (uwsgi.rpc_table[i].name[0] != 0) {
			if (!strcmp(uwsgi.rpc_table[i].name, name)) {
				urpc = &uwsgi.rpc_table[i];
				break;
			}
		}
	}

	if (urpc) {
		if (uwsgi.p[urpc->modifier1]->rpc) {
			ret = uwsgi.p[urpc->modifier1]->rpc(urpc->func, argc, argv, argvs, output);
		}
	}

	return ret;
}


char *uwsgi_do_rpc(char *node, char *func, uint8_t argc, char *argv[], uint16_t argvs[], uint16_t * len) {

	uint8_t i;
	uint16_t ulen;
	struct uwsgi_header *uh = NULL;
	char *buffer = NULL;

	*len = 0;

	if (node == NULL || !strcmp(node, "")) {
		// allocate the whole buffer
		buffer = uwsgi_malloc(65536);
		*len = uwsgi_rpc(func, argc, argv, argvs, buffer);
		return buffer;
	}


	// connect to node (async way)
	int fd = uwsgi_connect(node, 0, 1);
	if (fd < 0)
		return NULL;

	// wait for connection;
	int ret = uwsgi.wait_write_hook(fd, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
	if (ret <= 0) {
		return NULL;
	}

	// prepare a uwsgi array
	uint16_t buffer_size = 2 + strlen(func);

	for (i = 0; i < argc; i++) {
		buffer_size += 2 + argvs[i];
	}

	// allocate the whole buffer
	buffer = uwsgi_malloc(4+buffer_size);

	// set the uwsgi header
	uh = (struct uwsgi_header *) buffer;
	uh->modifier1 = 173;
	uh->pktsize = buffer_size;
	uh->modifier2 = 0;

	// add func to the array
	char *bufptr = buffer + 4;
	ulen = strlen(func);
	*bufptr++ = (uint8_t) (ulen & 0xff);
	*bufptr++ = (uint8_t) ((ulen >> 8) & 0xff);
	memcpy(bufptr, func, ulen);
	bufptr += ulen;

	for (i = 0; i < argc; i++) {
		ulen = argvs[i];
		*bufptr++ = (uint8_t) (ulen & 0xff);
		*bufptr++ = (uint8_t) ((ulen >> 8) & 0xff);
		memcpy(bufptr, argv[i], ulen);
		bufptr += ulen;
	}

	// ok the reuqest is ready, let's send it in non blocking way
	if (uwsgi_write_true_nb(fd, buffer, buffer_size+4, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT])) {
		goto error;
	}

	// ok time to wait for the response in non blocking way
	size_t rlen = buffer_size+4;
	if (uwsgi_read_with_realloc(fd, &buffer, &rlen, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT])) {
		goto error;
	}

	close(fd);
	*len = rlen;
	if (*len == 0) {
		goto error;
	}
	return buffer;

error:
	close(fd);
	free(buffer);
	return NULL;

}


void uwsgi_rpc_init() {
	uwsgi.rpc_table = uwsgi_calloc_shared(sizeof(struct uwsgi_rpc) * uwsgi.rpc_max);
}
