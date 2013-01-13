/*

	uWSGI channels

Channels are a way to cores to exchange messages with other cores (both on other workers and other instances)

Channels are quiet expensive (2 descriptors for each core in the instance) but very fast

1000 core for 4 workers = 8000 fd for a channel

	a channel structure (created by the master for each channel)

	char *name;
	int fd[cores*numproc*2];
	uint8_t subscriptions[cores*numproc];
	uint64_t max_packet_size;
	uint64_t tx;
	uint64_t rx;

the channels messages dispatcher lives in a master's thread

when a worker dies:
	clear the whole subscriptions memory area (read: unsubscribe dead cores)

when a request end:
	clear the byte in the subscriptions memory area:


non-blocking communication:

	the first rule is not block. If the socket queue of a core is full the message is discarded... REMEMBER THAT
	only the main socket (the one in which cores write) can block (as the dispatcher constantly read from it)
	

avoiding unwanted messages:

race conditions will be all over the place. To avoid receiving unwanted messages (that could be in the queue), the socket queue
is emptied before joining a channel and soon after leaving it.

When a worker restarts all of its queue are emptied.

queue size is tunable (this is a vital part for gaming as you may want to enqueue a lot of events, or just drop them instead of slowing down things)
	

*/

#include "../uwsgi.h"
extern struct uwsgi_server uwsgi;

struct uwsgi_channel *uwsgi_channel_new(char *name) {
	struct uwsgi_channel *old_c = NULL, *channel = uwsgi.channels;
	while(channel) {
		old_c = channel;
		channel = channel->next;
	}

	channel = uwsgi_calloc_shared(sizeof(struct uwsgi_channel));
	channel->name = name;
#if defined(SOCK_SEQPACKET) && defined(__linux__)
        if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, channel->write_pipe)) {
#else
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, channel->write_pipe)) {
#endif
		uwsgi_error("unable to initialize channel/socketpair()");
		exit(1);
	}

	uwsgi_socket_nb(channel->write_pipe[0]);
	uwsgi_socket_nb(channel->write_pipe[1]);

	channel->fd = uwsgi_calloc_shared(sizeof(int) * ((uwsgi.cores*uwsgi.numproc) * 2));
	int i,j;
	for(i=0;i<uwsgi.numproc;i++) {
		for(j=0;j<uwsgi.cores;j++) {
			int fd_pos = ((uwsgi.cores * i) + j) * 2;
#if defined(SOCK_SEQPACKET) && defined(__linux__)
        		if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, &channel->fd[fd_pos])) {
#else
        		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, &channel->fd[fd_pos])) {
#endif
                		uwsgi_error("unable to initialize channel/socketpair()");
                		exit(1);
        		}
			uwsgi_socket_nb(channel->fd[fd_pos]);
			uwsgi_socket_nb(channel->fd[fd_pos+1]);
		}
	}

	channel->subscriptions = uwsgi_calloc_shared(uwsgi.cores*uwsgi.numproc);
	channel->max_packet_size = 65536;
	channel->pktbuf = uwsgi_malloc(channel->max_packet_size);

	if (old_c) {
		old_c->next = channel;
	}
	else {
		uwsgi.channels = channel;
	}
	
	return channel;
}

struct uwsgi_buffer *uwsgi_channel_simple_recv(struct wsgi_request *wsgi_req, int fd, struct uwsgi_buffer *ub, int timeout) {
	int ret = uwsgi_waitfd(fd, timeout);
	if (ret < 0) return NULL;
	if (ret == 0) return ub;
	ssize_t len = read(fd, ub->buf, ub->len);
	if (len <= 0) return NULL;
	ub->pos += len;
	return ub;
}

void uwsgi_channels_init(void) {
	struct uwsgi_string_list *c = uwsgi.channels_list;
	while(c) {
		uwsgi_channel_new(c->value);
		c = c->next;
	}

	uwsgi.channel_recv_hook = uwsgi_channel_simple_recv;
}

struct uwsgi_channel *uwsgi_channel_by_name(char *name) {
	struct uwsgi_channel *channel = uwsgi.channels;
        while(channel) {
                if (!strcmp(name, channel->name)) {
                        return channel;
                }
                channel = channel->next;
        }

        return NULL;
}

struct uwsgi_channel *uwsgi_channel_find_by_fd(int fd) {
	struct uwsgi_channel *channel = uwsgi.channels;
        while(channel) {
		if (fd == channel->write_pipe[0]) {
			return channel;
		}
                channel = channel->next;
        }

	return NULL;
}

void uwsgi_channel_consume(struct uwsgi_channel *c, int fd) {
	char *buf = uwsgi_calloc(c->max_packet_size);
	for(;;) {
		ssize_t len = read(fd, buf, c->max_packet_size);
		if (len <= 0) {
			free(buf);
			return;
		}
	}
}

// 1 -> standard join
// 2 -> websocket join
void uwsgi_channel_join(struct wsgi_request *wsgi_req, struct uwsgi_channel *c, uint8_t t) {

	int s_pos = (uwsgi.cores * (uwsgi.mywid-1)) + wsgi_req->async_id;
	int fd_pos = ((uwsgi.cores * (uwsgi.mywid-1)) + wsgi_req->async_id) *2;

	uint8_t subscribed = c->subscriptions[s_pos];

	if (subscribed) {
		return;
	}

	int fd = c->fd[fd_pos+1];

	uwsgi_channel_consume(c, fd);

	c->subscriptions[s_pos] = t;
	
}

void uwsgi_channel_leave(struct wsgi_request *wsgi_req, struct uwsgi_channel *c) {
        int s_pos = (uwsgi.cores * (uwsgi.mywid-1)) + wsgi_req->async_id;
	int fd_pos = ((uwsgi.cores * (uwsgi.mywid-1)) + wsgi_req->async_id) *2;

        uint8_t subscribed = c->subscriptions[s_pos];

        if (!subscribed) {
                return;
        }

        c->subscriptions[s_pos] = 0;

        int fd = c->fd[fd_pos+1];

        uwsgi_channel_consume(c, fd);
}

void uwsgi_channels_leave(struct wsgi_request *wsgi_req) {
	struct uwsgi_channel *channel = uwsgi.channels;
	while(channel) {
		uwsgi_channel_leave(wsgi_req, channel);
		channel = channel->next;
	}	
}


int uwsgi_channel_send(struct uwsgi_channel *c, char *msg, size_t msg_len) {
	ssize_t len = write(c->write_pipe[1], msg, msg_len);
	if (len != (ssize_t) msg_len) {
		uwsgi_error("uwsgi_channel_send()/write()");
		return -1;
	}
	return 0;
}

struct uwsgi_buffer *uwsgi_channel_recv(struct wsgi_request *wsgi_req, struct uwsgi_channel *c, int timeout) {
        int s_pos = (uwsgi.cores * (uwsgi.mywid-1)) + wsgi_req->async_id;
	int fd_pos = ((uwsgi.cores * (uwsgi.mywid-1)) + wsgi_req->async_id) *2;

        uint8_t subscribed = c->subscriptions[s_pos];

	if (!subscribed) {
		return NULL;
	}

	int fd = c->fd[fd_pos+1];

	struct uwsgi_buffer *ub = uwsgi_buffer_new(c->max_packet_size);
	if (!uwsgi.channel_recv_hook(wsgi_req, fd, ub, timeout)) {
		uwsgi_buffer_destroy(ub);
		ub = NULL;
	}
	return ub;
}

void *uwsgi_channels_loop(void *foobar) {

	// block all signals
        sigset_t smask;
        sigfillset(&smask);
        pthread_sigmask(SIG_BLOCK, &smask, NULL);

	int i;
	int queue = event_queue_init();
	struct uwsgi_channel *channel = uwsgi.channels;
	while(channel) {
		event_queue_add_fd_read(queue, channel->write_pipe[0]);
		channel = channel->next;
	}

	void *events = event_queue_alloc(64);
	int items = uwsgi.cores * uwsgi.numproc;
	
	for(;;) {
		int nevents = event_queue_wait_multi(queue, -1, events, 64);
		for(i=0;i<nevents;i++) {
			int interesting_fd = event_queue_interesting_fd(events, i);
			channel = uwsgi_channel_find_by_fd(interesting_fd);
			if (!channel) {
				uwsgi_log("[channel-dispatcher] unexpected event received on fd: %d\n", interesting_fd);
				close(interesting_fd);
				continue;
			}
			ssize_t len = read(channel->write_pipe[0], channel->pktbuf, channel->max_packet_size);
			if (len <= 0) {
				uwsgi_error("[channel-dispatcher] read()");
				continue;
			}

			int j;
			for(j=0;j<items;j++) {
				if (channel->subscriptions[j] > 0) {
					int fd = channel->fd[j*2];
					ssize_t wlen = write(fd, channel->pktbuf, len);
					if (wlen != len) {
						uwsgi_error("channels_dispatcher_write()");
					}
				}
			}
		}
	}

	return NULL;
}
