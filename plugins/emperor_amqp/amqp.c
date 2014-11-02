#include "../../uwsgi.h"

#define AMQP_CONNECTION_HEADER "AMQP\0\0\x09\x01"

#define amqp_send(a, b, c) if (send(a, b, c, 0) < 0) { uwsgi_error("send()"); return -1; }

struct amqp_frame_header {

	char type;
	uint16_t channel;
	uint32_t size;

} __attribute__((__packed__));

struct amqp_frame_method {
	uint16_t class_id;
	uint16_t method_id;
} __attribute__((__packed__));

static char *amqp_simple_get_frame(int, struct amqp_frame_header *);
static char *amqp_get_method(int, uint16_t, uint16_t, uint32_t *);

static char *amqp_get_str(char *ptr, char *watermark) {

        uint8_t str_size;

	// over engeneering...
	if (ptr+1 > watermark) return NULL;

        str_size = *ptr;

	if (ptr+1+str_size > watermark) return NULL;

        return ptr+1+str_size;
}


static char *amqp_get_short(char *ptr, char *watermark, uint16_t *sv) {

	uint16_t tmp_short;

	if (ptr+2 > watermark) return NULL;

	memcpy(&tmp_short, ptr, 2);

	*sv = ntohs(tmp_short);

	return ptr+2;
}

static char *amqp_get_long(char *ptr, char *watermark, uint32_t *lv) {

	uint32_t tmp_long;

	if (ptr+4 > watermark) return NULL;

	memcpy(&tmp_long, ptr, 4);

	*lv = ntohl(tmp_long);
	return ptr+4;
}

static char *amqp_get_longlong(char *ptr, char *watermark, uint64_t *llv) {

	if (ptr+8 > watermark) return NULL;
        *llv = uwsgi_be64(ptr);
        return ptr+8;
}



static int amqp_send_ack(int fd, uint64_t delivery_tag) {

	uint32_t size = 4 + 8 + 1;

	struct uwsgi_buffer *ub = uwsgi_buffer_new(64);
        // send type and channel
	if (uwsgi_buffer_append(ub, "\1\0\1", 3)) goto end;
        // send size
	if (uwsgi_buffer_u32be(ub, size)) goto end;
	// send class 60 method 80
	if (uwsgi_buffer_append(ub, "\x00\x3C\x00\x50", 4)) goto end;
	// set delivery_tag
	if (uwsgi_buffer_u64be(ub, delivery_tag)) goto end;
	if (uwsgi_buffer_append(ub, "\0\xCE", 2)) goto end;

        // send buffer to socket
        if (write(fd, ub->buf, ub->pos) < 0) {
		uwsgi_error("amqp_send_ack()/write()");
		goto end;
	}


	uwsgi_buffer_destroy(ub);	
	return 0;
end:
	uwsgi_buffer_destroy(ub);
	return -1;
}

char *uwsgi_amqp_consume(int fd, uint64_t *msgsize, char **routing_key) {

	uint32_t size;
	struct amqp_frame_header fh;
	uint64_t delivery_tag;
	uint64_t current_size = 0;
	char *ptr;
	char *watermark;
	uint16_t sv;

	char *frame = amqp_get_method(fd, 60, 60, &size);
	if (!frame) return NULL;

	ptr = frame+4;
	watermark = frame+size;

	// consumer_tag
	ptr = amqp_get_str(ptr, watermark); if (!ptr) goto clear;
	// delivery_tag (needed for ack)
        ptr = amqp_get_longlong(ptr, watermark, &delivery_tag); if (!ptr) goto clear;
	// redelivered
	if (ptr+1 > watermark) goto clear;
	ptr++;
	// exchange
	ptr = amqp_get_str(ptr, watermark); if (!ptr) goto clear;
	// routing_key
	if (ptr+1 > watermark) goto clear;
	uint8_t rk_size = (uint8_t) *ptr;
	ptr++;
	if (ptr+rk_size > watermark) goto clear;

	if (rk_size > 0) {
		char *rkey = uwsgi_concat2n(ptr, rk_size, "", 0);
		ptr+=rk_size;

		*routing_key = rkey;	
	}
	else {
		*routing_key = NULL;
	}
	
	char *header = amqp_simple_get_frame(fd, &fh);
	if (!header) goto clear;

	if (fh.type != 2) goto clear2;

	ptr = header;
	watermark = ptr+fh.size;

	// header class_id
        ptr = amqp_get_short(ptr, watermark, &sv); if (!ptr) goto clear2;
        // header weight
        ptr = amqp_get_short(ptr, watermark, &sv); if (!ptr) goto clear2;
	// message size;
        ptr = amqp_get_longlong(ptr, watermark, msgsize); if (!ptr) goto clear2;

	free(frame);
	frame = NULL;
	free(header);
	header = NULL;

	char *fullbody = uwsgi_malloc(*msgsize);
	char *message;

	while(current_size < *msgsize) {
		message = amqp_simple_get_frame(fd, &fh);
		if (!message) goto clear;

		if (fh.type != 3) {
			free(message);
			goto clear3;
		}

		if (fh.size+current_size > *msgsize) {
			free(message);
			goto clear3;
		}

		memcpy(fullbody+current_size, message, fh.size);
		current_size+=fh.size;
		free(message);
	}

	if (amqp_send_ack(fd, delivery_tag) < 0) {
		goto clear3;
	}

	return fullbody;

clear3:
	free(fullbody);
	return NULL;

clear2:
	free(header);
clear:
	free(frame);
	return NULL;
	
}

static int amqp_send_exchange_declare( int fd, char *exchange, char *exchange_type) {

        uint32_t size = 4 + 2 + (1 +strlen(exchange)) + (1 +strlen(exchange_type)) + 1 + 4;
        uint8_t shortsize = strlen(exchange) ;

        size = htonl(size);
        // send type and channel
        amqp_send(fd, "\1\0\1", 3);
        // send size
        amqp_send(fd, &size, 4);

        // send class 40 method 10
        amqp_send(fd, "\x00\x28\x00\x0A", 4);

        // send empty reserved
        amqp_send(fd, "\0\0", 2);

        // set exchange name
        amqp_send(fd, &shortsize, 1);
        amqp_send(fd, exchange, shortsize);

        // set exchange type
        shortsize = strlen(exchange_type);
        amqp_send(fd, &shortsize, 1);
        amqp_send(fd, exchange_type, shortsize);

        // empty bits
        amqp_send(fd, "\0", 1);
        // empty table
        amqp_send(fd, "\0\0\0\0", 4);

        // send frame-end
        amqp_send(fd, "\xCE", 1);

        return 0;
}


static int amqp_send_queue_bind( int fd, char *queue, char *exchange) {

        uint32_t size = 4 + 2 + (1 +strlen(queue)) + (1 +strlen(exchange)) + 1 + 1 + 4;
        uint8_t shortsize = strlen(queue) ;

        size = htonl(size);
        // send type and channel
        amqp_send(fd, "\1\0\1", 3);
        // send size
        amqp_send(fd, &size, 4);

        // send class 50 method 20
        amqp_send(fd, "\x00\x32\x00\x14", 4);

        // send empty reserved
        amqp_send(fd, "\0\0", 2);

        // set queue name
        amqp_send(fd, &shortsize, 1);
        amqp_send(fd, queue, shortsize);

        // set exchange name
        shortsize = strlen(exchange);
        amqp_send(fd, &shortsize, 1);
        amqp_send(fd, exchange, shortsize);

	// set empty routing-key
        amqp_send(fd, "\0", 1);

        // empty bits
        amqp_send(fd, "\0", 1);
        // empty table
        amqp_send(fd, "\0\0\0\0", 4);

        // send frame-end
        amqp_send(fd, "\xCE", 1);

        return 0;
}


static int amqp_send_queue_consume( int fd, char *queue) {

	uint32_t size = 4 + 2 + (1 +strlen(queue)) + 1 + 1 + 4;
        uint8_t shortsize = strlen(queue) ;

        size = htonl(size);
        // send type and channel
        amqp_send(fd, "\1\0\1", 3);
        // send size
        amqp_send(fd, &size, 4);

        // send class 60 method 20
        amqp_send(fd, "\x00\x3C\x00\x14", 4);

        // send empty reserved
        amqp_send(fd, "\0\0", 2);

        // set queue name
        amqp_send(fd, &shortsize, 1);
        amqp_send(fd, queue, shortsize);

        // set tag name
        amqp_send(fd, "\0", 1);

        // empty bits
        amqp_send(fd, "\0", 1);
        // empty table
        amqp_send(fd, "\0\0\0\0", 4);

        // send frame-end
        amqp_send(fd, "\xCE", 1);

	return 0;
}

static int amqp_wait_connection_start(int fd) {
	uint32_t size;
	char *frame = amqp_get_method(fd, 10, 10, &size);

	if (frame) {
		free(frame);
		return 0;
	}

	return -1;
}

static int amqp_wait_exchange_declare_ok(int fd) {
        uint32_t size;
        char *frame = amqp_get_method(fd, 40, 11, &size);

        if (frame) {
                free(frame);
                return 0;
        }

        return -1;
}


static int amqp_wait_basic_consume_ok(int fd) {
        uint32_t size;
        char *frame = amqp_get_method(fd, 60, 21, &size);

        if (frame) {
                free(frame);
                return 0;
        }

        return -1;
}


static int amqp_wait_channel_open_ok(int fd) {
        uint32_t size;
        char *frame = amqp_get_method(fd, 20, 11, &size);

        if (frame) {
                free(frame);
                return 0;
        }

        return -1;
}

static int amqp_wait_queue_bind_ok(int fd) {
        uint32_t size;
        char *frame = amqp_get_method(fd, 50, 21, &size);

        if (frame) {
                free(frame);
                return 0;
        }

        return -1;
}


static char *amqp_wait_queue_declare_ok(int fd) {
        uint32_t size;
        char *frame = amqp_get_method(fd, 50, 11, &size);
	char *queue = NULL;
	char *ptr;
	char *watermark;

        if (frame) {

		ptr = frame+4;
		watermark = frame+size;

		ptr = amqp_get_str(ptr, watermark); if (!ptr) { free(frame); return NULL; }

                queue = uwsgi_concat2n(frame+5, *(frame+4), "", 0);
		
                free(frame);
                return queue;
        }

        return NULL;
}


static int amqp_wait_connection_open_ok(int fd) {
        uint32_t size;
        char *frame = amqp_get_method(fd, 10, 41, &size);

        if (frame) {
                free(frame);
                return 0;
        }

        return -1;
}


static int amqp_wait_connection_tune(int fd) {

	uint32_t size;
	char *frame = amqp_get_method(fd, 10, 30, &size);

	uint16_t sv;
	uint32_t lv;
	char *watermark ;
	char *ptr;


	if (frame) {
		ptr = frame+4;
		watermark = frame+size;
		ptr = amqp_get_short(ptr, watermark, &sv); if (!ptr) { free(frame); return -1; }
        	uwsgi_log("AMQP max channels: %d\n", sv);
        	ptr = amqp_get_long(ptr, watermark, &lv); if (!ptr) { free(frame); return -1; }
        	uwsgi_log("AMQP max frame size: %d\n", lv);
        	ptr = amqp_get_short(ptr, watermark, &sv); if (!ptr) { free(frame); return -1; }
        	uwsgi_log("AMQP heartbeath: %d\n", sv);

		free(frame);
		return 0;
	}

	return -1;
}

static char *amqp_simple_get_frame(int fd, struct amqp_frame_header *fh) {

	char *ptr = (char *) fh;
        size_t len = 0;
        ssize_t rlen;

        while(len < 7) {
                rlen = recv(fd, ptr, 7-len, 0);
                if (rlen <= 0) {
			if (rlen < 0)
                        	uwsgi_error("recv()");
                        return NULL;
                }
                len += rlen;
                ptr += rlen;
        }

        fh->channel = ntohs(fh->channel);
        fh->size = ntohl(fh->size);

        len = 0;

        char *frame = uwsgi_malloc(fh->size+1);
        ptr = frame;

        while(len < fh->size+1) {
                rlen = recv(fd, ptr, (fh->size+1)-len, 0);
                if (rlen <= 0) {
			if (rlen < 0)
                        	uwsgi_error("recv()");
                        return NULL;
                }
                len += rlen;
                ptr += rlen;
        }

	return frame;
}

static char *amqp_get_method(int fd, uint16_t class_id, uint16_t method_id, uint32_t *size) {

	struct amqp_frame_header fh;
        struct amqp_frame_method *fm;

        char *frame = amqp_simple_get_frame(fd, &fh);
        if (!frame) return NULL;

	if (fh.type != 1) goto clear;

	fm = (struct amqp_frame_method *) frame;
	fm->class_id = ntohs(fm->class_id);
	fm->method_id = ntohs(fm->method_id);

	if (fm->class_id != class_id) goto clear;
	if (fm->method_id != method_id) goto clear;

	*size = fh.size;
	return frame;

clear:

	free(frame);
	return NULL;
}

static int amqp_send_channel_open(int fd, uint16_t id) {
	
	uint32_t size = 4 + 1;
	size = htonl(size);
	// send type and channel
        amqp_send(fd, "\1\0\1", 3);
	// send size
        amqp_send(fd, &size, 4);

        // send class 20 method 10
        amqp_send(fd, "\x00\x14\x00\x0A", 4);

	amqp_send(fd, "\0", 1);
	// send frame-end
        amqp_send(fd, "\xCE", 1);

	return 0;
}

int amqp_send_connection_open(int fd, char *vhost) {

	uint8_t shortsize = strlen(vhost);
	uint32_t size = 4 + 1 +strlen(vhost) + 2;
	size = htonl(size);

        // send type and channel
        amqp_send(fd, "\1\0\0", 3);
        // send size
        amqp_send(fd, &size, 4);

        // send class 10 method 28
        amqp_send(fd, "\x00\x0A\x00\x28", 4);

	amqp_send(fd, &shortsize, 1);
	amqp_send(fd, vhost, strlen(vhost));

	shortsize = 0;
	amqp_send(fd, &shortsize, 1);
	amqp_send(fd, &shortsize, 1);
	// send frame-end
        amqp_send(fd, "\xCE", 1);

	return 0;

}

int amqp_send_connection_tune_ok(int fd, uint16_t max_chan, uint32_t max_frame_size, uint16_t heartbeat) {

	uint32_t size = 4 + 2 + 4 + 2;
	size = htonl(size);

	max_chan = htons(max_chan);
	max_frame_size = htonl(max_frame_size);
	heartbeat = htons(heartbeat);

	// send type and channel
	amqp_send(fd, "\1\0\0", 3);
        // send size
        amqp_send(fd, &size, 4);

        // send class 10 method 15
        amqp_send(fd, "\x00\x0A\x00\x1F", 4);	

	amqp_send(fd, &max_chan, 2);
	amqp_send(fd, &max_frame_size, 4);
	amqp_send(fd, &heartbeat, 2);

	// send frame-end
	amqp_send(fd, "\xCE", 1);

	return 0;

}


static int amqp_send_queue_declare(int fd, char *queue) {

	uint32_t size = 4 + 2 + (1 +strlen(queue)) + 1 + 4;
	uint8_t shortsize = strlen(queue) ;
	
	size = htonl(size);
        // send type and channel
        amqp_send(fd, "\1\0\1", 3);
        // send size
        amqp_send(fd, &size, 4);

	// send class 50 method 10
        amqp_send(fd, "\x00\x32\x00\x0A", 4);

	// send empty reserved
	amqp_send(fd, "\0\0", 2);

	// set queue name
	amqp_send(fd, &shortsize, 1);
	amqp_send(fd, queue, shortsize);

	// set auto-delete bit
	amqp_send(fd, "\x08", 1);
	// empty table
	amqp_send(fd, "\0\0\0\0", 4);

	// send frame-end
        amqp_send(fd, "\xCE", 1);

	return 0;
}

static char *amqp_get_queue(int fd, char *queue) {

	if (amqp_send_queue_declare(fd, queue) < 0) {
		return NULL;
	}

	return amqp_wait_queue_declare_ok(fd);
}


static int amqp_send_connection_start_ok(int fd, char *mech, char *sasl_response, int sasl_response_size, char *locale) {

	uint32_t size = 4 + 4 + (1 +strlen(mech)) + (4 + sasl_response_size) + (1 + strlen(locale));
	uint8_t shortsize ;

	size = htonl(size);
	// send type and channel
	amqp_send(fd, "\1\0\0", 3);
	// send size
	amqp_send(fd, &size, 4);

	// send class 10 method 11
	amqp_send(fd, "\x00\x0A\x00\x0B", 4);

	// send empty client properties
	amqp_send(fd, "\0\0\0\0", 4);

	// send mechanism short string
	shortsize = strlen(mech);
	amqp_send(fd, &shortsize, 1);
	amqp_send(fd, mech, strlen(mech));

	// send sasl response
	size = htonl(sasl_response_size);
	amqp_send(fd, &size, 4);
	amqp_send(fd, sasl_response, sasl_response_size);

	// send locale
	shortsize = strlen(locale);
	amqp_send(fd, &shortsize, 1);
	amqp_send(fd, locale, strlen(locale));

	// send frame-end
	amqp_send(fd, "\xCE", 1);
	
	return 0;
	
}

int uwsgi_amqp_consume_queue(int fd, char *vhost, char *username, char *password, char *queue, char *exchange, char *exchange_type) {

	char *auth = uwsgi_concat4n("\0",1, username, strlen(username), "\0",1, password, strlen(password));

	if (send(fd, AMQP_CONNECTION_HEADER, 8, 0) < 0) {
		uwsgi_error("send()");
		return -1;
	}

	if (amqp_wait_connection_start(fd) < 0) {
		uwsgi_log("AMQP error waiting for Connection.start\n");
		return -1;
	}

	uwsgi_log("sending Connection.start-ok\n");
	if (amqp_send_connection_start_ok(fd, "PLAIN", auth, strlen(username)+strlen(password)+2, "en_US") < 0) {
		free(auth);
		uwsgi_log("AMQP error sending Connection.start-ok\n");
		return -1;
	}

	free(auth);

	if (amqp_wait_connection_tune(fd) < 0) {
		uwsgi_log("AMQP error waiting for Connection.tune\n");
		return -1;
	}

	uwsgi_log("sending Connection.tune-ok\n");
	if (amqp_send_connection_tune_ok(fd, 0, 0xffff, 0) < 0) {
		uwsgi_log("AMQP error sending Connection.tune-ok\n");
		return -1;
	}

	uwsgi_log("sending Connection.open\n");
	if (amqp_send_connection_open(fd, vhost) < 0) {
		uwsgi_log("AMQP error sending Connection.open\n");
		return -1;
	}

	if (amqp_wait_connection_open_ok(fd) < 0) {
		uwsgi_log("AMQP error waiting for Connection.open-ok\n");
		return -1;
	}

	uwsgi_log("sending Channel.open\n");
	if (amqp_send_channel_open(fd, 1) < 0) {
		uwsgi_log("AMQP error sending Channel.open\n");
		return -1;
	}

	if (amqp_wait_channel_open_ok(fd) < 0) {
		uwsgi_log("AMQP error waiting for Channel.open-ok\n");
		return -1;
	}

	queue = amqp_get_queue(fd, queue);
	if (!queue) {
		uwsgi_log("AMQP error sending Queue.declare\n");
		return -1;
	}

	if (exchange) {
		if (amqp_send_exchange_declare(fd, exchange, exchange_type) < 0) {
			uwsgi_log("AMQP error sending Exchange.declare\n");
			free(queue);
                        return -1;
		}

		if (amqp_wait_exchange_declare_ok(fd) < 0) {
			uwsgi_log("AMQP error waiting for Exchange.declare-ok\n");
			free(queue);
                        return -1;
		}

		if (amqp_send_queue_bind(fd, queue, exchange) < 0) {
			uwsgi_log("AMQP error sending Queue.bind\n");
			free(queue);
                        return -1;
                }

		if (amqp_wait_queue_bind_ok(fd) < 0) {
			uwsgi_log("AMQP error waiting for Queue.bind-ok\n");
			free(queue);
                        return -1;
		}
	}

	if (amqp_send_queue_consume(fd, queue) < 0) {
		uwsgi_log("AMQP error sending Basic.consume\n");
        	free(queue);
                return -1;
	}

	if (amqp_wait_basic_consume_ok(fd) < 0) {
		uwsgi_log("AMQP error waiting for Basic.consume-ok\n");
        	free(queue);
                return -1;
	}
	
	free(queue);

	uwsgi_log("AMQP subscription done, waiting for events...\n");
	return 0;
}
