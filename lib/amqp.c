#include "../uwsgi.h"

#define AMQP_CONNECTION_HEADER "AMQP\0\0\x09\x01"

#ifdef __BIG_ENDIAN__
#define ntohll(x) x
#else
#define ntohll(x) ( ( (uint64_t)(ntohl( (uint32_t)((x << 32) >> 32) )) << 32) | ntohl( ((uint32_t)(x >> 32)) ) )     
#endif
#define htonll(x) ntohll(x)

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

static char *amqp_simple_get_frame(int, struct amqp_frame_header *, uint32_t *);

static char *amqp_get_longstr(char *ptr, char *watermark) {

        uint32_t longstr_size;

	if (ptr+4 > watermark) return NULL;

        memcpy(&longstr_size, ptr, 4);
        longstr_size = ntohl(longstr_size);

	if (ptr+4+longstr_size > watermark) return NULL;

        return ptr+4+longstr_size;
}

static char *amqp_get_str(char *ptr, char *watermark) {

        uint8_t str_size;

	// over engeneering...
	if (ptr+1 > watermark) return NULL;

        str_size = *ptr;

	if (ptr+1+str_size > watermark) return NULL;

	uwsgi_log("%.*s\n", str_size, ptr+1);

        return ptr+1+str_size;
}


static char *amqp_get_table(char *ptr, char *watermark) {

	uint32_t table_size;

	if (ptr+4 > watermark) return NULL;

	memcpy(&table_size, ptr, 4);

	table_size = ntohl(table_size);

	if (ptr+4+table_size > watermark) return NULL;

	return ptr+4+table_size;
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

        uint64_t tmp_longlong;

	if (ptr+8 > watermark) return NULL;

        memcpy(&tmp_longlong, ptr, 8);

        *llv = ntohll(tmp_longlong);
        return ptr+8;
}


static int amqp_send_queue_declare(int, char *);

static char *amqp_get_frame(int, int *, char *, char *,uint32_t *);

static int amqp_send_ack(int fd, uint64_t delivery_tag) {

	uint32_t size = 4 + 8 + 1;

        size = htonl(size);
        // send type and channel
        amqp_send(fd, "\1\0\1", 3);
        // send size
        amqp_send(fd, &size, 4);

        // send class 60 method 80
        amqp_send(fd, "\x00\x3C\x00\x50", 4);

	// set delivery_tag
	delivery_tag = htonll(delivery_tag);
	amqp_send(fd, &delivery_tag, 8);

        // empty bits
        amqp_send(fd, "\0", 1);

        // send frame-end
        amqp_send(fd, "\xCE", 1);

	return 0;
}

char *uwsgi_amqp_consume(int fd, uint64_t *msgsize) {

	uint32_t size;
	struct amqp_frame_header fh;
	struct amqp_frame_method *fm;
	uint64_t delivery_tag;
	uint64_t current_size = 0;
	char *ptr;
	char *watermark;
	uint16_t sv;

	char *frame = amqp_simple_get_frame(fd, &fh, &size);

	if (!frame) return NULL;

	if (fh.type != 1) goto clear;

        fm = (struct amqp_frame_method *) frame;
        fm->class_id = ntohs(fm->class_id);
        fm->method_id = ntohs(fm->method_id);

	uwsgi_log("getting frame %d %d %d %d\n", fm->class_id, fm->method_id, fh.size, size);

	if (fm->class_id != 60 || fm->method_id != 60) goto clear;

	ptr = frame+4;
	watermark = frame+fh.size;

	uwsgi_log("ok0 %p\n", watermark);

	ptr = amqp_get_str(ptr, watermark); if (!ptr) goto clear;
	uwsgi_log("ok1 %p %p\n", ptr, watermark);
        ptr = amqp_get_longlong(ptr, watermark, &delivery_tag); if (!ptr) goto clear;
	uwsgi_log("ok2\n");
        uwsgi_log("delivery_tag %llu\n", delivery_tag);

	char *header = amqp_simple_get_frame(fd, &fh, &size);
	if (!header) goto clear;

	if (fh.type != 2) goto clear2;

	ptr = header;
	watermark = ptr+fh.size;

	// header class_id
        ptr = amqp_get_short(ptr, watermark, &sv); if (!ptr) goto clear2;
        // header weight
        ptr = amqp_get_short(ptr, watermark, &sv); if (!ptr) goto clear2;
        ptr = amqp_get_longlong(ptr, watermark, msgsize); if (!ptr) goto clear2;

	free(frame);
	free(header);

	char *fullbody = uwsgi_malloc(*msgsize);
	char *message;

	while(current_size < *msgsize) {
		message = amqp_simple_get_frame(fd, &fh, &size);
		if (!message) goto clear;

		if (fh.type != 3) {
			free(message);
			goto clear3;
		}

		if (size+current_size > *msgsize) {
			free(message);
			goto clear3;
		}

		memcpy(fullbody+current_size, message, size);
		current_size+=size;
		free(message);
	}

	uwsgi_log("ack\n");
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

static int amqp_manage_channel(int fd, int *status, char *queue, char *consumer, uint16_t method_id, char *frame, uint32_t size) {

	if (method_id == 11) {
		uwsgi_log("Channel.open-ok\n");
		uwsgi_log("sending Queue.declare\n");
		if (amqp_send_queue_declare(fd, queue) < 0) {
			return -1;
		}

		*status = 4;	
	}

	return 0;
}

static int amqp_send_queue_consume( int fd, int *status, char *queue, char *tag) {

	uint32_t size = 4 + 2 + (1 +strlen(queue)) + (1 +strlen(tag)) + 1 + 4;
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
	shortsize = strlen(tag);
        amqp_send(fd, &shortsize, 1);
        amqp_send(fd, tag, shortsize);

        // empty bits
        amqp_send(fd, "\0", 1);
        // empty table
        amqp_send(fd, "\0\0\0\0", 4);

        // send frame-end
        amqp_send(fd, "\xCE", 1);

	*status = 5;

	return 0;
}

static int amqp_manage_queue(int fd, int *status, char *queue, char *consumer, uint16_t method_id, char *frame, uint32_t size) {

	struct amqp_frame_header fh;
	struct amqp_frame_method *fm;

        if (method_id == 11 && *status == 4) {
                printf("Queue.declare-ok\n");
		// ok start the consumer !!!
		if (amqp_send_queue_consume(fd, status, queue, consumer)) {
			return -1;
		}

		char *frame = amqp_simple_get_frame(fd, &fh, &size);

        	if (!frame) return -1;

        	if (fh.type != 1) goto clear;

        	fm = (struct amqp_frame_method *) frame;
        	fm->class_id = ntohs(fm->class_id);
        	fm->method_id = ntohs(fm->method_id);

        	uwsgi_log("getting frame %d %d %d %d\n", fm->class_id, fm->method_id, fh.size, size);

        	if (fm->class_id != 60 || fm->method_id != 21) return -1;

		free(frame);
                *status = 5;
        }

	return 0;

clear:
	free(frame);
	return -1;
}


static int amqp_manage_connection(int fd, int *status, char *queue, char *consumer, uint16_t method_id, char *frame, uint32_t size) {

	char *ptr = frame;
	uint16_t sv;
	uint32_t lv;

	char *watermark = frame+size;

	if (method_id == 10) {
		printf("Connection.start\n");

		printf("version major: %d\n", *ptr); ptr++;
		printf("version minor: %d\n", *ptr); ptr++;

		ptr = amqp_get_table(ptr, watermark); if (!ptr) return -1;
		ptr = amqp_get_longstr(ptr, watermark); if (!ptr) return -1;
		ptr = amqp_get_longstr(ptr, watermark); if (!ptr) return -1;
		
		*status = 1;
	}
	else if (method_id == 30) {
		printf("Connection.tune\n");

		ptr = amqp_get_short(ptr, watermark, &sv); if (!ptr) return -1;
		printf("max channels: %d\n", sv);
		ptr = amqp_get_long(ptr, watermark, &lv); if (!ptr) return -1;
		printf("max frame size: %d\n", lv);
		ptr = amqp_get_short(ptr, watermark, &sv); if (!ptr) return -1;
		printf("heartbeath: %d\n", sv);

		*status = 2;
	}
	else if (method_id == 41) {
		printf("Connection.open-ok\n");
		*status = 3;
	}

	return 0;
}

static char *amqp_simple_get_frame(int fd, struct amqp_frame_header *fh, uint32_t *size) {

	char *ptr = (char *) fh;
        size_t len = 0, rlen;

        while(len < 7) {
                rlen = recv(fd, ptr, 7-len, 0);
                if (rlen <= 0) {
                        uwsgi_error("recv()");
                        return NULL;
                }
                len += rlen;
                ptr += rlen;
        }

        fh->channel = ntohs(fh->channel);
        fh->size = ntohl(fh->size);

	uwsgi_log("fh->size %d\n", fh->size);
        len = 0;

        char *frame = malloc(fh->size+1);
        ptr = frame;

        while(len < fh->size+1) {
                rlen = recv(fd, ptr, (fh->size+1)-len, 0);
                if (rlen <= 0) {
                        uwsgi_error("recv()");
                        return NULL;
                }
                len += rlen;
                ptr += rlen;
        }

        *size = fh->size;

	return frame;
}

static char *amqp_get_frame(int fd, int *status, char *queue, char *consumer, uint32_t *size) {

	struct amqp_frame_header fh;
	struct amqp_frame_method *fm;

	char *frame = amqp_simple_get_frame(fd, &fh, size);
	if (!frame) return NULL;

	if (fh.type == 1) {
		fm = (struct amqp_frame_method *) frame;
		fm->class_id = ntohs(fm->class_id);
		fm->method_id = ntohs(fm->method_id);

		if (fm->class_id == 10) {
			amqp_manage_connection(fd, status, queue, consumer, fm->method_id, frame+4, fh.size-4);
		}		
		else if (fm->class_id == 20) {
			amqp_manage_channel(fd, status, queue, consumer, fm->method_id, frame+4, fh.size-4);
		}
		else if (fm->class_id == 50) {
			amqp_manage_queue(fd, status, queue, consumer, fm->method_id, frame+4, fh.size-4);
		}
		else {
			printf("AMQP UNMANAGED class_id %d method_id %d\n", fm->class_id, fm->method_id);
		}
	}
	else {
		printf("AMQP UNMANAGED message type %d\n", fh.type);
	}
	return frame;
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

	// empty bits
	amqp_send(fd, "\0", 1);
	// empty table
	amqp_send(fd, "\0\0\0\0", 4);

	// send frame-end
        amqp_send(fd, "\xCE", 1);

	return 0;
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

int uwsgi_amqp_consume_queue(int fd, char *vhost, char *queue, char *consumer) {

	uint32_t size;
	int status = 0;
	char *frame;

	if (send(fd, AMQP_CONNECTION_HEADER, 8, 0) < 0) {
		uwsgi_error("send()");
		return -1;
	}

	for(;;) {

		if (status == 6) return 0;

		frame = amqp_get_frame(fd, &status, queue, consumer, &size);
		//uwsgi_log("received a frame of %d bytes on %p\n", size, frame);
		if (frame == NULL) {
			return -1;
		}

		if (status == 1) {
			uwsgi_log("sending Connection.start-ok\n");
			if (amqp_send_connection_start_ok(fd, "PLAIN", "\0guest\0guest", 12, "en_US") < 0) goto clear;
		}
		else if (status == 2) {
			uwsgi_log("sending Connection.tune-ok\n");
			if (amqp_send_connection_tune_ok(fd, 0, 0xffff, 0) < 0) goto clear;
			uwsgi_log("sending Connection.open\n");
			if (amqp_send_connection_open(fd, vhost) < 0) goto clear;
		}
		else if (status == 3) {
			uwsgi_log("sending Channel.open\n");
			amqp_send_channel_open(fd, 1);
		}
		else if (status == 5) {
			uwsgi_log("Consumer setup\n");
			status = 6;
		}

		free(frame);
	}
	

clear:
	free(frame);
	return -1;

	
}
