#ifndef ROCK_SOLID
#ifndef UNBIT

#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

#define SNMP_SEQUENCE 0x30
#define SNMP_INTEGER 0x02
#define SNMP_STRING 0x04
#define SNMP_GET 0xA0
#define SNMP_OID 0x06

/* 1.3.6.1.4.1.35156.17.X.X */
#define SNMP_UWSGI_BASE "\x2B\x06\x01\x04\x01\x82\x92\x54\x11"

static int get_snmp_length(uint8_t *, uint16_t *);
static int get_snmp_integer(uint8_t *, uint64_t *);
static int get_snmp_string(uint8_t *, uint16_t *, char **);

static uint64_t get_uwsgi_snmp_value(uint64_t);
static uint64_t get_uwsgi_custom_snmp_value(uint64_t);


struct uwsgi_oid {
	uint64_t oid1;
	uint64_t oid2;
	uint64_t value;
	uint64_t valuesize;
	uint16_t size;
	uint8_t first_byte ;
};

static int build_snmp_response(struct uwsgi_oid*, int, uint8_t *, int, uint64_t, uint64_t, char *, uint16_t);

void manage_snmp(int fd, uint8_t *buffer, int size, struct sockaddr_in *client_addr) {
	uint16_t asnlen;
	uint16_t oidlen;
	uint64_t oid_part[2];
	uint8_t what_oid_part ;
	uint16_t slen;
	int ptrdelta ;
	uint8_t *ptr = buffer ;

	struct uwsgi_oid output_oid[10];
	int how_many_output_oid = 0;

	uint64_t snmp_int ;
	uint64_t snmp_version ;
	uint64_t request_id ;
	char *snmp_str ;

	// skip first byte (already parsed)
	ptr++;

	// check total sequence size
	
	ptrdelta = get_snmp_length(ptr, &asnlen);

	if (ptrdelta <= 0)
		return;

	if (asnlen != size-(ptrdelta+1))
		return;

	ptr += ptrdelta ;

	// check snmp version	
	if (*ptr != SNMP_INTEGER)
		return;

	ptr++;

	ptrdelta = get_snmp_integer(ptr, &snmp_version);

	if (ptrdelta <= 0)
		return;

	if (snmp_version > 2)
		return;

	if (ptr+ptrdelta >= buffer+size)
		return;

	ptr += ptrdelta ;

	// check for community string (this must be set from the python vm using uwsgi.community)
	if (*ptr != SNMP_STRING)
                return;

        ptr++;

	ptrdelta = get_snmp_string(ptr, &slen, &snmp_str);

	if (ptrdelta <= 0)
                return;	
	

	if (ptr+ptrdelta >= buffer+size)
		return;

	// TODO check for community string

	ptr += ptrdelta ;
	
	// check for get request
	if (*ptr != SNMP_GET)
                return;

	ptr++;

	ptrdelta = get_snmp_length(ptr, &asnlen);

        if (ptrdelta <= 0)
                return;

	if (ptr+ptrdelta >= buffer+size)
                return;
	
	if (asnlen != ( (buffer+size) - (ptr+ptrdelta) ))
		return;
	ptr += ptrdelta ;
	
	// get request_id
	if (*ptr != SNMP_INTEGER)
                return;
	ptr++; ptrdelta = get_snmp_integer(ptr, &request_id);
	if (ptrdelta <= 0)
                return;
	if (ptr+ptrdelta >= buffer+size)
                return;
        ptr += ptrdelta ;

	// get error
	if (*ptr != SNMP_INTEGER)
                return;
	ptr++; ptrdelta = get_snmp_integer(ptr, &snmp_int);
	if (ptrdelta <= 0)
                return;
	if (ptr+ptrdelta >= buffer+size)
                return;
	if (snmp_int != 0)
		return;
        ptr += ptrdelta ;

	// get index
	if (*ptr != SNMP_INTEGER)
                return;
	ptr++; ptrdelta = get_snmp_integer(ptr, &snmp_int);
	if (ptrdelta <= 0)
                return;
	if (ptr+ptrdelta >= buffer+size)
                return;
	if (snmp_int != 0)
		return;
        ptr += ptrdelta ;

	// check for sequence
	if (*ptr != SNMP_SEQUENCE)
                return;

	ptr++;
	ptrdelta = get_snmp_length(ptr, &asnlen);

        if (ptrdelta <= 0)
                return;

	if (ptr+ptrdelta >= buffer+size)
                return;
	
	if (asnlen != ( (buffer+size) - (ptr+ptrdelta) ))
		return;
        ptr += ptrdelta ;
	
	// now the interesting stuff: OID management
	while(ptr < buffer+size && how_many_output_oid < 10) {
		if (*ptr != SNMP_SEQUENCE)
                	return;
		ptr++;
		ptrdelta = get_snmp_length(ptr, &asnlen);
		if (ptrdelta <= 0)
			return;

		if (ptr+ptrdelta >= buffer+size)
			return;
		
		// check for normal OID uWSGI size: |1.3|.6|.1|.4|.1.|35156|.17|.1/2|.x| + OID_NULL
		if (asnlen < 13)
			return;

		ptr += ptrdelta ;
		// is it an OID ?
		if (*ptr != SNMP_OID)
			return;

		ptr++;

		ptrdelta = get_snmp_length(ptr, &oidlen);
		if (ptrdelta <= 0)
                        return;

                if (ptr+ptrdelta >= buffer+size)
                        return;
		if (oidlen > (asnlen-ptrdelta-2))
			return;

		ptr += ptrdelta ;

		// used by the output sender
		output_oid[how_many_output_oid].size = oidlen ;

		// and now parse the OID !!!
		if (strncmp((char *) ptr, SNMP_UWSGI_BASE, 9))
			return;
		ptr+=9;

		// get the next two oid number
		oidlen = oidlen - 9 ;	
		what_oid_part = 0;
		while(oidlen > 0 && what_oid_part < 2) {
			oid_part[what_oid_part] = 0 ;
			while( (*ptr & 0x80) && oidlen > 0) {
				oid_part[what_oid_part] += (oid_part[what_oid_part] * 0x80) + (*ptr^0x80) ;
				ptr++;
				oidlen--;
			}	
			oid_part[what_oid_part] = (oid_part[what_oid_part] * 0x80) + *ptr;
			ptr++;
			oidlen--;
			what_oid_part++;
		}
		

		if (oid_part[1] > 100)
			return;

		// check for null
		if (strncmp((char *)ptr, "\x05\x00", 2))
			return;


		ptr+=2;

		if (oid_part[0] == 1) {
			output_oid[how_many_output_oid].oid1 = oid_part[0] ;
			output_oid[how_many_output_oid].oid2 = oid_part[1] ;
			output_oid[how_many_output_oid].value = get_uwsgi_snmp_value(oid_part[1]);
		}
		else if (oid_part[0] == 2) {
			output_oid[how_many_output_oid].oid1 = oid_part[0] ;
			output_oid[how_many_output_oid].oid2 = oid_part[1] ;
			output_oid[how_many_output_oid].value = get_uwsgi_custom_snmp_value(oid_part[1]);
		}
		else {
			return;

		}
		how_many_output_oid++;

	}
	

	size = build_snmp_response(output_oid, how_many_output_oid, buffer, size, request_id, snmp_version, snmp_str, slen);

	if (size > 0) {
		if (sendto(fd, buffer, size, 0, ( struct sockaddr * ) client_addr, sizeof(struct sockaddr_in)) < 0) {
			perror("sendto()");
		}
	}
	
}

static uint64_t get_uwsgi_snmp_value(uint64_t val) {
	return val * 300 ;
}

static uint64_t get_uwsgi_custom_snmp_value(uint64_t val) {
	return val * 260 ;
}

static int get_snmp_string(uint8_t *ptr, uint16_t *strlen, char **str) {
        int delta;

        delta = get_snmp_length(ptr, strlen) ;

        if (*strlen > 0) {
                *str = (char *) ptr+delta ;
                return delta + *strlen ;
        }

        return -1 ;
}

static int get_snmp_integer(uint8_t *ptr, uint64_t *val) {
        uint16_t tlen ;
        int delta,i;

        delta = get_snmp_length(ptr, &tlen) ;

        if (tlen > 0) {

#ifdef __BIG_ENDIAN__
                for(i=0;i<tlen;i++) {
#else
                for(i=tlen-1;i>=0;i--) {
#endif
                        val[i] = ptr[1+i];
                }

                return tlen + delta ;
        }

        return -1 ;
}



static int get_snmp_length(uint8_t *ptr, uint16_t *len) {
        char tlen ;
        int i ;

        char *blen = (char *) len ;

        *len = *ptr ;

        if (*len > 127) {
                tlen = *len & 0x7f ;
                if (tlen > 2) {
                        fprintf(stderr,"unsupported snmp length\n");
                        return -1 ;
                }

#ifdef __BIG_ENDIAN__
                for(i=0;i<tlen;i++) {
                        blen[i] = ptr[1+i];
#else
                for(i=tlen-1;i>=0;i--) {
                        blen[i] = ptr[1+((tlen-1)-i)];
#endif
                }

                return tlen+1 ;
        }
        else {
                return 1 ;
        }

}


static int build_snmp_response(struct uwsgi_oid* output_oid, int num_output_oid, uint8_t *buffer, int size, uint64_t request_id, uint64_t version, char *community, uint16_t community_len) {

	static char *snmp_buffer = NULL ;
	int i ;
	int tmpptr = 0 ;
	
	// calc the new size without null values
	uint64_t new_size = size - (2*num_output_oid) ;
	uint16_t seq_size ;


	if (snmp_buffer == NULL) {
		snmp_buffer = malloc(uwsgi.buffer_size);
		if (!snmp_buffer) {
			perror("malloc()");
			return -1 ;
		}
	}

	for(i=0;i<num_output_oid;i++) {
		new_size += output_oid[i].valuesize = 1 ;
		if (output_oid[i].value > 127) {
			output_oid[i].valuesize++;
			output_oid[i].first_byte = 0x81 ;
			if (output_oid[i].value > 0xFF) {
				output_oid[i].valuesize++;
				output_oid[i].first_byte = 0x82 ;
			}
		}	
		new_size += output_oid[i].valuesize ;
	}
	
	fprintf(stderr,"the SNMP output size is : %llu\n", new_size);

	if (new_size > uwsgi.buffer_size || new_size > 0xFFFF)
		return -1;

	seq_size = (uint16_t) new_size ;

	snmp_buffer[0] = buffer[0];
	if (seq_size > 127) {
		if (seq_size > 0xff) {
			snmp_buffer[1] = 0x81 ;
			snmp_buffer[2] = (uint8_t) seq_size ;
			tmpptr = 3 ;
		}
		else {
			snmp_buffer[1] = 0x82 ;
#ifdef __BIG_ENDIAN__
			snmp_buffer[2] = ((uint8_t *) &seq_size)[0];
			snmp_buffer[3] = ((uint8_t *) &seq_size)[1];
#else
			snmp_buffer[2] = ((uint8_t *) &seq_size)[1];
			snmp_buffer[3] = ((uint8_t *) &seq_size)[0];
#endif
			tmpptr = 4 ;
				
		}	
	}
	else {
		tmpptr = 2 ;
		snmp_buffer[1] = (uint8_t) seq_size ;
	}

/*
	snmp_buffer[tmpptr] = // copy version
	snmp_buffer[tmpptr] = // copy community
	snmp_buffer[tmpptr] = // set response
	snmp_buffer[tmpptr] = // sequence size (!!!)
	snmp_buffer[tmpptr] = // request_id
	snmp_buffer[tmpptr] = // error
	snmp_buffer[tmpptr] = // index

	snmp_buffer[tmpptr] = // main sequence

	snmp_buffer[tmpptr] = // OID cycle -> sequence + oid + value
*/

	return -1 ;

}



#endif
#endif
