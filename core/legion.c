#include "../uwsgi.h"

extern struct uwsgi_server uwsgi;
/*

	uWSGI Legions subsystem

	A Legion is a group of uWSGI instances sharing a single object. This single
	object can be owned only by the instance with the higher valor. Such an instance is the
	Lord of the Legion. There can only be one (and only one) Lord for each Legion.
	If a member of a Legion spawns with an higher valor than the current Lord, it became the new Lord.
	If two (or more) member of a legion have the same valor, their name (read: ip address) is used as the delta
	for choosing the new Lord:

	each octect of the address + the port is summed to form the delta (192.168.0.1:4001 = 192 + 168 + 0 + 1 + 4001 = 4362).

	The delta number is a last resort, you should always give different valors to the members of a Legion

	{ "legion": "legion1", "valor": "100", "unix": "1354533245", "lord": "1354533245", "name": "foobar" }

	Legions options (the legion1 is formed by 4 nodes, only one node will get the ip address, this is an ip takeover implementation)

	// became a member of a legion (each legion uses a shared secret)
	legion = legion1 192.168.0.1:4001 100 algo:mysecret
	// the other members of the legion
	legion-node = legion1 192.168.0.2:4001
	legion-node = legion1 192.168.0.3:4001
	legion-node = legion1 192.168.0.4:4001

	legion-lord = legion1 iptakeover:action=up,addr=192.168.0.100
	legion-unlord = legion1 iptakeover:action=down,addr=192.168.0.100

	legion-lord = legion1 cmd:foobar.sh up
	legion-unlord = legion1 cmd:foobar.sh down

	TODO
	some option could benefit from the legions subsystem, expecially in clustered environments	
	Cron-tasks for example could be run only by the lord and so on...

	

*/

void legion_loop(struct uwsgi_legion *ul) {
	for(;;) {
		// wait for event
		// ensure the first 4 bytes are valid
		// decrypt packet using the secret
		// parse packet
		uint64_t valor = 10;
		if (valor > ul->valor && ul->lord) {
			// no more lord, trigger unlord event
		}
	}
}

void uwsgi_start_legions() {
	struct uwsgi_legion *legion = uwsgi.legions;
	while(legion) {
		char *colon = strchr(legion->addr, ':');
		if (colon) {
			legion->socket = bind_to_udp(legion->addr, 0, 0);
		}
		else {
			legion->socket = bind_to_unix_dgram(legion->addr);
		}
		legion = legion->next;
	}
}

void uwsgi_legion_add(struct uwsgi_legion *ul) {
	struct uwsgi_legion *old_legion=NULL,*legion = uwsgi.legions;
	while(legion) {
		old_legion = legion;
		legion = legion->next;
	}

	if (old_legion) {
		old_legion->next = ul;
	}
	else {
		uwsgi.legions = ul;
	}
}

int uwsgi_legion_announce(struct uwsgi_legion *ul) {
	struct uwsgi_buffer *ub = uwsgi_buffer_new(4096);

	if (uwsgi_buffer_append(ub, "\0\0\0\0", 4)) goto err;

	if (uwsgi_buffer_append_keyval(ub, "legion", 6, ul->legion, ul->legion_len)) goto err;
	if (uwsgi_buffer_append_keynum(ub, "valor", 5, ul->valor)) goto err;
	if (uwsgi_buffer_append_keynum(ub, "unix", 4, uwsgi_now())) goto err;
	if (uwsgi_buffer_append_keynum(ub, "lord", 4, ul->lord ? ul->lord : 0)) goto err;
	if (uwsgi_buffer_append_keyval(ub, "name", 4, uwsgi.hostname, uwsgi.hostname_len)) goto err;

	struct uwsgi_string_list *usl = ul->nodes;
	while(usl) {
/*
		if (uwsgi_buffer_dgram(ub, ul->socket, usl->custom_ptr)) {
			uwsgi_log("[uwsgi-legion] unable to announce presence to legion \"%s\" using addres \"%s\"\n", ul->legion, usl->value);
		}
*/
		usl = usl->next;
	}

err:
	uwsgi_buffer_destroy(ub);
	return -1;
}

void uwsgi_opt_legion(char *opt, char *value, void *foobar) {

	// legion addr valor algo:secret
	char *legion = uwsgi_str(value);	
	char *space = strchr(legion, ' ');
	if (!space) {
		uwsgi_log("invalid legion syntax, must be <legion> <addr> <valor> <algo:secret>\n");
		exit(1);
	}
	*space = 0;
	char *addr = space+1;

	space = strchr(addr, ' ');
	if (!space) {
                uwsgi_log("invalid legion syntax, must be <legion> <addr> <valor> <algo:secret>\n");
                exit(1);
        }
	*space = 0;
	char *valor = space+1;

	space = strchr(valor, ' ');
	if (!space) {
                uwsgi_log("invalid legion syntax, must be <legion> <addr> <valor> <algo:secret>\n");
                exit(1);
        }
	*space = 0;
	char *algo_secret = space+1;

	char *colon = strchr(algo_secret, ':');
	if (!colon) {
                uwsgi_log("invalid legion syntax, must be <legion> <addr> <valor> <algo:secret>\n");
                exit(1);
        }
	*colon = 0;
	char *secret = colon+1;
	
	if (!uwsgi.ssl_initialized) {
                uwsgi_ssl_init();
        }

	EVP_CIPHER_CTX *ctx = uwsgi_malloc(sizeof(EVP_CIPHER_CTX));
        EVP_CIPHER_CTX_init(ctx);

        const EVP_CIPHER *cipher = EVP_get_cipherbyname(algo_secret);
	if (!cipher) {
		uwsgi_log("[uwsgi-legion] unable to find algorithm/cipher %s\n", algo_secret); 
		exit(1);
	}

	char *iv = uwsgi_ssl_rand(strlen(secret));
	if (!iv) {
		uwsgi_log("[uwsgi-legion] unable to generate iv for legion %s\n", legion); 
		exit(1);
	}

        if (EVP_EncryptInit_ex(ctx, cipher, NULL, (const unsigned char *)secret, (const unsigned char *) iv) <= 0) {
        	uwsgi_error("EVP_EncryptInit_ex()");
		exit(1);
	}

	EVP_CIPHER_CTX *ctx2 = uwsgi_malloc(sizeof(EVP_CIPHER_CTX));
        EVP_CIPHER_CTX_init(ctx2);

        if (EVP_DecryptInit_ex(ctx2, cipher, NULL, (const unsigned char *)secret, NULL) <= 0) {
                uwsgi_error("EVP_DecryptInit_ex()");
                exit(1);
        }

	// we use shared memory, as we want to export legion status to the api
	struct uwsgi_legion *ul = uwsgi_calloc_shared(sizeof(struct uwsgi_legion));
	ul->legion = legion;
	ul->legion_len = strlen(ul->legion);

	ul->valor = strtol(valor, (char **) NULL, 10);
	ul->addr = addr;
	
	ul->encrypt_ctx = ctx;
	ul->decrypt_ctx = ctx2;

	uwsgi_legion_add(ul);
}
