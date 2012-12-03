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
	legion = legion1 192.168.0.1:4001 100 mysecret
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

struct uwsgi_legion {
	char *legion;
	uint16_t legion_len;
	uint64_t valor;
	time_t lord;
	int socket;
	struct uwsgi_string_list *nodes;
	struct uwsgi_legion *next;
};

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
