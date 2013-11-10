#include "../../uwsgi.h"
#include "erlang.h"

extern struct uwsgi_server uwsgi;
struct uwsgi_erlang uerl;

struct uwsgi_option erlang_options[] = {
	{"erlang", required_argument, 0, "spawn an erlang c-node", uwsgi_opt_set_str, &uerl.name, UWSGI_OPT_MASTER},
        {"erlang-cookie", required_argument, 0, "set erlang cookie", uwsgi_opt_set_str, &uerl.cookie, 0},
	{0, 0, 0, 0, 0, 0, 0},
};


void dump_eterm(ei_x_buff *x) {

	int etype, esize, arity;
	long long num;
	char *atom;
	int i;
	char *binary;
	long bin_size;
	double fnum;

	ei_get_type(x->buff, &x->index, &etype, &esize);
        uwsgi_log("etype: %d/%c esize: %d\n", etype, etype, esize);

	switch(etype) {
		case ERL_SMALL_INTEGER_EXT:		
		case ERL_INTEGER_EXT:
		case ERL_SMALL_BIG_EXT:
		case ERL_LARGE_BIG_EXT:
			ei_decode_longlong(x->buff, &x->index, &num);
			uwsgi_log("num: %lu\n", num);
			break;
		case ERL_FLOAT_EXT:
			ei_decode_double(x->buff, &x->index, &fnum);
			uwsgi_log("float: %f\n", fnum);
			break;
		case ERL_STRING_EXT:
			atom = uwsgi_malloc(esize+1);
			ei_decode_string(x->buff, &x->index, atom);
			uwsgi_log("string: %s\n", atom);
			free(atom);
			break;
		case ERL_ATOM_EXT:
			atom = uwsgi_malloc(esize+1);
			ei_decode_atom(x->buff, &x->index, atom);
			uwsgi_log("atom: %s\n", atom);
			free(atom);
			break;
		case ERL_SMALL_TUPLE_EXT:
		case ERL_LARGE_TUPLE_EXT:
			ei_decode_tuple_header(x->buff, &x->index, &arity);
			for(i=0;i<arity;i++) {
				dump_eterm(x);
			}
			break;
		case ERL_LIST_EXT:
		case ERL_NIL_EXT:
			ei_decode_list_header(x->buff, &x->index, &arity);
			if (arity == 0) {
				uwsgi_log("nil value\n");
				break;
			}
                        for(i=0;i<arity+1;i++) {
                                dump_eterm(x);
                        }
                        break;
		case ERL_BINARY_EXT:
			binary = uwsgi_malloc(esize);
			ei_decode_binary(x->buff, &x->index, binary, &bin_size);
			uwsgi_log("binary data of %d bytes\n", bin_size);
			free(binary);
			break;
		default:
			uwsgi_log("ignored...\n");
			ei_skip_term(x->buff, &x->index);
			break;
			
			
			
	}
	
	
}

void uwsgi_erlang_rpc(int fd, erlang_pid *from, ei_x_buff *x) {

	int etype, esize;
	int arity;

	char *gen_call;
	char *module;
	char *call;
	char buffer[0xffff];

	char *argv[256] ;
	uint16_t argvs[256] ;
	int argc = 0;
	uint16_t ret;
	ei_x_buff xr;

	erlang_ref eref;

	ei_get_type(x->buff, &x->index, &etype, &esize);

#ifdef UWSGI_DEBUG
	uwsgi_log("%d %c %c %c\n", etype, etype, ERL_SMALL_TUPLE_EXT, ERL_LARGE_TUPLE_EXT);
#endif
	if (etype != ERL_SMALL_TUPLE_EXT && etype != ERL_LARGE_TUPLE_EXT) return;

	ei_decode_tuple_header(x->buff, &x->index, &arity);

#ifdef UWSGI_DEBUG
	uwsgi_log("rpc arity %d\n", arity);
#endif
	if (arity != 3) return ;

	ei_get_type(x->buff, &x->index, &etype, &esize);

	if (etype != ERL_ATOM_EXT && etype != ERL_STRING_EXT) return ;

	gen_call = uwsgi_malloc(esize);

	if (etype == ERL_ATOM_EXT) {
                ei_decode_atom(x->buff, &x->index, gen_call);
        }
        else {
                ei_decode_string(x->buff, &x->index, gen_call);
        }

#ifdef UWSGI_DEBUG
	uwsgi_log("gen call = %s\n", gen_call);
#endif

	ei_get_type(x->buff, &x->index, &etype, &esize);
	
	if (etype != ERL_SMALL_TUPLE_EXT) return ;

	ei_decode_tuple_header(x->buff, &x->index, &arity);
	if (arity != 2) return ;

	ei_get_type(x->buff, &x->index, &etype, &esize);
	ei_skip_term(x->buff, &x->index);
	ei_get_type(x->buff, &x->index, &etype, &esize);
	ei_decode_ref(x->buff, &x->index, &eref);

	ei_get_type(x->buff, &x->index, &etype, &esize);

	module = uwsgi_malloc(esize);

	if (etype == ERL_ATOM_EXT) {
		ei_decode_atom(x->buff, &x->index, module);
	}
	else {
		ei_decode_string(x->buff, &x->index, module);
	}

	ei_get_type(x->buff, &x->index, &etype, &esize);

	if (etype != ERL_SMALL_TUPLE_EXT) return ;

	ei_decode_tuple_header(x->buff, &x->index, &arity);

#ifdef UWSGI_DEBUG
	uwsgi_log("arity: %d\n", arity);
#endif
	if (arity != 5) return ;

	ei_get_type(x->buff, &x->index, &etype, &esize);

        char *method = uwsgi_malloc(esize);

        if (etype == ERL_ATOM_EXT) {
                ei_decode_atom(x->buff, &x->index, method);
        }
        else {
                ei_decode_string(x->buff, &x->index, method);
        }

        if (strcmp(method, "call")) return;

        ei_get_type(x->buff, &x->index, &etype, &esize);

	if (etype != ERL_ATOM_EXT && etype != ERL_STRING_EXT) return ;

	module = uwsgi_malloc(esize);

	if (etype == ERL_ATOM_EXT) {
		ei_decode_atom(x->buff, &x->index, module);
	}
	else {
		ei_decode_string(x->buff, &x->index, module);
	}

	ei_get_type(x->buff, &x->index, &etype, &esize);

	if (etype != ERL_ATOM_EXT && etype != ERL_STRING_EXT) return ;

	call = uwsgi_malloc(esize);

	if (etype == ERL_ATOM_EXT) {
		ei_decode_atom(x->buff, &x->index, call);
	}
	else {
		ei_decode_string(x->buff, &x->index, call);
	}

#ifdef UWSGI_DEBUG
	uwsgi_log("RPC %s %s\n", module, call);
#endif

	ei_get_type(x->buff, &x->index, &etype, &esize);

	if (etype == ERL_ATOM_EXT) {
		argc = 1;
		argv[0] = uwsgi_malloc(esize+1);
		ei_decode_atom(x->buff, &x->index, argv[0]);	
		argvs[1] = esize;
	}
	else if (etype == ERL_STRING_EXT) {
		argc = 1;
		argv[0] = uwsgi_malloc(esize+1);
		ei_decode_string(x->buff, &x->index, argv[0]);	
		argvs[1] = esize;
	}

	ret = uwsgi_rpc(call, argc, argv, argvs, buffer);

#ifdef UWSGI_DEBUG
	uwsgi_log("buffer: %.*s\n", ret, buffer);
#endif

	ei_x_new_with_version(&xr);

	ei_x_encode_tuple_header(&xr, 2);
	//ei_x_encode_atom(&xr, "rex");
	ei_x_encode_ref(&xr, &eref);
	ei_x_encode_string_len(&xr, buffer, ret);

	uwsgi_log("ei_send to %d %s %d %d %d: %d %d\n", fd, from->node, from->num , from->serial, from->creation, xr.index, ei_send(fd, from, xr.buff, xr.index));
	//uwsgi_log("ei_send to %d %s %d %d %d: %d %d\n", fd, from->node, from->num , from->serial, from->creation, xr.index, ei_reg_send(&uerl.cnode, fd, "rex", xr.buff, xr.index));
	
	
}

void erlang_loop(int id, void *data) {

	ErlConnect econn;
	//ErlMessage em;
	erlang_msg em;
	int fd;

	int eversion;

	ei_x_buff x, xr;

	ei_x_new(&x); 
	ei_x_new(&xr); 

	
	/*
	int fd0 = ei_connect(&uerl.cnode, "anothernode@maverick64");
	uwsgi_log("fd0: %d\n", fd0);

	ei_x_encode_list_header(&x, 0);

	ei_rpc_to(&uerl.cnode, fd0, "erlang", "node", x.buff, x.index);

	ei_rpc_from(&uerl.cnode, fd0, 10000, &em, &xr);

	uwsgi_log("From: %s To: %s RegName: %s\n", em.from.node, em.to.node, em.toname);

	xr.index = 0;
	ei_decode_version(xr.buff, &xr.index, &eversion);
        uwsgi_log("eversion: %d\n", eversion);

	dump_eterm(&xr);	
	*/

	for(;;) {

		fd = ei_accept(&uerl.cnode, uerl.fd, &econn);

		if (fd >= 0) {

			for (;;) {
				if (ei_xreceive_msg(fd, &em, &x) == ERL_MSG) {

					if (em.msgtype == ERL_TICK)
						continue;

					uwsgi_log("[erlang] message From: %s To (process): %s\n", em.from.node, em.toname);


					
					x.index = 0;
					ei_decode_version(x.buff, &x.index, &eversion);
#ifdef UWSGI_DEBUG
					uwsgi_log("eversion: %d\n", eversion);
#endif

					if (!strcmp(em.toname, "rex")) {
						uwsgi_erlang_rpc(fd, &em.from, &x);
					}
					else {
						struct uwsgi_erlang_process *uep = uerl.uep;
						while(uep) {
							if (!strcmp(uep->name, em.toname)) {
								if (uep->plugin) {
									uep->plugin(uep->func, &x);	
								}
								break;
							}
							uep = uep->next;
						}

						if (!uep) {
							uwsgi_log("!!! unregistered erlang process requested, dumping it !!!\n");
							dump_eterm(&x);
						}
					}
					
					

/*

					if (em.msgtype) {
						dump_erl_obj(em.msg);
						erl_free_compound(em.msg);
					}
					if (em.to) {
						uwsgi_log("*** TO ***\n");
						dump_erl_obj(em.to);
						erl_free_compound(em.to);
					}

					if (em.from) {
						uwsgi_log("*** FROM ***\n");
						dump_erl_obj(em.from);
						erl_free_compound(em.from);
					}
*/

				}
				else {
					break;
				}
			}

			close(fd);

		}
	}
}

int erlang_init() {

	char *host;
	struct sockaddr_in sin;
	socklen_t slen = sizeof(struct sockaddr_in);
	char *ip = NULL;
	char *nodename;
	struct in_addr addr;

        uerl.lock = uwsgi_lock_init("erlang");

        if (uerl.name) {


		host = strchr(uerl.name, '@');

		if (!host) {
			if (ei_connect_init(&uerl.cnode, uerl.name, uerl.cookie, 0) < 0) {
				uwsgi_log("unable to initialize erlang connection\n");
				exit(1);
			}
		}
		else {
			nodename = uwsgi_concat2n(uerl.name, host-uerl.name, "",0);
			ip = uwsgi_resolve_ip(host+1);
			if (ip) {
#ifdef UWSGI_DEBUG
				uwsgi_log("ip: %s\n", ip);
#endif
				addr.s_addr = inet_addr(ip);
				if (ei_connect_xinit(&uerl.cnode, host+1, nodename, uerl.name, &addr, uerl.cookie, 0) < 0) {
					uwsgi_log("unable to initialize erlang connection\n");
					exit(1);
				}
			}
			else {
				if (ei_connect_init(&uerl.cnode, nodename, uerl.cookie, 0) < 0) {
					uwsgi_log("unable to initialize erlang connection\n");
					exit(1);
				}
			}
			free(nodename);
		}

		if (ip) {
			uerl.fd = bind_to_tcp(ip, uwsgi.listen_queue, NULL);
		}
		else {
			uerl.fd = bind_to_tcp("", uwsgi.listen_queue, NULL);
		}

		if (uerl.fd < 0) {
			exit(1);
		}

        	if (getsockname(uerl.fd, (struct sockaddr *) &sin, &slen)) {
                	uwsgi_error("getsockname()");
			exit(1);
        	}

		if (ei_publish(&uerl.cnode, ntohs(sin.sin_port)) < 0) {
                	uwsgi_log( "*** unable to subscribe with EPMD ***\n");
			exit(1);
		}

		uwsgi_log("Erlang C-Node %s registered on port %d\n", ei_thisnodename(&uerl.cnode), ntohs(sin.sin_port));

	
                if (register_gateway("uWSGI erlang c-node", erlang_loop, NULL) == NULL) {
                        uwsgi_log("unable to register the erlang gateway\n");
                        exit(1);
                }

        }

        return 0;
}

struct uwsgi_plugin erlang_plugin = {

	.name = "erlang",
        .options = erlang_options,
        .init = erlang_init,
};

