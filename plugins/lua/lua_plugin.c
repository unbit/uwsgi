#include "../../uwsgi.h"

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

extern struct uwsgi_server uwsgi;

struct uwsgi_lua {
	struct lua_State **L;

	char *filename;
} ulua;

#define lca(L, n)		ulua_check_args(L, __FUNCTION__, n)
#define response_append(x, y) if (uwsgi_buffer_append(status_and_headers, x, y)) { uwsgi_buffer_destroy(status_and_headers); lua_pushvalue(L, -1); goto clear;}
#define response_append_header(x, y) if (uwsgi_buffer_append(status_and_headers, x, y)) { uwsgi_buffer_destroy(status_and_headers); lua_pop(L, 2); lua_pushvalue(L, -1); goto clear;}

struct uwsgi_option uwsgi_lua_options[] = {

	{"lua", required_argument, 0, "load lua wsapi app", uwsgi_opt_set_str, &ulua.filename, 0},

	{0, 0, 0, 0},

};

static void ulua_check_args(lua_State *L, const char *func, int n) {
	int args = lua_gettop(L);
	char error[4096];
	if (args != n) {
		if (n == 1) {
			snprintf(error, 4096, "uwsgi.%s takes 1 parameter", func+10);
		}
		else {
			snprintf(error, 4096, "uwsgi.%s takes %d parameters", func+10, n);
		}
		lua_pushstring(L, error);
        	lua_error(L);
	}
}

static int uwsgi_api_log(lua_State *L) {
	
	const char *logline ;

	lca(L, 1);

	if (lua_isstring(L, 1)) {
		logline = lua_tolstring(L, 1, NULL);
                uwsgi_log( "%s\n", logline);
	}

	return 0;
}

static int uwsgi_api_register_rpc(lua_State *L) {

        uint8_t argc = lua_gettop(L);
	const char *name;
	// a hack for 64bit;
	int func;
	long lfunc;

	if (argc < 2) {
		lua_pushnil(L);
		return 1;
	}

	name = lua_tolstring(L, 1, NULL);

	lua_pushvalue(L, 2);
        func = luaL_ref(L, LUA_REGISTRYINDEX);

	uwsgi_log("registered function %d in global table\n", func);
	lfunc = func;

        if (uwsgi_register_rpc((char *)name, 6, 0, (void *) lfunc)) {
		lua_pushnil(L);
        }
	else {
		lua_pushboolean(L, 1);
	}

	return 1;
}



static char *encode_lua_table(lua_State *L, int index, uint16_t *size) {

	char *buf, *ptrbuf;
	char *key;
	char *value;
	size_t keylen;
	size_t vallen;

	*size = 0;

	lua_pushnil(L);
	while (lua_next(L, index) != 0) {
		if (lua_isstring(L, -2) && lua_isstring(L, -1)) {
			key = (char *) lua_tolstring(L, -2, &keylen);
			value = (char *) lua_tolstring(L, -1, &vallen);
			if (keylen > 0xffff || vallen > 0xffff) continue;
			*size += (2+keylen+2+vallen);
		}
		lua_pop(L, 1);
	}

	buf = uwsgi_malloc(*size);

	ptrbuf = buf;
	lua_pushnil(L);
	while (lua_next(L, index) != 0) {
		if (lua_isstring(L, -2) && lua_isstring(L, -1)) {
			key = (char *) lua_tolstring(L, -2, &keylen);
			value = (char *) lua_tolstring(L, -1, &vallen);

			if (keylen > 0xffff || vallen > 0xffff) continue;

			*ptrbuf++ = (uint8_t) (keylen  & 0xff);
                        *ptrbuf++ = (uint8_t) ((keylen >>8) & 0xff);
			memcpy(ptrbuf, key, keylen); ptrbuf += keylen;
			*ptrbuf++ = (uint8_t) (vallen  & 0xff);
                        *ptrbuf++ = (uint8_t) ((vallen >>8) & 0xff);
			memcpy(ptrbuf, value, vallen); ptrbuf += vallen;
		}
		lua_pop(L, 1);
	}

	return buf;
}

static int uwsgi_api_cache_set(lua_State *L) {

	int args = lua_gettop(L);
        const char *key ;
        const char *value ;
        uint64_t expires = 0;
	size_t vallen;


	if (args > 1) {

		key = lua_tolstring(L, 1, NULL);
		value = lua_tolstring(L, 2, &vallen);
		if (args > 2) {
			expires = lua_tonumber(L, 3);
		}

        	uwsgi_cache_set((char *)key, strlen(key), (char *)value, (uint16_t) vallen, expires, 0);
		
	}

	lua_pushnil(L);
	return 1;

}

static int uwsgi_api_register_signal(lua_State *L) {

	int args = lua_gettop(L);
	uint8_t sig;
	long lhandler;
	const char *who;
	
	if (args >= 3) {

		sig = lua_tonumber(L, 1);
		who = lua_tostring(L, 2);
		lua_pushvalue(L, 3);
		lhandler = luaL_ref(L, LUA_REGISTRYINDEX);

		uwsgi_register_signal(sig, (char *)who, (void *) lhandler, 6);
	}

	lua_pushnil(L);
        return 1;
}


static int uwsgi_api_cache_get(lua_State *L) {

        char *value ;
        uint64_t valsize;
	const char *key ;

        lca(L, 1);

	if (lua_isstring(L, 1)) {

		key = lua_tolstring(L, 1, NULL);
        	value = uwsgi_cache_get((char *)key, strlen(key), &valsize);

        	if (value) {
                	lua_pushlstring(L, value, valsize);
			return 1;
        	}

	}

	lua_pushnil(L);

        return 1;

}


static int uwsgi_api_send_message(lua_State *L) {

	int args = lua_gettop(L);
	const char *host;
	int uwsgi_fd;
	uint8_t modifier1, modifier2;
	char *pkt = NULL;
	uint16_t pktsize = 0 ;
	char buf[4096];
	int rlen;
	int items = 0;
	int input_fd = -1, timeout = -1, input_size = 0;
	
	// is this an fd ?
	if (lua_isnumber(L, 1)) {
		args = 1;
	}
	else if (lua_isstring(L, 1)) {
		host = lua_tolstring(L, 1, NULL);	
		uwsgi_fd = uwsgi_connect((char *)host, timeout, 0);
		modifier1 = lua_tonumber(L, 2);	
		modifier2 = lua_tonumber(L, 3);	
		if (args > 4) {
			timeout = lua_tonumber(L, 5);
			if (args == 7) {
				input_fd = lua_tonumber(L, 6);	
				input_size = lua_tonumber(L, 7);	
			}
		}
		if (lua_istable(L,4)) {
			// passed a table
			pkt = encode_lua_table(L, 4, &pktsize);
		}
	 	if (uwsgi_send_message(uwsgi_fd, modifier1, modifier2, pkt, pktsize, input_fd, input_size, timeout) == -1) {
			free(pkt);
			lua_pushnil(L);
			return 1;
		}
		free(pkt);

		for(;;) {
        		rlen = uwsgi_waitfd(uwsgi_fd, timeout);
        		if (rlen > 0) {
                		rlen = read(uwsgi_fd, buf, 4096);
                		if (rlen < 0) {
                        		uwsgi_error("read()");
					break;
                		}
                		else if (rlen > 0) {
					lua_pushlstring(L, buf, rlen);	
					items++;
                		}
				else {
					break;
				}
			}
        		else if (rlen == 0) {
                		uwsgi_log("uwsgi request timed out waiting for response\n");
				break;
        		}
		}

                close(uwsgi_fd);

	}
	
	return items;
}

static int uwsgi_api_cl(lua_State *L) {

	struct wsgi_request *wsgi_req = current_wsgi_req();
	
	lua_pushnumber(L, wsgi_req->post_cl);
	return 1;
}

static int uwsgi_api_req_fd(lua_State *L) {

	struct wsgi_request *wsgi_req = current_wsgi_req();
	
	lua_pushnumber(L, wsgi_req->poll.fd);
	return 1;
}

static const luaL_reg uwsgi_api[] = {
  {"log", uwsgi_api_log},
  {"cl", uwsgi_api_cl},
  {"req_fd", uwsgi_api_req_fd},
  {"send_message", uwsgi_api_send_message},
  {"cache_get", uwsgi_api_cache_get},
  {"cache_set", uwsgi_api_cache_set},
  {"register_signal", uwsgi_api_register_signal},
  {"register_rpc", uwsgi_api_register_rpc},
  {NULL, NULL}
};



static int uwsgi_lua_input(lua_State *L) {

	struct wsgi_request *wsgi_req = current_wsgi_req();
	int fd = wsgi_req->async_post ?
	  fileno(wsgi_req->async_post) : wsgi_req->poll.fd;
	ssize_t sum, len, total;
	char *buf, *ptr;

	int n = lua_gettop(L);

	if (!wsgi_req->post_cl) {
		lua_pushlstring(L, "", 0);
		return 1;
	}

	sum = lua_tonumber(L, 2);

	if (n > 1) {
		uwsgi_log("requested %d bytes\n", sum);
	}

	buf = uwsgi_malloc(sum);

	total = sum;

	ptr = buf;
	while(total) {
		len = read(fd, ptr, total);
		ptr += len;
		total -= len;
	}

	lua_pushlstring(L, buf, sum);
	free(buf);

	return 1;
}

int uwsgi_lua_init(){

	uwsgi_log("Initializing Lua environment... (%d cores)\n", uwsgi.cores);

	ulua.L = uwsgi_malloc( sizeof(lua_State*) * uwsgi.cores );

	// ok the lua engine is ready
	return 0;


}

void uwsgi_lua_app() {
	int i;

	if (ulua.filename) {
		for(i=0;i<uwsgi.cores;i++) {
			ulua.L[i] = luaL_newstate();
			luaL_openlibs(ulua.L[i]);
			luaL_register(ulua.L[i], "uwsgi", uwsgi_api);
			if (luaL_loadfile(ulua.L[i], ulua.filename)) {
				uwsgi_log("unable to load file %s: %s\n", ulua.filename, lua_tostring(ulua.L[i], -1));
				exit(1);
			}
			
			// use a pcall
			//lua_call(ulua.L[i], 0, 1);
			if (lua_pcall(ulua.L[i], 0, 1, 0) != 0) {
				uwsgi_log("%s\n", lua_tostring(ulua.L[i], -1));
				exit(1);
			}
			
			// if the loaded lua app returns as a table, fetch the
			// run function.
			if (lua_istable(ulua.L[i], 2)) {
				lua_pushstring(ulua.L[i], "run" );
				lua_gettable(ulua.L[i], 2);
				lua_replace(ulua.L[i], 2);
			}
					
			if (! lua_isfunction(ulua.L[i], 2))	{
				uwsgi_log("Can't find WSAPI entry point (no function, nor a table with function'run').\n");
				exit(1);
			}
		}

	}
}

int uwsgi_lua_request(struct wsgi_request *wsgi_req) {

	int i;
	const char *http;
	size_t slen;
	ssize_t rlen;
	char *ptrbuf;
	lua_State *L = ulua.L[wsgi_req->async_id];

#ifdef UWSGI_ASYNC
	if (wsgi_req->async_status == UWSGI_AGAIN) {
		if ((i = lua_pcall(L, 0, 1, 0)) == 0) {
			if (lua_type(L, -1) == LUA_TSTRING) {
				http = lua_tolstring(L, -1, &slen);
				if ( (rlen = wsgi_req->socket->proto_write(wsgi_req, (char *)http, slen)) != (ssize_t) slen) {
					return UWSGI_OK;
				}
				wsgi_req->response_size += rlen;
			}
			lua_pop(L, 1);
			lua_pushvalue(L, -1);
			return UWSGI_AGAIN;
		}
		goto clear;
	}
#endif

	/* Standard WSAPI request */
	if (!wsgi_req->uh.pktsize) {
		uwsgi_log( "Invalid WSAPI request. skip.\n");
		goto clear2;
	}

	if (uwsgi_parse_vars(wsgi_req)) {
		uwsgi_log("Invalid WSAPI request. skip.\n");
		goto clear2;
	}

	// put function in the stack
	//lua_getfield(L, LUA_GLOBALSINDEX, "run");
	lua_pushvalue(L, -1);

	// put cgi vars in the stack

	lua_newtable(L);
	lua_pushstring(L, "");
	lua_setfield(L, -2, "CONTENT_TYPE");
	for(i=0;i<wsgi_req->var_cnt;i++) {
		lua_pushlstring(L, (char *)wsgi_req->hvec[i+1].iov_base, wsgi_req->hvec[i+1].iov_len);
		// transform it in a valid c string TODO this is ugly
		ptrbuf = wsgi_req->hvec[i].iov_base+wsgi_req->hvec[i].iov_len;
		*ptrbuf = 0;
		lua_setfield(L, -2, (char *)wsgi_req->hvec[i].iov_base);
		i++;
	}


	// put "input" table
	lua_newtable(L);
	lua_pushcfunction(L, uwsgi_lua_input);
	lua_setfield(L, -2, "read");
	lua_setfield(L, -2, "input");

#ifdef UWSGI_DEBUG
	uwsgi_log("stack pos %d\n", lua_gettop(L));
#endif

	// call function
	i = lua_pcall(L, 1, 3, 0);
	if (i != 0) {
		uwsgi_log("%s\n", lua_tostring(L, -1));
		lua_pop(L, 1);
                lua_pushvalue(L, -1);
		goto clear;
	}

	//uwsgi_log("%d %s %s %s\n",i,lua_typename(L, lua_type(L, -3)), lua_typename(L, lua_type(L, -2)) ,  lua_typename(L, lua_type(L, -1)));

	// this buffer will contains the whole headers (+status)
	struct uwsgi_buffer *status_and_headers = uwsgi_buffer_new(4096);

	// send status
	if (lua_type(L, -3) == LUA_TSTRING || lua_type(L, -3) == LUA_TNUMBER) {
		http = lua_tolstring(L, -3, &slen);

		response_append(wsgi_req->protocol, wsgi_req->protocol_len);
		response_append(" ", 1);
		response_append((char *) http, slen);
		response_append("\r\n", 2);

		// transform the first 3 bytes of the string in a number
		wsgi_req->status = uwsgi_str3_num((char *)http);
	}
	else {
		uwsgi_log("[uwsgi-lua] invalid response status !!!\n");
		// let's continue 
	}

	// send headers

	lua_pushnil(L);
	while(lua_next(L, -3) != 0) {
		http = lua_tolstring(L, -2, &slen);

		response_append_header((char *)http, slen);
		response_append_header(": ", 2);

		http = lua_tolstring(L, -1, &slen);

		response_append_header((char *)http, slen);
		response_append_header("\r\n", 2);

		lua_pop(L, 1);
		wsgi_req->header_cnt++;
	}

	response_append("\r\n", 2);

	wsgi_req->headers_size = wsgi_req->socket->proto_write_header(wsgi_req, status_and_headers->buf, status_and_headers->pos);
	uwsgi_buffer_destroy(status_and_headers);

	// send body with coroutine
	lua_pushvalue(L, -1);

	while ( (i = lua_pcall(L, 0, 1, 0)) == 0) {
		if (lua_type(L, -1) == LUA_TSTRING) {
			http = lua_tolstring(L, -1, &slen);
			if ( (rlen = wsgi_req->socket->proto_write(wsgi_req, (char *)http, slen)) != (ssize_t) slen) {
				lua_pop(L, 1);
                		lua_pushvalue(L, -1);
				goto clear;
			}
			wsgi_req->response_size += rlen;
		}
		lua_pop(L, 1);
		lua_pushvalue(L, -1);
#ifdef UWSGI_ASYNC
		if (uwsgi.async > 1) {
			return UWSGI_AGAIN;
		}
#endif
	}

clear:
	lua_pop(L, 4);
clear2:

	// set frequency
	lua_gc(L, LUA_GCCOLLECT, 0);

	return UWSGI_OK;

}

void uwsgi_lua_after_request(struct wsgi_request *wsgi_req) {

	log_request(wsgi_req);
}


int uwsgi_lua_magic(char *mountpoint, char *lazy) {

	if (!strcmp(lazy+strlen(lazy)-4, ".lua")) {
                ulua.filename = lazy;
                return 1;
        }
        else if (!strcmp(lazy+strlen(lazy)-3, ".ws")) {
                ulua.filename = lazy;
                return 1;
        }


	return 0;
}

char *uwsgi_lua_code_string(char *id, char *code, char *func, char *key, uint16_t keylen) {

	static struct lua_State *L = NULL;

	if (!L) {
		L = luaL_newstate();
                luaL_openlibs(L);
                if (luaL_loadfile(L, code) || lua_pcall(L, 0, 0, 0)) {
                	uwsgi_log("unable to load file %s: %s\n", code, lua_tostring(L, -1));
			lua_close(L);
			L = NULL;
			return NULL;
                }
		lua_getglobal(L, func);
		if (!lua_isfunction(L,-1)) {
			uwsgi_log("unable to find %s function in lua file %s\n", func, code);
			lua_close(L);
			L = NULL;
			return NULL;
		}
		lua_pushnil(L);
	}

	
	lua_pop(L, 1);

	lua_pushvalue(L, -1);
	lua_pushlstring(L, key, keylen);

#ifdef UWSGI_DEBUG
	uwsgi_log("stack pos %d %.*s\n", lua_gettop(L), keylen, key);
#endif

        if (lua_pcall(L, 1, 1, 0) != 0) {
                uwsgi_log("error running function `f': %s",
                 lua_tostring(L, -1));
                return NULL;

        }

	if (lua_isstring(L, -1)) {
                const char *ret = lua_tolstring(L, -1, NULL);
		return (char *)ret;
        }

        return NULL;
}

int uwsgi_lua_signal_handler(uint8_t sig, void *handler) {

	struct wsgi_request *wsgi_req = current_wsgi_req();
	
	lua_State *L = ulua.L[wsgi_req->async_id];

	uwsgi_log("managing signal handler on core %d\n", wsgi_req->async_id);

	lua_rawgeti(L, LUA_REGISTRYINDEX, (long) handler);

	lua_pushnumber(L, sig);

	if (lua_pcall(L, 1, 1, 0) != 0) {
		uwsgi_log("error running function `f': %s",
                 lua_tostring(L, -1));

		return -1;

	}

	return 0;
	
}

uint16_t uwsgi_lua_rpc(void * func, uint8_t argc, char **argv, uint16_t argvs[], char *buffer) {

        uint8_t i;
        const char *sv;
        size_t sl;
	long lfunc = (long) func;
	int ifunc = lfunc;

	struct wsgi_request *wsgi_req = current_wsgi_req();
	
	lua_State *L = ulua.L[wsgi_req->async_id];

	uwsgi_log("get function %d\n", ifunc);
	lua_rawgeti(L, LUA_REGISTRYINDEX, ifunc);

        for(i=0;i<argc;i++) {
		lua_pushlstring(L, argv[i], argvs[i]);
        }

        if (lua_pcall(L, argc, 1, 0) != 0) {
		uwsgi_log("error running function `f': %s", lua_tostring(L, -1));
		return 0;
        }

	
	sv = lua_tolstring(L, -1, &sl);

	uwsgi_log("sv = %s sl = %d\n", sv, sl);
	if (sl <= 0xffff) {
		memcpy(buffer, sv, sl);
		return sl;
	}

        return 0;

}


struct uwsgi_plugin lua_plugin = {

	.name = "lua",
	.modifier1 = 6,
	.init = uwsgi_lua_init,
	.options = uwsgi_lua_options,
	.request = uwsgi_lua_request,
	.after_request = uwsgi_lua_after_request,
	.init_apps = uwsgi_lua_app,
	.magic = uwsgi_lua_magic,
	.signal_handler = uwsgi_lua_signal_handler,

	.code_string = uwsgi_lua_code_string,
	.rpc = uwsgi_lua_rpc,

};

