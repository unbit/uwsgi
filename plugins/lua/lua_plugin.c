#include "../../uwsgi.h"

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

extern struct uwsgi_server uwsgi;

struct uwsgi_lua {
	struct lua_State **L ;

	char *filename;
} ulua;

#define LONG_ARGS_LUA_BASE	17000 + (6 * 100)
#define LONG_ARGS_LUA		LONG_ARGS_LUA_BASE + 1

struct option uwsgi_lua_options[] = {

        {"lua", required_argument, 0, LONG_ARGS_LUA},

        {0, 0, 0, 0},

};


static void *uwsgi_lua_alloc(void *ud, void *ptr, size_t osize, size_t nsize) {
	if(nsize == 0) {
		free(ptr);
		return NULL;
	}

	return realloc(ptr, nsize);
}

static int uwsgi_lua_input(lua_State *L) {

	struct wsgi_request *wsgi_req = current_wsgi_req();
	ssize_t sum, len, total;
	char *buf, *ptr ;

        int n = lua_gettop(L);

	if (!wsgi_req->post_cl) {
		lua_pushlstring(L, "", 0);
		return 1;
	}

	sum = lua_tonumber(L, 2) ;

	if (n > 1) {
		uwsgi_log("requested %d bytes\n", sum);
	}

	buf = malloc(sum);
	if (!buf) {
		uwsgi_error("malloc()");
	}

	total = sum;

	ptr = buf;
	while(total) {
		len = read(wsgi_req->poll.fd, ptr, total); 
		ptr += len;
		total -= len;
	}

        lua_pushlstring(L, buf, sum);
	free(buf);

        return 1;
}

int uwsgi_lua_init(){

	int i;

	uwsgi_log("Initializing Lua environment... (%d cores)\n", uwsgi.cores);

	ulua.L = malloc( sizeof(lua_State*) * uwsgi.cores );
	if (!ulua.L) {
		uwsgi_error("malloc()");
		exit(1);
	}
	
	for(i=0;i<uwsgi.cores;i++) {
		ulua.L[i] = lua_newstate(uwsgi_lua_alloc, NULL);
		luaL_openlibs(ulua.L[i]);
		if (luaL_loadfile(ulua.L[i], ulua.filename)) {
			uwsgi_log("unable to load file %s\n", ulua.filename);
			exit(1);
		}
		// use a pcall
		//lua_call(ulua.L[i], 0, 1);
		if (lua_pcall(ulua.L[i], 0, 1, 0) != 0) {
                	uwsgi_log("%s\n", lua_tostring(ulua.L[i], -1));
			exit(1);
		}
	}

	// ok the lua engine is ready
	return 0 ;
	
	
}

int uwsgi_lua_request(struct wsgi_request *wsgi_req) {

	int i;
	const char *http ;
	size_t slen ;
	char *ptrbuf;
	lua_State *L = ulua.L[wsgi_req->async_id];

#ifdef UWSGI_ASYNC
        if (wsgi_req->async_status == UWSGI_AGAIN) {
		if ((i = lua_pcall(L, 0, 1, 0)) == 0) {
                	if (lua_type(L, -1) == LUA_TSTRING) {
                        	http = lua_tolstring(L, -1, &slen);
                        	if (write(wsgi_req->poll.fd, http, slen) != (ssize_t) slen) {
                                	perror("write()");
                                	return UWSGI_OK ;
                        	}
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
		goto clear;
	}

	if (uwsgi_parse_vars(wsgi_req)) {
                uwsgi_log("Invalid WSAPI request. skip.\n");
		goto clear;
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
		ptrbuf = wsgi_req->hvec[i].iov_base+wsgi_req->hvec[i].iov_len ;
		*ptrbuf = 0 ;
		lua_setfield(L, -2, (char *)wsgi_req->hvec[i].iov_base);
		i++;
	}


	// put "input" table
        lua_newtable(L);
        lua_pushcfunction(L, uwsgi_lua_input);
        lua_setfield(L, -2, "read");
	lua_setfield(L, -2, "input");


	// call function
	i = lua_pcall(L, 1, 3, 0);
	if (i != 0) {
		uwsgi_log("%s\n", lua_tostring(L, -1));
		lua_pop(L, 1);
		goto clear;
	}

	//uwsgi_log("%d %s %s %s\n",i,lua_typename(L, lua_type(L, -3)), lua_typename(L, lua_type(L, -2)) ,  lua_typename(L, lua_type(L, -1)));

	// send status
	if (lua_type(L, -3) == LUA_TSTRING || lua_type(L, -3) == LUA_TNUMBER) {
		http = lua_tolstring(L, -3, &slen);
		if (write(wsgi_req->poll.fd, wsgi_req->protocol, wsgi_req->protocol_len) != wsgi_req->protocol_len) {
			perror("write()");
			goto clear;
		}
		if (write(wsgi_req->poll.fd, " ", 1) != 1) {
			perror("write()");
			goto clear;
		}
		if (write(wsgi_req->poll.fd, http, slen) != (ssize_t) slen) {
			perror("write()");
			goto clear;
		}
		// a performance hack
		ptrbuf = (char *) http;
		ptrbuf[3] = 0;
		wsgi_req->status = atoi(ptrbuf);
		if (write(wsgi_req->poll.fd, "\r\n", 2) != 2) {
			perror("write()");
			goto clear;
		}
	}
	
	// send headers

	lua_pushnil(L);
        while(lua_next(L, -3) != 0) {
		http = lua_tolstring(L, -2, &slen);
		if (write(wsgi_req->poll.fd, http, slen) != (ssize_t) slen) {
			perror("write()");
			goto clear;
		}
		if (write(wsgi_req->poll.fd, ": ", 2) != 2) {
			perror("write()");
			goto clear;
		}
		http = lua_tolstring(L, -1, &slen);
		if (write(wsgi_req->poll.fd, http, slen) != (ssize_t) slen) {
			perror("write()");
			goto clear;
		}
		if (write(wsgi_req->poll.fd, "\r\n", 2) != 2) {
			perror("write()");
			goto clear;
		}
                lua_pop(L, 1);
        }

	if (write(wsgi_req->poll.fd, "\r\n", 2) != 2) {
		perror("write()");
		goto clear;
	}
	
	// send body with coroutine
	lua_pushvalue(L, -1);

        while ( (i = lua_pcall(L, 0, 1, 0)) == 0) {
                if (lua_type(L, -1) == LUA_TSTRING) {
			http = lua_tolstring(L, -1, &slen);
			if (write(wsgi_req->poll.fd, http, slen) != (ssize_t) slen) {
				perror("write()");
				goto clear;
			}
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

	// set frequency
	lua_gc(L, LUA_GCCOLLECT, 0);

	return UWSGI_OK;

}

void uwsgi_lua_after_request(struct wsgi_request *wsgi_req) {

	if (uwsgi.shared->options[UWSGI_OPTION_LOGGING])
                log_request(wsgi_req);
}

int uwsgi_lua_manage_options(int i, char *optarg) {

        switch(i) {
                case LONG_ARGS_LUA:
                        ulua.filename = optarg;
                        return 1;
        }

        return 0;
}


struct uwsgi_plugin lua_plugin = {

        .name = "lua",
        .modifier1 = 6,
        .init = uwsgi_lua_init,
        .options = uwsgi_lua_options,
        .manage_opt = uwsgi_lua_manage_options,
        .request = uwsgi_lua_request,
        .after_request = uwsgi_lua_after_request,

};

