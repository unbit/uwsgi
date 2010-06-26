#include <uwsgi.h>

/* gcc -fPIC -shared -o lua_plugin.so `python2.5-config --cflags` -I /usr/include/lua5.1 -llua5.1 lua_plugin.c */

#include <lua.h>
#include <lualib.h>


static struct uwsgi_lua {
	struct lua_State *L ;
	struct uwsgi_server *uwsgi;
} ulua;

static void *uwsgi_lua_alloc(void *ud, void *ptr, size_t osize, size_t nsize) {
	if(nsize == 0) {
		free(ptr);
		return NULL;
	}

	return realloc(ptr, nsize);
}

static const char *uwsgi_read_lua(lua_State *L, void *data, size_t *size) {

	int fd = *(int *)data;
	static char buf[4096];

	*size = read(fd, buf, 4096);
	
	if (size == 0) {
		return NULL;
	}

	return buf;
}

static int uwsgi_lua_input(lua_State *L) {

        int n = lua_gettop(L);

	static char *buf = "" ;

	fprintf(stderr,"richiesti %d bytes\n", n);

	//sum = read(ulua.uwsgi->poll.fd,); 

        lua_pushlstring(L, buf, 0);

        return 1;
}

int uwsgi_init(struct uwsgi_server *uwsgi, char *args){

	int fd, i;

	fprintf(stderr,"Initializing Lua environment...\n");

	
	

	ulua.L = lua_newstate(uwsgi_lua_alloc, NULL);

	luaL_openlibs(ulua.L);

	
	fd = open(args, O_RDONLY) ;
	if (fd < 0) {
		perror("open()");
		return -1 ;
	}
	
	
	i = lua_load(ulua.L, uwsgi_read_lua, &fd, "uwsgi");

	fprintf(stderr,"lua_load: %d\n" ,i);

	// use a pcall
	lua_call(ulua.L, 0, 1);

	fprintf(stderr,"%s\n", lua_typename(ulua.L, lua_type(ulua.L, -1)));

	// ok the lua engine is ready
	return 0 ;
	
	
}

int uwsgi_request(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {

	int i;
	const char *http ;
	size_t slen ;
	char *ptrbuf;

	/* Standard WSAPI request */
	if (!wsgi_req->uh.pktsize) {
		fprintf (stderr, "Invalid WSAPI request. skip.\n");
		return -1;
	}

	if (uwsgi_parse_vars(uwsgi, wsgi_req)) {
                fprintf(stderr,"Invalid WSAPI request. skip.\n");
                return -1;
        }

	// put function in the stack
	lua_getfield(ulua.L, LUA_GLOBALSINDEX, "run");

	// put cgi vars in the stack
	lua_newtable(ulua.L);
	lua_pushstring(ulua.L, "");
	lua_setfield(ulua.L, -2, "CONTENT_TYPE");
	for(i=0;i<wsgi_req->var_cnt;i++) {
		lua_pushlstring(ulua.L, (char *)wsgi_req->hvec[i+1].iov_base, wsgi_req->hvec[i+1].iov_len);
		// transform it in a valid c string TODO this is ugly
		ptrbuf = wsgi_req->hvec[i].iov_base+wsgi_req->hvec[i].iov_len ;
		*ptrbuf = 0 ;
		lua_setfield(ulua.L, -2, (char *)wsgi_req->hvec[i].iov_base);
		i++;
	}


	// put "input" table
        lua_newtable(ulua.L);
        lua_pushcfunction(ulua.L, uwsgi_lua_input);
        lua_setfield(ulua.L, -2, "read");
	lua_setfield(ulua.L, -2, "input");


	// call function
	i = lua_pcall(ulua.L, 1, 3, 0);
	if (i != 0) {
		fprintf(stderr,"%s\n", lua_tostring(ulua.L, -1));
		lua_pop(ulua.L, 1);
		return -1 ;
	}

	fprintf(stderr,"%d %s %s %s\n",i,lua_typename(ulua.L, lua_type(ulua.L, -3)), lua_typename(ulua.L, lua_type(ulua.L, -2)) ,  lua_typename(ulua.L, lua_type(ulua.L, -1)));

	// send status
	if (lua_type(ulua.L, -3) == LUA_TSTRING || lua_type(ulua.L, -3) == LUA_TNUMBER) {
		http = lua_tolstring(ulua.L, -3, &slen);
		if (write(wsgi_req->poll.fd, "HTTP/1.1 ", 9) != 9) {
			perror("write()");
			return -1 ;
		}
		if (write(wsgi_req->poll.fd, http, slen) != slen) {
			perror("write()");
			return -1 ;
		}
		if (write(wsgi_req->poll.fd, "\r\n", 2) != 2) {
			perror("write()");
			return -1 ;
		}
	}
	
	// send headers

	lua_pushnil(ulua.L);
        while(lua_next(ulua.L, -3) != 0) {
		http = lua_tolstring(ulua.L, -2, &slen);
		if (write(wsgi_req->poll.fd, http, slen) != slen) {
			perror("write()");
			return -1 ;
		}
		if (write(wsgi_req->poll.fd, ": ", 2) != 2) {
			perror("write()");
			return -1 ;
		}
		http = lua_tolstring(ulua.L, -1, &slen);
		if (write(wsgi_req->poll.fd, http, slen) != slen) {
			perror("write()");
			return -1 ;
		}
		if (write(wsgi_req->poll.fd, "\r\n", 2) != 2) {
			perror("write()");
			return -1 ;
		}
                lua_pop(ulua.L, 1);
        }

	if (write(wsgi_req->poll.fd, "\r\n", 2) != 2) {
		perror("write()");
		return -1 ;
	}
	
	// send body with coroutine
	lua_pushvalue(ulua.L, -1);

        while ( (i = lua_pcall(ulua.L, 0, 1, 0)) == 0) {
                if (lua_type(ulua.L, -1) == LUA_TSTRING) {
			http = lua_tolstring(ulua.L, -1, &slen);
			if (write(wsgi_req->poll.fd, http, slen) != slen) {
				perror("write()");
				return -1 ;
			}
			//fprintf(stderr,"%.*s\n", slen, http);
                }
                lua_pop(ulua.L, 1);
                lua_pushvalue(ulua.L, -1);
        }

        lua_pop(ulua.L, 4);

	return 0;

}

void uwsgi_after_request(struct uwsgi_server *uwsgi, struct wsgi_request *wsgi_req) {

	if (uwsgi->shared->options[UWSGI_OPTION_LOGGING])
                log_request(wsgi_req);
}
