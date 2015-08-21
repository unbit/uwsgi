#include <uwsgi.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#if LUA_VERSION_NUM < 502
# define ulua_pushapi luaL_register
# define lua_rawlen lua_objlen
#else
# define ulua_pushapi(L,key,api) lua_newtable(L);luaL_setfuncs(L,api,0);lua_pushvalue(L,-1);lua_setglobal(L,key)
#endif

extern struct uwsgi_server uwsgi;

struct uwsgi_lua {
	struct lua_State ***state;
	uint8_t shell;
	uint8_t shell_oneshot;
	struct uwsgi_string_list *load;
	char *wsapi;
	struct uwsgi_string_list *postload;
	int gc_freq;
	int gc_full;
} ulua;

#define ULUA_MYWID (uwsgi.mywid-1)
#define ULUA_WORKER_STATE ulua.state[ULUA_MYWID]
#define ULUA_LOG_HEADER "[uwsgi-lua]"

#define ULUA_WSAPI_REF 1
#define ULUA_RPC_REF 2
#define ULUA_SIGNAL_REF 3

#define ULUA_METRIC_INC 1
#define ULUA_METRIC_DIV 2
#define ULUA_METRIC_MUL 3
#define ULUA_METRIC_DEC 4

#define ulua_log(c, ar...) uwsgi_log(ULUA_LOG_HEADER" "c"\n", ##ar)

#define ULUA_WORKER_ANYAPP (ulua.wsapi ||\
	ulua.load ||\
	ulua.postload ||\
	ulua.shell ||\
	ulua.shell_oneshot)

struct uwsgi_plugin lua_plugin;

static void uwsgi_opt_luashell(char *opt, char *value, void *foobar) {
	uwsgi.honour_stdin = 1;
	ulua.shell = 1;
}

static void uwsgi_opt_luashell_oneshot(char *opt, char *value, void *foobar) {
	// enable shell
	uwsgi_opt_luashell(NULL, NULL, NULL);
	
	ulua.shell_oneshot = 1;
}

static struct uwsgi_option uwsgi_lua_options[] = {

	{"lua", required_argument, 0, "load lua wsapi app", uwsgi_opt_set_str, &ulua.wsapi, 0},
	{"lua-load", required_argument, 0, "load a lua file before wsapi app", uwsgi_opt_add_string_list, &ulua.load, 0},
	{"lua-postload", required_argument, 0, "load a lua file after wsapi app", uwsgi_opt_add_string_list, &ulua.postload, 0},
	{"lua-shell", no_argument, 0, "run the lua interactive shell (debug.debug())", uwsgi_opt_luashell, NULL, 0},
	{"luashell", no_argument, 0, "run the lua interactive shell (debug.debug())", uwsgi_opt_luashell, NULL, 0},
	{"lua-shell-oneshot", no_argument, 0, "run the lua interactive shell (debug.debug(), one-shot variant)", uwsgi_opt_luashell_oneshot, NULL, 0},
	{"luashell-oneshot", no_argument, 0, "run the lua interactive shell (debug.debug(), one-shot variant)", uwsgi_opt_luashell_oneshot, NULL, 0},
	{"lua-gc-freq", required_argument, 0, "set the lua gc frequency (default: 1, runs after every request)", uwsgi_opt_set_int, &ulua.gc_freq, 0},
	{"lua-gc-full", no_argument, 0, "set the lua gc to perform a full garbage-collection cycle (default: 0, gc performs an incremental step of garbage collection)", uwsgi_opt_set_int, &ulua.gc_full, 0},

	{0, 0, 0, 0},

};

static int uwsgi_lua_metatable_tostring(lua_State *L, int obj) {
	// replace table with __tostring result, or do nothing in case of fail
	
	if (!(luaL_getmetafield(L, obj, "__tostring"))) {
		return 0;
	}
	
	if (!(lua_isfunction(L, -1))) {
		ulua_log("__tostring is not a function");
		lua_pop(L, 1);
		return 0;
	}
	
	lua_pushvalue(L, --obj);
		
	if (lua_pcall(L, 1, 1, 0)) {
		ulua_log("%s", lua_tostring(L, -1));
		lua_pop(L, 1);
		return 0;
	}
	
	if (lua_isstring(L, -1)) {
		lua_replace(L, obj);
		return 1;
	}
	
	lua_pop(L, 1);
	
	return 0;
}


static int uwsgi_lua_metatable_call(lua_State *L, int obj) {
	// get __call attr and place it before table, or do nothing in case of fail

	if (!(luaL_getmetafield(L, obj, "__call"))) {
		return 0;
	}
	
	if (!(lua_isfunction(L, -1))) {
		ulua_log("__call is not a function");
		lua_pop(L, 1);
		return 0;
	}
	
	lua_insert(L, obj-1);
	
	return 1;
}

static int uwsgi_api_metric_get(lua_State *L) {
	
	if (!(lua_gettop(L)) || !(lua_isstring(L, 1))) {
		return 0;
	}

	lua_pushnumber(L, uwsgi_metric_get((char *) lua_tostring(L, 1), NULL));
	
	return 1;
}

static int uwsgi_api_metric_set(lua_State *L) {
	
	if ((lua_gettop(L) < 2) || 
		!(lua_isstring(L, 1)) || 
		!(lua_isnumber(L, 2)) ||
		uwsgi_metric_set((char *) lua_tostring(L, 1), NULL, lua_tonumber(L, 2)))
	{
		return 0;
	}
	
	lua_pushboolean(L, 1);
	
	return 1;
}

static int uwsgi_lua_metric_op(lua_State *L, uint8_t op) {
	int64_t value = 1;
	uint8_t argc = lua_gettop(L);
	
	int code = -1;
	char *name;
	
	if (!(argc) || !(lua_isstring(L, 1))) {
		return 0;
	}
	
	if (argc > 1 && lua_isnumber(L, 2)) {
		value = lua_tonumber(L, 2);
	}
	
	name = (char *) lua_tostring(L, 1);
	
	switch(op) {
		case ULUA_METRIC_INC: code = uwsgi_metric_inc(name, NULL, value); break;
		case ULUA_METRIC_DIV: code = uwsgi_metric_div(name, NULL, value); break;
		case ULUA_METRIC_MUL: code = uwsgi_metric_mul(name, NULL, value); break;
		case ULUA_METRIC_DEC: code = uwsgi_metric_dec(name, NULL, value); break;
	}
	
	if (code) {
		return 0;
	}
	
	lua_pushboolean(L, 1);
	
	return 1;
}

static int uwsgi_api_metric_inc(lua_State *L) {
	return uwsgi_lua_metric_op(L, ULUA_METRIC_INC);
}

static int uwsgi_api_metric_div(lua_State *L) {
	return uwsgi_lua_metric_op(L, ULUA_METRIC_DIV);
}

static int uwsgi_api_metric_mul(lua_State *L) {
	return uwsgi_lua_metric_op(L, ULUA_METRIC_MUL);
}

static int uwsgi_api_metric_dec(lua_State *L) {
	return uwsgi_lua_metric_op(L, ULUA_METRIC_DEC);
}


static int uwsgi_api_signal(lua_State *L) {
	uint8_t argc = lua_gettop(L);

	if (argc > 0 && lua_isnumber(L, 1)) {
		if (argc > 1 && lua_isstring(L, 2)) {
			lua_pushnumber(L, uwsgi_remote_signal_send((char *) lua_tostring(L, -2), (uint8_t) lua_tonumber(L, 1)));
			
			return 1;
		} else {
			uwsgi_signal_send(uwsgi.signal_socket, (uint8_t) lua_tonumber(L, 1));
		}
	}

	return 0;
}

static int uwsgi_api_log(lua_State *L) {
	uint8_t argc = lua_gettop(L);
	uint8_t i;
	unsigned long point;
	int type;
	
	if (!(argc)) {
		return 0;
	}
	
	uwsgi_log(ULUA_LOG_HEADER);
	
	for(i = 1; i <= argc; i++) {
		type = lua_type(L, i);
		
		switch(type) {
			case LUA_TNIL: uwsgi_log(" nil"); continue;
			
			case LUA_TBOOLEAN: uwsgi_log(lua_toboolean(L, i) ? " true" : " false"); continue;
			
			case LUA_TTABLE: if(!(uwsgi_lua_metatable_tostring(L, i - argc - 1))) break;
			case LUA_TSTRING:
			case LUA_TNUMBER: uwsgi_log(" %s", lua_tostring(L, i)); continue;			
		}
		
		point = (unsigned long) (lua_topointer(L, i));
		
		if (point) {
			uwsgi_log(" %s: 0x%.8x", lua_typename(L, type), point);
		} else {
			uwsgi_log(" %s", lua_typename(L, type));
		}
	}

	uwsgi_log("\n");
	
	return 0;
}

static int uwsgi_api_rpc(lua_State *L) {
	
	uint8_t argc = lua_gettop(L);
	uint8_t argnum;
	uint8_t i;
	uint64_t len;
	
	if (argc < 2) {
		return 0;
	}
	
	argnum = argc - 2;
	
	char **argv = NULL;
	uint16_t *argvs = NULL;
		
	if (argnum > 0) {
		argv = (char **) uwsgi_malloc(sizeof(char *)*argnum);
		argvs = (uint16_t *) uwsgi_malloc(sizeof(uint16_t)*argnum);
		
		for(i = 0; i < argnum; i++) {	
			switch(lua_type(L, i + 3)) {
				case LUA_TTABLE: if(!(uwsgi_lua_metatable_tostring(L, i + 2 - argc))) break;
				case LUA_TSTRING:
				case LUA_TNUMBER: argv[i] = (char *) lua_tolstring(L, i + 3, (size_t *) &argvs[i]); continue;
			}
			
			// default
			argv[i] = NULL; 
			argvs[i] = 0;
		}
	}
	
	char *str = uwsgi_do_rpc((char *) lua_tostring(L, 1), (char *) lua_tostring(L, 2), argnum, argv, argvs, &len);
	
	if (!(len)) { // fail??
		lua_pushnil(L);
	} else {
		lua_pushlstring(L, str, len);
	}
	
	if (argc > 0) {
		free(argv);
		free(argvs);
	}

	free(str);
	
	return 1;
}

static int uwsgi_api_rpc_register_key(const char *key, size_t len) {

	// exists??
	size_t i;
	int offset = uwsgi.mywid * uwsgi.rpc_max;
	
	for(i = 0; i < uwsgi.shared->rpc_count[uwsgi.mywid]; i++) {
		if (!strcmp(key, (&uwsgi.rpc_table[offset + i])->name)) {
			if ((&uwsgi.rpc_table[offset + i])->plugin == &lua_plugin) {
				return 1;
			}
			
			break;
		}
	}
	
	// no
	char *name = (char *) uwsgi_malloc(sizeof(char) * len);
	
	memcpy(name, key, sizeof(char) * len);
	
	if (uwsgi_register_rpc(name, &lua_plugin, 0, name)) {
		// error
		free(name);
		return 0;
	} 

	return 1;
}

static int uwsgi_api_register_rpc(lua_State *L) {
	// legacy rpc register func

	uint8_t argc = lua_gettop(L);
	
	if (argc < 2) {
		lua_pushnil(L);
		return 1;
	}
	
	lua_rawgeti(L, LUA_REGISTRYINDEX, ULUA_RPC_REF);
	
	lua_pushvalue(L, 1);
	lua_pushvalue(L, 2);
	
	lua_settable(L, -3);
	
	lua_pushvalue(L, 1);
	lua_rawget(L, -2);
	
	if (!(lua_isnil(L, -1))) {
		lua_pushboolean(L, 1);
	}
	
	return 1;
}

static int uwsgi_api_register_rpc_newindex(lua_State *L) {
	// 3 args: table, key(string or number), value(not nil)
	
	uint8_t argc = lua_gettop(L);
	size_t len;
	
	if (argc != 3) {
		return 0;
	}
	
	const char *key = lua_tolstring(L, -2, &len);

	if (len && !(lua_isnil(L, -1)) && uwsgi_api_rpc_register_key(key, len + 1)) {
		lua_rawset(L, -3);
	}
	
	return 0;
}

static int uwsgi_lua_cache_set(lua_State *L, uint8_t flag) {
	
	uint8_t argc = lua_gettop(L);
	
	char *cache = NULL;
	uint64_t expires = 0;
	
	char *key;
	size_t keylen;
	
	char *value = NULL;
	size_t valuelen = 0;
	
	if (argc < 2) {
		return 0;
	}
	
	// key
	key = (char *) lua_tolstring(L, 1, &keylen);
	
	// value
	switch(lua_type(L, 2)) {
		case LUA_TTABLE: if(!(uwsgi_lua_metatable_tostring(L, -argc + 1))) break;
		case LUA_TSTRING:
		case LUA_TNUMBER: value = (char *) lua_tolstring(L, 2, &valuelen);
	}
	
	if (argc > 2) {
		expires = lua_tonumber(L, 3);
		if (argc > 3) {
			cache = (char *) lua_tostring(L, 4);
		}
	}
	
	if (!uwsgi_cache_magic_set(key, keylen, value, valuelen, expires, flag, cache)) {
		lua_pushboolean(L, 1);
		return 1;
	}
	
	return 0;
}

static int uwsgi_api_cache_set(lua_State *L) {
	return uwsgi_lua_cache_set(L, 0);
}

static int uwsgi_api_cache_update(lua_State *L) {
	return uwsgi_lua_cache_set(L, UWSGI_CACHE_FLAG_UPDATE);
}

static int uwsgi_lua_cache_set_table(lua_State *L, uint8_t flag) {
	
	uint8_t argc = lua_gettop(L);
	uint8_t error = 0;
	
	char *cache = NULL;
	uint64_t expires = 0;
	
	char *key;
	size_t keylen;
	
	char *value = NULL;
	size_t valuelen = 0;
	
	if (argc < 1 || !lua_istable(L, 1)) {
		return 0;
	}
	
	if (argc > 1) {
		expires = lua_tonumber(L, 2);
		if (argc > 2) {
			cache = (char *) lua_tostring(L, 3);
		}
	}
	
	lua_pushnil(L);
	
	while(lua_next(L, 1)) {
		lua_pushvalue(L, -2);
		
		//key
		key = (char *) lua_tolstring(L, -1, &keylen);
		
		//value
		switch(lua_type(L, -2)) {
			case LUA_TTABLE: if(!(uwsgi_lua_metatable_tostring(L, -2))) break;
			case LUA_TSTRING:
			case LUA_TNUMBER: value = (char *) lua_tolstring(L, -2, &valuelen);
		}
		
		if (uwsgi_cache_magic_set(key, keylen, value, valuelen, expires, flag, cache)) {
			lua_pop(L, 2);
			lua_pushvalue(L, -1);
			++error;
		} else {
			lua_pop(L, 2);
		}
	}
	
	if (!error) {
		lua_pushboolean(L, 1);
		return 1;
	}
	
	lua_pushnumber(L, error);
	lua_insert(L, -(++error));
	
	lua_pushnil(L);
	lua_insert(L, -(++error));

	return error;
	
}

static int uwsgi_api_cache_set_table(lua_State *L) {
	return uwsgi_lua_cache_set_table(L, 0);
}

static int uwsgi_api_cache_update_table(lua_State *L) {
	return uwsgi_lua_cache_set_table(L, UWSGI_CACHE_FLAG_UPDATE);
}


static int uwsgi_lua_cache_set_multi(lua_State *L, uint8_t flag) {
	
	uint8_t argc = lua_gettop(L);
	uint8_t error = 0;
	uint8_t i;
	
	char *cache;
	uint64_t expires;
	
	char *key;
	size_t keylen;
	
	char *value = NULL;
	size_t valuelen = 0;
	
	if (argc < 4) {
		return 0;
	}
	
	expires = lua_tonumber(L, 1);
	cache = (char *) lua_tostring(L, 2);
	
	for (i = 4; i <= argc; i+=2) {
		// key
		key = (char *) lua_tolstring(L, i - 1, &keylen);
	
		// value
		switch(lua_type(L, i)) {
			case LUA_TTABLE: if(!(uwsgi_lua_metatable_tostring(L, i - argc - 1 - error))) break;
			case LUA_TSTRING:
			case LUA_TNUMBER: value = (char *) lua_tolstring(L, i, &valuelen);
		}
		
		if (uwsgi_cache_magic_set(key, keylen, value, valuelen, expires, flag, cache)) {
			++error;
			lua_pushnumber(L, (i/2) - 1);
		}
	}	
	
	if(!error) {
		lua_pushboolean(L, 1);
		return 1;
	}
	
	lua_pushnumber(L, error);
	lua_insert(L, -(++error));
	
	lua_pushnil(L);
	lua_insert(L, -(++error));

	return error;
}

static int uwsgi_api_cache_set_multi(lua_State *L) {
	return uwsgi_lua_cache_set_multi(L, 0);
}

static int uwsgi_api_cache_update_multi(lua_State *L) {
	return uwsgi_lua_cache_set_multi(L, UWSGI_CACHE_FLAG_UPDATE);
}


static int uwsgi_api_cache_clear(lua_State *L) {

	char *cache = NULL;
	uint8_t argc = lua_gettop(L);

	if (argc > 0) {
		cache = (char *) lua_tostring(L, 1);
	}
	
	if (!uwsgi_cache_magic_clear(cache)) {
		lua_pushboolean(L, 1);
		return 1;
	}

	return 0;
}


static int uwsgi_api_cache_del(lua_State *L) {

	size_t keylen;
	char *key;
	char *cache = NULL;
	uint8_t argc = lua_gettop(L);

	if (!(argc)) {
		return 0;
	}

	// get the key
	key = (char *) lua_tolstring(L, 1, &keylen);
	
	if (argc > 1) {
		cache = (char *) lua_tostring(L, 2);
	}
				
	if (keylen && !uwsgi_cache_magic_del(key, keylen, cache)) {
		lua_pushboolean(L, 1);
		return 1;
	}
	
	return 0;
}

static int uwsgi_api_cache_del_multi(lua_State *L) {
	
	size_t keylen;
	char *key;
	char *cache;
	uint8_t argc = lua_gettop(L);
	uint8_t error = 0;
	uint8_t i;
	
	if (argc < 1) {
		return 0;
	}
	
	cache = (char *) lua_tostring(L, 1);
	
	for (i = 2; i <= argc; i++) {
		key = (char *) lua_tolstring(L, i, &keylen);
		
		if (!keylen || uwsgi_cache_magic_del(key, keylen, cache)) {
			++error;
			lua_pushnumber(L, i - 1);
		}
	}
	
	if (!error) {
		lua_pushboolean(L, 1);
		return 1;
	}
	
	lua_pushnumber(L, error);
	lua_insert(L, -(++error));
	
	lua_pushnil(L);
	lua_insert(L, -(++error));

	return error;
	
	return error;
}

static int uwsgi_api_cache_exists(lua_State *L) {

	size_t keylen;
	char *key;
	char *cache = NULL;
	uint8_t argc = lua_gettop(L);

	if (argc < 1) {
		return 0;
	}

	// get the key
	key = (char *) lua_tolstring(L, 1, &keylen);
	
	if (argc > 1) {
		cache = (char *) lua_tostring(L, 2);
	}

	lua_pushboolean(L, keylen && uwsgi_cache_magic_exists(key, keylen, cache));

	return 1;
}

static int uwsgi_api_cache_exists_multi(lua_State *L) {

	size_t keylen;
	char *key;
	char *cache;
	uint8_t argc = lua_gettop(L);
	uint8_t i;
	
	if (argc < 2) {
		return 0;
	}

	cache = (char *) lua_tostring(L, 1);
	
	for (i = 2; i <= argc; i++) {
	
		key = (char *) lua_tolstring(L, i, &keylen);
		lua_pushboolean(L, keylen && uwsgi_cache_magic_exists(key, keylen, cache));
		
	}

	return argc - 1;
}


static int uwsgi_api_signal_wait(lua_State *L) {

	struct wsgi_request *wsgi_req = current_wsgi_req();
	ulua_log("%d", wsgi_req);
	uint8_t args = lua_gettop(L);
	int received_signal;
	
	wsgi_req->signal_received = -1;
	
	if (args > 0 && lua_isnumber(L, 1)) {
		received_signal = uwsgi_signal_wait(wsgi_req, lua_tonumber(L, 1));
	} else {
		received_signal = uwsgi_signal_wait(wsgi_req, -1);
	}
	ulua_log("%d", received_signal);
	if (received_signal < 0) {
		lua_pushnil(L);
	} else {
		wsgi_req->signal_received = received_signal;
		lua_pushnumber(L, received_signal);
	}
	
	return 1;
}

static int uwsgi_api_signal_received(lua_State *L) {
	
	struct wsgi_request *wsgi_req = current_wsgi_req();
	
	lua_pushnumber(L, wsgi_req->signal_received);
	
	return 1;
}

static int uwsgi_api_signal_registered(lua_State *L) {
	
	uint8_t args = lua_gettop(L);
	struct uwsgi_signal_entry *use;
	uint8_t sig;
	
	if (args < 1 || !(lua_isnumber(L, 1))) {
		return 0;
	}
	
	sig = (uint8_t) lua_tonumber(L, 1);
	use = &uwsgi.shared->signal_table[sig];
	
	lua_pushboolean(L, use->handler ? 1 : 0);
	lua_pushstring(L, use->receiver);
		
	if (uwsgi.mywid > 0) {
		use = &uwsgi.shared->signal_table[sig + uwsgi.mywid*256];
	}
		
	lua_pushnumber(L, use->modifier1);

	return 3;
}

static int uwsgi_api_register_signal(lua_State *L) {

	uint8_t args = lua_gettop(L);
	uint8_t sig;
	struct uwsgi_signal_entry *use;
	const char *who;
	size_t len;
	int i;
	
	if(!(uwsgi.master_process)) {
		ulua_log("no master, no signals");
		return 0;
	}

	if (args < 1 || !(lua_isnumber(L, 1))) {
		return 0;
	}	
	
	sig = (uint8_t) lua_tonumber(L, 1);
	who = lua_tolstring(L, 2, &len);
	use = &uwsgi.shared->signal_table[sig];
		
	if (!len) {
		who = (const char *) &len; // len is zero anyway
	} else if (len > 63) {
		ulua_log("receiver is too long: %s", who);
		return 0;
	}
	
	if (use->handler && use->modifier1 != 6) {
		ulua_log("signal %s has already been taken, but not by lua-plugin", sig);
	}
	
	// register signal's receiver on master
	// copy handlers and modifiers if calling from mywid == 0
	if (!(use->handler) || strcmp(use->receiver, who)) {
		uwsgi_lock(uwsgi.signal_table_lock);
		
		strcpy(use->receiver, who);
			
		if (!(use->handler)) {
			use->handler = (void *) (1 /* unused */);
			use->modifier1 = 6;
			
			if (uwsgi.mywid == 0) {
				for(i = 1; i <= uwsgi.numproc; i++) {
					use = &uwsgi.shared->signal_table[sig + i*256];
					use->handler = (void *) (1 /* unused */);
					use->modifier1 = 6;
				}
			}
		}
		
		uwsgi_unlock(uwsgi.signal_table_lock);
	} 
	
	// worker, just register handler and modifier1
	if (uwsgi.mywid > 0) {
		use = &uwsgi.shared->signal_table[sig + uwsgi.mywid*256];
	
		if (use->modifier1 != 6) {
			uwsgi_lock(uwsgi.signal_table_lock);
			
			use->handler = (void *) (1 /* unused */);
			use->modifier1 = 6;
			
			uwsgi_unlock(uwsgi.signal_table_lock);
		}
	}	
	
	if (args > 2) {
		lua_rawgeti(L, LUA_REGISTRYINDEX, ULUA_SIGNAL_REF);
			
		lua_pushvalue(L, 3);
		lua_rawseti(L, -2, sig);
	}
	
	ulua_log("signum %d registered (by wid %d, target: %s)", sig, uwsgi.mywid, len ? who : "default");
	
	lua_pushboolean(L, 1);
	return 1;
}

static int uwsgi_api_add_file_monitor(lua_State *L) {
	uint8_t args = lua_gettop(L);
	uint8_t sig;
	const char *file;
	size_t len;
	
	if (args < 2 || !(lua_isnumber(L, 1))) {
		return 0;
	}
	
	sig = (uint8_t) lua_tonumber(L, 1);
	file = lua_tolstring(L, 2, &len);
	
	if (!len) {
		return 0;
	}
	
	if (!(uwsgi_add_file_monitor(sig, (char *) file))) {
		lua_pushboolean(L, 1);
		return 1;
	}
	
	return 0;

}

static int uwsgi_api_signal_add_timer(lua_State *L) {
	uint8_t args = lua_gettop(L);
	uint8_t sig;
	int secs;
	
	if (args < 2 || !(lua_isnumber(L, 1) && lua_isnumber(L, 2))) {
		return 0;
	}
	
	sig = (uint8_t) lua_tonumber(L, 1);
	secs = lua_tonumber(L, 2);
	
	if (!(uwsgi_add_timer(sig, secs))) {
		lua_pushboolean(L, 1);
		return 1;
	}

	return 0;
}

static int uwsgi_api_signal_add_rb_timer(lua_State *L) {
	uint8_t args = lua_gettop(L);
	uint8_t sig;
	int secs, itrs;
	
	if (args < 3 || !(lua_isnumber(L, 1) && lua_isnumber(L, 2) && lua_isnumber(L, 3))) {
		return 0;
	}
	
	sig = (uint8_t) lua_tonumber(L, 1);
	secs = lua_tonumber(L, 2);
	itrs = lua_tonumber(L, 3);
	
	if (!(uwsgi_signal_add_rb_timer(sig, secs, itrs))) {
		lua_pushboolean(L, 1);
		return 1;
	}

	return 0;
}

static int uwsgi_api_signal_add_cron(lua_State *L) {
	int date[] = {-1, -1, -1, -1, -1};
	uint8_t args = lua_gettop(L);
	int i;
	
	if (args < 1 || !(lua_isnumber(L, 1))) {
		return 0;
	}
	
	if (args > 6) args = 6;
	
	for (i = 2; i <= args; i++) {
		if (lua_isnumber(L, i)) {
			date[i-2] = lua_tonumber(L, i);
		}
	}
	
	if (!(uwsgi_signal_add_cron((uint8_t) lua_tonumber(L, 1),
		date[0], date[1], date[2], date[3], date[4]))) 
	{
		lua_pushboolean(L, 1);
		return 1;
	}
	
	return 0;
}

static int uwsgi_api_alarm(lua_State *L) {
	uint8_t args = lua_gettop(L);
	const char *msg;
	size_t len;
	
	if (args < 2 || !(lua_isstring(L, 1) && lua_isstring(L, 2))) {
		return 0;
	}
	
	msg = lua_tolstring(L, 2, &len);
	
	uwsgi_alarm_trigger((char *) lua_tostring(L, 1), (char *) msg, len);	
	
	return 0;
}


static int uwsgi_api_async_sleep(lua_State *L) {
	uint8_t argc = lua_gettop(L);
        if (argc == 0) goto end;

        struct wsgi_request *wsgi_req = current_wsgi_req();

        int timeout = lua_tonumber(L, 1);

        if (timeout >= 0) {
                async_add_timeout(wsgi_req, timeout);
        }
end:
	lua_pushnil(L);
        return 1;
}

static int uwsgi_api_wait_fd_read(lua_State *L) {
        uint8_t argc = lua_gettop(L);
        if (argc == 0) goto end;

        struct wsgi_request *wsgi_req = current_wsgi_req();

	int fd = lua_tonumber(L, 1);
	int timeout = 0;
	if (argc > 1) {
        	timeout = lua_tonumber(L, 2);
	}

	if (async_add_fd_read(wsgi_req, fd, timeout)) {
		lua_pushstring(L, "unable to call async_add_fd_read()");
        	lua_error(L);
        	return 0;
        }
end:
        lua_pushnil(L);
        return 1;
}

static int uwsgi_api_wait_fd_write(lua_State *L) {
        uint8_t argc = lua_gettop(L);
        if (argc == 0) goto end;

        struct wsgi_request *wsgi_req = current_wsgi_req();

        int fd = lua_tonumber(L, 1);
        int timeout = 0;
        if (argc > 1) {
                timeout = lua_tonumber(L, 2);
        }

        if (async_add_fd_write(wsgi_req, fd, timeout)) {
                lua_pushstring(L, "unable to call async_add_fd_write()");
                lua_error(L);
                return 0;
        }
end:
        lua_pushnil(L);
        return 1;
}

static int uwsgi_api_async_connect(lua_State *L) {
        uint8_t argc = lua_gettop(L);
        if (argc == 0) goto end;

	int fd = uwsgi_connect((char *)lua_tostring(L, 1), 0, 1);
	lua_pushnumber(L, fd);
	return 1;
end:
        lua_pushnil(L);
        return 1;
}

static int uwsgi_api_is_connected(lua_State *L) {
        uint8_t argc = lua_gettop(L);
        if (argc == 0) goto end;
	int fd = lua_tonumber(L, 1);
	if (uwsgi_is_connected(fd)) {
		lua_pushboolean(L, 1);
		return 1;
	}
	lua_pushboolean(L, 0);
        return 1;
end:
        lua_pushnil(L);
        return 1;
}

static int uwsgi_api_close(lua_State *L) {
        uint8_t argc = lua_gettop(L);
        if (argc == 0) goto end;
        int fd = lua_tonumber(L, 1);
	close(fd);
end:
        lua_pushnil(L);
        return 1;
}


static int uwsgi_api_ready_fd(lua_State *L) {
	struct wsgi_request *wsgi_req = current_wsgi_req();
        int fd = uwsgi_ready_fd(wsgi_req);
        lua_pushnumber(L, fd);
        return 1;
}

static int uwsgi_api_websocket_handshake(lua_State *L) {
	uint8_t argc = lua_gettop(L);

	const char *key = NULL, *origin = NULL, *proto = NULL;
	size_t key_len = 0, origin_len = 0, proto_len = 0;
		
	if (argc > 0) {
		key = lua_tolstring(L, 1, &key_len);
		if (argc > 1) {
			origin = lua_tolstring(L, 2, &origin_len);
			if (argc > 2) {
				proto = lua_tolstring(L, 3, &proto_len);
			}
		}
	}

	struct wsgi_request *wsgi_req = current_wsgi_req();
	if (uwsgi_websocket_handshake(wsgi_req, (char *)key, key_len, (char *)origin, origin_len, (char *) proto, proto_len)) {
		goto error;
	}	

	lua_pushnil(L);
        return 1;

error:
	lua_pushstring(L, "unable to complete websocket handshake");
	lua_error(L);
	return 0;	
}

static int uwsgi_api_websocket_send(lua_State *L) {
	uint8_t argc = lua_gettop(L);
        if (argc == 0) goto error;

	size_t message_len = 0;
	const char *message = lua_tolstring(L, 1, &message_len);
	struct wsgi_request *wsgi_req = current_wsgi_req();

        if (uwsgi_websocket_send(wsgi_req, (char *) message, message_len)) {
		goto error;
        }
	lua_pushnil(L);
        return 1;
error:
        lua_pushstring(L, "unable to send websocket message");    
        lua_error(L);
        return 0;
}

static int uwsgi_api_websocket_send_binary(lua_State *L) {
        uint8_t argc = lua_gettop(L);
        if (argc == 0) goto error;

        size_t message_len = 0;
        const char *message = lua_tolstring(L, 1, &message_len);
        struct wsgi_request *wsgi_req = current_wsgi_req();

        if (uwsgi_websocket_send_binary(wsgi_req, (char *) message, message_len)) {
                goto error;
        }
	lua_pushnil(L);
        return 1;
error:
        lua_pushstring(L, "unable to send websocket binary message");      
        lua_error(L);
        return 0;
}

static int uwsgi_api_websocket_send_from_sharedarea(lua_State *L) {
        uint8_t argc = lua_gettop(L);
        if (argc < 2) goto error;

	int id = lua_tonumber(L, 1);
	uint64_t pos = lua_tonumber(L, 2);
	uint64_t len = 0;
	if (argc > 2) {
		len = lua_tonumber(L, 3);
	}
        struct wsgi_request *wsgi_req = current_wsgi_req();

	if (uwsgi_websocket_send_from_sharedarea(wsgi_req, id, pos, len)) {
                goto error;
        }
	lua_pushnil(L);
        return 1;
error:
        lua_pushstring(L, "unable to send websocket message from sharedarea");      
        lua_error(L);
        return 0;
}

static int uwsgi_api_websocket_send_binary_from_sharedarea(lua_State *L) {
        uint8_t argc = lua_gettop(L);
        if (argc < 2) goto error;

        int id = lua_tonumber(L, 1);
        uint64_t pos = lua_tonumber(L, 2);
        uint64_t len = 0;
        if (argc > 2) {
                len = lua_tonumber(L, 3);
        }
        struct wsgi_request *wsgi_req = current_wsgi_req();

        if (uwsgi_websocket_send_binary_from_sharedarea(wsgi_req, id, pos, len)) {
                goto error;
        }
        lua_pushnil(L);
        return 1;
error:
        lua_pushstring(L, "unable to send websocket message from sharedarea");
        lua_error(L);
        return 0;
}

static int uwsgi_api_websocket_recv(lua_State *L) {
	struct wsgi_request *wsgi_req = current_wsgi_req();
        struct uwsgi_buffer *ub = uwsgi_websocket_recv(wsgi_req);
	if (!ub) {
        	lua_pushstring(L, "unable to receive websocket message");
        	lua_error(L);
        	return 0;
	}
	lua_pushlstring(L, ub->buf, ub->pos);
	uwsgi_buffer_destroy(ub);
	return 1;
}

static int uwsgi_api_websocket_recv_nb(lua_State *L) {
        struct wsgi_request *wsgi_req = current_wsgi_req();
        struct uwsgi_buffer *ub = uwsgi_websocket_recv_nb(wsgi_req);
        if (!ub) {
                lua_pushstring(L, "unable to receive websocket message");
                lua_error(L);
                return 0;
        }
        lua_pushlstring(L, ub->buf, ub->pos);
        uwsgi_buffer_destroy(ub);
        return 1;
}

static int uwsgi_api_cache_get(lua_State *L) {

	char *value;
	uint64_t valsize;
	size_t keylen;
	char *key;
	char *cache = NULL;
	uint8_t argc = lua_gettop(L);

	if (argc == 0) goto error;

	// get the key
	key = (char *) lua_tolstring(L, 1, &keylen);
		
	if (argc > 1) {
		cache = (char *) lua_tostring(L, 2);
	}
	
	if (!keylen) goto error;
	
	value = uwsgi_cache_magic_get(key, keylen, &valsize, NULL, cache);
	
	if (value) {
		lua_pushlstring(L, value, valsize);
		free(value);
		return 1;
	}

error:
	lua_pushnil(L);
	return 1;

}

static int uwsgi_api_cache_get_multi(lua_State *L) {

	char *value ;
	uint64_t valsize;
	size_t keylen;
	char *key;
	char *cache;
	
	uint8_t argc = lua_gettop(L);
	uint8_t i;
	
	if (argc < 2) {
		return 0;
	}
	
	cache = (char *) lua_tostring(L, 1);
	
	for (i = 2; i <= argc; i++) {
	
		value = NULL;
		key = (char *) lua_tolstring(L, i, &keylen);
		
		if (keylen) {
			value = uwsgi_cache_magic_get(key, keylen, &valsize, NULL, cache);
		}
		
		if (value) {
			lua_pushlstring(L, value, valsize);
			free(value);
		} else {
			lua_pushnil(L);
		}
	}

	return argc - 1;
}

static int uwsgi_api_req_fd(lua_State *L) {

	struct wsgi_request *wsgi_req = current_wsgi_req();
	
	lua_pushnumber(L, wsgi_req->fd);
	return 1;
}

static int uwsgi_api_lock(lua_State *L) {

	int lock_num = 0;

	// the spooler cannot lock resources
	if (uwsgi.i_am_a_spooler) {
		lua_pushstring(L, "The spooler cannot lock/unlock resources");
		lua_error(L);
	}

	if (lua_gettop(L) > 0) {
		lock_num = lua_isnumber(L, 1) ? lua_tonumber(L, 1) : -1;
		if (lock_num < 0 || lock_num > uwsgi.locks) {
			lua_pushstring(L, "Invalid lock number");
	    		lua_error(L);
	  	}
	}
	
	uwsgi_lock(uwsgi.user_lock[lock_num]);

	return 0;
}


static int uwsgi_api_unlock(lua_State *L) {

	int lock_num = 0;

	// the spooler cannot lock resources
	if (uwsgi.i_am_a_spooler) {
		lua_pushstring(L, "The spooler cannot lock/unlock resources");
		lua_error(L);
	}

	if (lua_gettop(L) > 0) {
		lock_num = lua_isnumber(L, 1) ? lua_tonumber(L, 1) : -1;
		if (lock_num < 0 || lock_num > uwsgi.locks) {
			lua_pushstring(L, "Invalid lock number");
	    		lua_error(L);
	  	}
	}
	
	uwsgi_unlock(uwsgi.user_lock[lock_num]);

	return 0;
}

static int uwsgi_lua_input(lua_State *L) {

	struct wsgi_request *wsgi_req = current_wsgi_req();
	ssize_t sum = 0;

	int n = lua_gettop(L);

	if (n > 1) {
		sum = lua_tonumber(L, 2);
	}

	ssize_t rlen = 0;

        char *buf = uwsgi_request_body_read(wsgi_req, sum, &rlen);
        if (buf) {
		lua_pushlstring(L, buf, rlen);
                return 1;
        }

	return 0;
}


static int uwsgi_api_async_id_get(lua_State *L) {

	struct wsgi_request *wsgi_req = current_wsgi_req();
	
	lua_pushnumber(L, wsgi_req->async_id);
	
	return 1;
}

static int uwsgi_api_memory_usage(lua_State *L) {

	uint64_t rss = 0;
	uint64_t vsz = 0;
	
	get_memusage(&rss, &vsz);
	
	lua_pushnumber(L, rss);
	lua_pushnumber(L, vsz);
	
	return 2;
}

static int uwsgi_api_pid(lua_State *L) {
	
	int id = 0;
	
	if (lua_gettop(L) > 0) {
		id = lua_tonumber(L, 1);
	}
	
	if (id <= uwsgi.numproc) {
		lua_pushnumber(L, uwsgi.workers[id].pid);
		return 1;
	}
	
	return 0;
	
}

static const luaL_Reg uwsgi_api_worker[] = {
  {"log", uwsgi_api_log},
  {"connection_fd", uwsgi_api_req_fd},

  {"metric_get", uwsgi_api_metric_get},
  {"metric_set", uwsgi_api_metric_set},
  {"metric_inc", uwsgi_api_metric_inc},
  {"metric_div", uwsgi_api_metric_div},
  {"metric_mul", uwsgi_api_metric_mul},
  {"metric_dec", uwsgi_api_metric_dec},
  
  {"cache_get", uwsgi_api_cache_get},
  {"cache_get_multi", uwsgi_api_cache_get_multi},
  {"cache_set", uwsgi_api_cache_set},
  {"cache_set_table", uwsgi_api_cache_set_table},
  {"cache_set_multi", uwsgi_api_cache_set_multi},
  {"cache_update", uwsgi_api_cache_update},
  {"cache_update_table", uwsgi_api_cache_update_table},
  {"cache_update_multi", uwsgi_api_cache_update_multi},
  {"cache_del", uwsgi_api_cache_del},
  {"cache_del_multi", uwsgi_api_cache_del_multi},
  {"cache_exists", uwsgi_api_cache_exists},
  {"cache_exists_multi", uwsgi_api_cache_exists_multi},
  {"cache_clear", uwsgi_api_cache_clear},

  {"register_signal", uwsgi_api_register_signal},
  {"signal_registered", uwsgi_api_signal_registered},
  {"signal_wait", uwsgi_api_signal_wait},
  {"signal_received", uwsgi_api_signal_received},
  {"add_file_monitor", uwsgi_api_add_file_monitor},
  {"add_timer", uwsgi_api_signal_add_timer},
  {"add_rb_timer", uwsgi_api_signal_add_rb_timer},
  {"add_cron", uwsgi_api_signal_add_cron},
  
  {"alarm", uwsgi_api_alarm},
  
  {"register_rpc", uwsgi_api_register_rpc},

  {"rpc", uwsgi_api_rpc},
  {"signal", uwsgi_api_signal},
  
  {"req_input_read", uwsgi_lua_input},
  
  {"mem", uwsgi_api_memory_usage},
  {"pid", uwsgi_api_pid},

  {"websocket_handshake", uwsgi_api_websocket_handshake},
  {"websocket_recv", uwsgi_api_websocket_recv},
  {"websocket_recv_nb", uwsgi_api_websocket_recv_nb},
  {"websocket_send", uwsgi_api_websocket_send},
  {"websocket_send_from_sharedarea", uwsgi_api_websocket_send_from_sharedarea},
  {"websocket_send_binary", uwsgi_api_websocket_send_binary},
  {"websocket_send_binary_from_sharedarea", uwsgi_api_websocket_send_binary_from_sharedarea},

  {"lock", uwsgi_api_lock},
  {"unlock", uwsgi_api_unlock},

  {"async_sleep", uwsgi_api_async_sleep},
  {"async_connect", uwsgi_api_async_connect},
  {"async_id_get", uwsgi_api_async_id_get},
  {"is_connected", uwsgi_api_is_connected},
  {"close", uwsgi_api_close},
  {"wait_fd_read", uwsgi_api_wait_fd_read},
  {"wait_fd_write", uwsgi_api_wait_fd_write},
  {"ready_fd", uwsgi_api_ready_fd},

  {NULL, NULL}
};


static int uwsgi_lua_init(){

	if (!ULUA_WORKER_ANYAPP) {
		return 0;
	}

	int i;

	uwsgi_log(ULUA_LOG_HEADER " Initializing Lua environment... ");
	
	ulua.state = uwsgi_malloc(sizeof(lua_State**) * uwsgi.numproc);
	
	for (i=0;i<uwsgi.numproc;i++) {
		ulua.state[i] = uwsgi_malloc(sizeof(lua_State*) * uwsgi.cores);
	}
	
	uwsgi_log("%d lua_States (with %d lua_Threads)\n", uwsgi.numproc, uwsgi.cores);
	
	if(!(ulua.gc_full)) {
		ulua.gc_full = LUA_GCSTEP;
	} else {
		ulua.gc_full = LUA_GCCOLLECT;
	}
	
	// ok the lua engine is ready
	return 0;
}

static void uwsgi_lua_init_state(lua_State **Ls, int wid, int sid, int cores) {

	if (!ULUA_WORKER_ANYAPP) {
		return;
	}

	int i;
	int uslnargs;
	lua_State *L;

	// spawn worker state		
	Ls[0] = luaL_newstate();
	L = Ls[0];

	// init worker state
	luaL_openlibs(L);
	ulua_pushapi(L, "uwsgi", uwsgi_api_worker);

	lua_pushstring(L, UWSGI_VERSION);
	lua_setfield(L, -2, "version");

	lua_pushnumber(L, wid);
	lua_setfield(L, -2, "mywid");
	
	lua_pushnumber(L, sid);
	lua_setfield(L, -2, "mysid");
	
	// reserve ref 1 for ws func
	lua_pushboolean(L, 0);
	luaL_ref(L, LUA_REGISTRYINDEX);
	
	// rpc metatable ref 2
	lua_newtable(L);
	lua_createtable(L, 0, 1);
	lua_pushcfunction(L, uwsgi_api_register_rpc_newindex);
	lua_setfield(L, -2, "__newindex");
	lua_setmetatable(L, -2);
	lua_pushvalue(L, -1);
	
	luaL_ref(L, LUA_REGISTRYINDEX);
	lua_setfield(L, -2, "rpc_ref");
	
	// signal table ref 3
	lua_newtable(L);
	lua_pushvalue(L, -1);
	
	luaL_ref(L, LUA_REGISTRYINDEX);
	lua_setfield(L, -2, "signal_ref");
	
	// init main app
	uslnargs = lua_gettop(L);

	struct uwsgi_string_list *usl = ulua.load;
	
	while(usl) {
		if (luaL_dofile(L, usl->value)) {
			ulua_log("unable to load Lua file %s: %s", usl->value, lua_tostring(L, -1));
			lua_pop(L, 1);
		}
		usl = usl->next;
	}
			
	uslnargs = lua_gettop(L) - uslnargs;
			
	if (ulua.wsapi) {
		if (luaL_loadfile(L, ulua.wsapi)) {
			ulua_log("unable to load Lua file %s: %s", ulua.wsapi, lua_tostring(L, -1));
			lua_pop(L, uslnargs + 1);
			uslnargs = 0;
		} else {
			// put function before args
			if (uslnargs > 0) {
				lua_insert(L, -uslnargs - 1);
			}
		
			if (lua_pcall(L, uslnargs, 1, 0)) {
				ulua_log("%s", lua_tostring(L, -1));
				lua_pop(L, 1);
				uslnargs = 0;
			} else {
				uslnargs = 1;
			}
		}
	} else {
		lua_pop(L, uslnargs);
		uslnargs = 0;
	}
			
	// table ??
	if (uslnargs > 0 && lua_istable(L, -1)) {
		lua_pushstring(L, "run");
		lua_gettable(L, -1);
		lua_replace(L, -1);
	}
			
	// no app ???
	if (!uslnargs || !lua_isfunction(L, -1)) {
		// loading dummy
		lua_pop(L, uslnargs);	
		ulua_log("Can't find WSAPI entry point (no function, nor a table with function'run').");
	} else {
		lua_rawseti(L, LUA_REGISTRYINDEX, ULUA_WSAPI_REF);
	}
			
	//init additional threads for current worker
	if (cores > 0) {
	
		lua_createtable(L, cores - 1, 0);
				
		for(i = 1; i < cores; i++) {

			// create thread and save it
			Ls[i] = lua_newthread(L);
			lua_rawseti(L, -2, i);

		}
		
		lua_setfield(L, -2, "luathreads");
	}
			
	lua_pop(L, 1);
	
	// post load
	usl = ulua.postload;
	
	while(usl) {
		if (luaL_loadfile(L, usl->value) || lua_pcall(L, 0, 0, 0)) {
			ulua_log("unable to load Lua file %s: %s", usl->value, lua_tostring(L, -1));
			lua_pop(L, 1);
		}
		usl = usl->next;
	}
	
	// and the worker is ready!
	lua_gc(L, LUA_GCCOLLECT, 0);
}

static int uwsgi_lua_request(struct wsgi_request *wsgi_req) {

	const char *http, *http2;
	size_t i, tlen, slen, slen2;

	if(!ulua.wsapi) {
		ulua_log("No WSAPI App. skip.");
		return -1;
	}

	lua_State *L = ULUA_WORKER_STATE[wsgi_req->async_id];

	/* Standard WSAPI request */
	if (!wsgi_req->len) {
		ulua_log("Empty lua request. skip.");
		return -1;
	}
	
	if (wsgi_req->async_status == UWSGI_AGAIN) {
async_coroutine:
		while (!lua_pcall(L, 0, 1, 0)) {
			switch(lua_type(L, -1)) {
				case LUA_TNIL: // posible dead coroutine
				
					lua_pop(L, 1);
					lua_pushvalue(L, -1);
					continue; // retry
			
				case LUA_TTABLE: if(!(uwsgi_lua_metatable_tostring(L, -1))) break;
				case LUA_TSTRING:
				case LUA_TNUMBER:
				
					http = lua_tolstring(L, -1, &slen);
					uwsgi_response_write_body_do(wsgi_req, (char *)http, slen);
					
			}
			
			lua_pop(L, 1);
			lua_pushvalue(L, -1);
			return UWSGI_AGAIN;
		}
		goto clear;
	}

	if (uwsgi_parse_vars(wsgi_req)) {
		return -1;
	}

	// put function in the stack
	lua_rawgeti(L, LUA_REGISTRYINDEX, ULUA_WSAPI_REF);

	// put cgi vars in the stack
	lua_createtable(L, 0, wsgi_req->var_cnt + 2);
	
	lua_pushstring(L, "");
	lua_setfield(L, -2, "CONTENT_TYPE");
	
	for(i = 0; i < wsgi_req->var_cnt; i+=2) {
		lua_pushlstring(L, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len);
		lua_pushlstring(L, wsgi_req->hvec[i+1].iov_base, wsgi_req->hvec[i+1].iov_len);
		lua_rawset(L, -3);
	}

	// put "input" table
	lua_createtable(L, 0, 1);
	lua_pushcfunction(L, uwsgi_lua_input);
	lua_setfield(L, -2, "read");
	lua_setfield(L, -2, "input");
	

#ifdef UWSGI_DEBUG
	ulua_log("stack pos %d", lua_gettop(L));
#endif

	// call function
	if (lua_pcall(L, 1, 3, 0)) {
		ulua_log("%s", lua_tostring(L, -1));
		lua_pop(L, 1);
		goto clear2;
	}

#ifdef UWSGI_DEBUG
	ulua_log("%d %s %s %s",i,lua_typename(L, lua_type(L, -3)), lua_typename(L, lua_type(L, -2)) ,  lua_typename(L, lua_type(L, -1)));
#endif

	// send status
	http = lua_tolstring(L, -3, &slen);
	
	if (uwsgi_response_prepare_headers(wsgi_req, (char *) http, slen)) {
		ulua_log("invalid response status!!!");
		// let's continue 
	}

	// send headers
	if (lua_istable(L, -2)) {
	
		lua_pushnil(L);
		
		while(lua_next(L, -3)) {
		
			// lua_tolstring may change the 'lua_next' sequence, if the key is not a string, by modifying it
			lua_pushvalue(L, -2); 
			// so -1 is key, -2 is value
			http = lua_tolstring(L, -1, &slen);

			if (lua_istable(L, -2)) {
				tlen = lua_rawlen(L, -2);
			
				for (i = 1; i <= tlen; i++) {
					lua_rawgeti(L, -2, i);
					
					http2 = lua_tolstring(L, -1, &slen2);
					uwsgi_response_add_header(wsgi_req, (char *) http, slen, (char *) http2, slen2);

					lua_pop(L, 1);
				}
				
			} else {
			
				http2 = lua_tolstring(L, -2, &slen2);
				uwsgi_response_add_header(wsgi_req, (char *) http, slen, (char *) http2, slen2);
			}
			
			lua_pop(L, 2);
		}
	}

	// send body with coroutine or copy from string
	lua_pushvalue(L, -1);
	
	switch(lua_type(L, -1)) {
		case LUA_TFUNCTION:
		
			if (uwsgi.async > 0) {	
				goto async_coroutine;
			}
	
			while (!lua_pcall(L, 0, 1, 0)) {				
				switch(lua_type(L, -1)) {
					case LUA_TTABLE: if(!(uwsgi_lua_metatable_tostring(L, -1))) break;
					case LUA_TSTRING:
					case LUA_TNUMBER:
							
						http = lua_tolstring(L, -1, &slen);
						uwsgi_response_write_body_do(wsgi_req, (char *) http, slen);
				}
			
				lua_pop(L, 1);
				lua_pushvalue(L, -1);
			}
			
			break;
			
		case LUA_TTABLE: if(!(uwsgi_lua_metatable_tostring(L, -1))) break;
		case LUA_TSTRING:
		case LUA_TNUMBER:
			
			http = lua_tolstring(L, -1, &slen);
			uwsgi_response_write_body_do(wsgi_req, (char *) http, slen);
	}

clear:
	lua_pop(L, 4);
clear2:
	// set frequency
	if (ulua.gc_freq && (ulua.gc_freq == 1 || 
		(uwsgi.threads == 1 && uwsgi.workers[uwsgi.mywid].requests % ulua.gc_freq == 0) || 
		(uwsgi.threads > 1 && uwsgi.workers[uwsgi.mywid].cores[wsgi_req->async_id].requests % ulua.gc_freq == 0))) 
	{
			lua_gc(L, ulua.gc_full, 0);
	}

	return UWSGI_OK;

}

static void uwsgi_lua_after_request(struct wsgi_request *wsgi_req) {

	log_request(wsgi_req);
}


static int uwsgi_lua_magic(char *mountpoint, char *lazy) {

	if( !strcmp(lazy+strlen(lazy)-4, ".lua")  ||
		!strcmp(lazy+strlen(lazy)-5, ".luac") ||
		!strcmp(lazy+strlen(lazy)-3, ".ws")) 
	{
		ulua.wsapi = lazy;
		return 1;
	}

	return 0;
}

static char *uwsgi_lua_code_string(char *id, char *code, char *func, char *key, uint16_t keylen) {

	static struct lua_State *L = NULL;

	if (!L) {
		L = luaL_newstate();
                luaL_openlibs(L);
                if (luaL_loadfile(L, code) || lua_pcall(L, 0, 0, 0)) {
                ulua_log("unable to load file %s: %s", code, lua_tostring(L, -1));
			lua_close(L);
			L = NULL;
			return NULL;
                }
		lua_getglobal(L, func);
		if (!lua_isfunction(L,-1)) {
			ulua_log("unable to find %s function in lua file %s", func, code);
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
	ulua_log("stack pos %d %.*s", lua_gettop(L), keylen, key);
#endif

        if (lua_pcall(L, 1, 1, 0)) {
                ulua_log("error running function `f': %s", lua_tostring(L, -1));
                return NULL;

        }

	if (lua_isstring(L, -1)) {
                const char *ret = lua_tostring(L, -1);
		return (char *)ret;
        }

        return NULL;
}

static int uwsgi_lua_signal_handler(uint8_t sig, void *handler) {

	int type;
	struct wsgi_request *wsgi_req = current_wsgi_req();
	
	lua_State *L = ULUA_WORKER_STATE[wsgi_req->async_id];
	
	lua_rawgeti(L, LUA_REGISTRYINDEX, ULUA_SIGNAL_REF);
	lua_rawgeti(L, -1, sig);

#ifdef UWSGI_DEBUG
	ulua_log("managing signal handler on core %d", wsgi_req->async_id);
#endif

	type = lua_type(L, -1);

	if (!(type == LUA_TFUNCTION) && !(type == LUA_TTABLE && uwsgi_lua_metatable_call(L, -1))) {
		ulua_log("signal: attempt to call a %s value", lua_typename(L, type));
		lua_pop(L, 2);
		return -1;
	}

	lua_pushnumber(L, sig);

	if (lua_pcall(L, 1 + (type == LUA_TTABLE), 1, 0)) {
		ulua_log("signal: error running function `f': %s",
		lua_tostring(L, -1));
		lua_pop(L, 2);
		return -1;
	}

	lua_pop(L, 2);
	return 0;
}

static uint64_t uwsgi_lua_rpc(void * func, uint8_t argc, char **argv, uint16_t argvs[], char **buffer) {

	uint8_t i;
	const char *sv = NULL;
	size_t sl = 0;

	int type;
	struct wsgi_request *wsgi_req = current_wsgi_req();
	
	lua_State *L = ULUA_WORKER_STATE[wsgi_req->async_id];
	lua_rawgeti(L, LUA_REGISTRYINDEX, ULUA_RPC_REF);
	
	lua_pushstring(L, (char *) func);
	lua_rawget(L, -2);
	
	type = lua_type(L, -1);
	
	if (!(type == LUA_TFUNCTION) && !(type == LUA_TTABLE && uwsgi_lua_metatable_call(L, -1))) {
		ulua_log("rpc: attempt to call a %s value", lua_typename(L, type));
		lua_pop(L, 2);
		return 0;
	}
	
	for(i = 0; i < argc; i++) {
		lua_pushlstring(L, argv[i], argvs[i]);
	}
	
	if (lua_pcall(L, argc + (type == LUA_TTABLE), 1, 0)) {
		ulua_log("rpc: error running function `f': %s", lua_tostring(L, -1));
		lua_pop(L, 2);
		return 0;
	}

	switch(lua_type(L, -1)) {
		case LUA_TTABLE: if(!(uwsgi_lua_metatable_tostring(L, -1))) break;
		case LUA_TSTRING:
		case LUA_TNUMBER: sv = lua_tolstring(L, -1, &sl);
	}

	if (sl > 0) {
		*buffer = uwsgi_malloc(sizeof(char) * sl);
		memcpy(*buffer, sv, sizeof(char) * sl);
	}

	lua_pop(L, 2);
	
	return sl;
}

static void uwsgi_lua_configurator_array(lua_State *L) { 

	int i;
	int n = lua_rawlen(L, -3);

	for(i=1;i<=n;i++) {
		lua_rawgeti(L, 1, i);
		if (lua_istable(L, -1)) {
                	lua_pushnil(L);
                        while (lua_next(L, -2) != 0) {
                        	char *key = uwsgi_str((char *)lua_tostring(L, -2));
                                char *value = uwsgi_str((char *)lua_tostring(L, -1));
                                add_exported_option(key, value, 0);
                                lua_pop(L, 1);
                        }
                }
	}
}


static void uwsgi_lua_configurator(char *filename, char *magic_table[]) {
	size_t len = 0;
	uwsgi_log_initial("[uWSGI] getting Lua configuration from %s\n", filename);
	char *code = uwsgi_open_and_read(filename, &len, 1, magic_table);
	lua_State *L = luaL_newstate();
	if (!L) {
		uwsgi_log("unable to initialize Lua state for configuration\n");
		exit(1);
	}
        luaL_openlibs(L);
	if (luaL_dostring(L, code) != 0) {
		uwsgi_log("error running Lua configurator: %s\n", lua_tostring(L, -1));
		exit(1);
	}
	free(code);

	if (!lua_istable(L, -1)) {
		uwsgi_log("Lua configurator has to return a table !!!\n");
		exit(1);
	}

	lua_pushnil(L);
	// we always use uwsgi_str to avoid GC destroying our strings
	// and to be able to call lua_close at the end
	while (lua_next(L, -2) != 0) {
		// array ?
		if (lua_isnumber(L, -2)) {
			uwsgi_lua_configurator_array(L);
			break;
		}
		// dictionary
		else {
			char *key = uwsgi_str((char *)lua_tostring(L, -2));
			if (lua_istable(L, -1)) {
				lua_pushnil(L);
				while (lua_next(L, -2) != 0) {
					char *value = uwsgi_str((char *)lua_tostring(L, -1));
					add_exported_option(key, value, 0);
					lua_pop(L, 1);
				}
			}
			else {
				char *value = uwsgi_str((char *)lua_tostring(L, -1));
				add_exported_option(key, value, 0);
			}
		}
		lua_pop(L, 1);
	}

	// this will destroy the whole Lua state
	lua_close(L);
}

static void uwsgi_register_lua_features() {	
	uwsgi_register_configurator(".luac", uwsgi_lua_configurator);
	uwsgi_register_configurator(".lua", uwsgi_lua_configurator);
	
	// non zero or non inited defaults:
	ulua.gc_freq = 1;
}

static void uwsgi_lua_hijack(void) {

	if (ulua.shell && uwsgi.mywid == 1) {
	
		if (ulua.shell_oneshot && uwsgi.workers[uwsgi.mywid].hijacked_count > 0) {
			uwsgi.workers[uwsgi.mywid].hijacked = 0;
			return;
		}
		
		uwsgi.workers[uwsgi.mywid].hijacked = 1;
		uwsgi.workers[uwsgi.mywid].hijacked_count++;
		// re-map stdin to stdout and stderr if we are logging to a file
		if (uwsgi.logfile) {
			if (dup2(0, 1) < 0) {
				uwsgi_error("dup2()");
			}
			if (dup2(0, 2) < 0) {
				uwsgi_error("dup2()");
			}
		}

		// run in the first state
		lua_State *L = ULUA_WORKER_STATE[0];		
		lua_getglobal(L, "debug");
		lua_getfield(L, -1, "debug");
		
		ulua_log("Hallo, this is lua debug.debug() aka lua_debug, use CTRL+D to %s", 
			(ulua.shell_oneshot || uwsgi.master_process) ? "resume" : "exit");
		
		if (lua_pcall(L, 0, 0, 0)) {
			ulua_log("unable to call 'debug.debug()': %s", lua_tostring(L, -1));
		}

		if (ulua.shell_oneshot || uwsgi.master_process) { // master will respawn it anyway
		
			uwsgi.workers[uwsgi.mywid].hijacked = 0;
			
			uwsgi_log("\n");
			ulua_log("worker %d has been resumed...", uwsgi.mywid);
			
			return;
		} 
			
		exit(UWSGI_QUIET_CODE);

	}
}


static void uwsgi_lua_init_apps() {
	
	if (!ULUA_WORKER_ANYAPP) {
		return;
	}

	int i,j,sid;
	
	//cores per lua thread
	int cores = uwsgi.threads > 1 ? 1 : uwsgi.cores;

	if (uwsgi.mywid > 0) {	// lazy app
		sid = ULUA_MYWID*uwsgi.threads;
	
		for(i=0;i<uwsgi.threads;i++) {
			uwsgi_lua_init_state(&(ULUA_WORKER_STATE[i]), uwsgi.mywid, sid + i, cores);
		}
		
		ulua_log("inited %d lua_State(s) for worker %d", uwsgi.threads, uwsgi.mywid);
	} else {
		for(j=0;j<uwsgi.numproc;j++){
			sid = j*uwsgi.threads;
			
			for(i=0;i<uwsgi.threads;i++) {
				uwsgi_lua_init_state(&(ulua.state[j][i]), j + 1, sid + i, cores);
			}
			
			ulua_log("inited %d lua_State(s) for worker %d", uwsgi.threads, j + 1);
		}
	}
}
	
struct uwsgi_plugin lua_plugin = {

	.name = "lua",
	.modifier1 = 6,
	.init = uwsgi_lua_init,
	.options = uwsgi_lua_options,
	.request = uwsgi_lua_request,
	.after_request = uwsgi_lua_after_request,
	
	.init_apps = uwsgi_lua_init_apps,
	
	.magic = uwsgi_lua_magic,
	.signal_handler = uwsgi_lua_signal_handler,

	.hijack_worker = uwsgi_lua_hijack,

	.code_string = uwsgi_lua_code_string,
	.rpc = uwsgi_lua_rpc,

	.on_load = uwsgi_register_lua_features,
};

