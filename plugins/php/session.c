#include "common.h"

PS_OPEN_FUNC(uwsgi) {
	PS_SET_MOD_DATA((char *)save_path);
	return SUCCESS;
}

PS_CLOSE_FUNC(uwsgi) {
	return SUCCESS;
}

PS_READ_FUNC(uwsgi) {
	char *cache = PS_GET_MOD_DATA();
	uint64_t valsize = 0;
	char *value = uwsgi_cache_magic_get((char *)key, strlen(key), &valsize, NULL, cache);
        if (!value) return FAILURE;
	char *new_val = emalloc(valsize);
	memcpy(new_val, value, valsize);
	free(value);
	*val = new_val;
	*vallen = valsize;
	return SUCCESS;
	
}

PS_WRITE_FUNC(uwsgi) {
	char *cache = PS_GET_MOD_DATA();
	if (vallen == 0) return SUCCESS;
	if (!uwsgi_cache_magic_set((char *)key, strlen(key), (char *)val, vallen, 0, UWSGI_CACHE_FLAG_UPDATE, cache)) {
		return SUCCESS;	
	}
	return FAILURE;
}

PS_DESTROY_FUNC(uwsgi) {
	char *cache = PS_GET_MOD_DATA();
	if (!uwsgi_cache_magic_del((char *)key, strlen(key), cache)) {
		return SUCCESS;
	}
	return FAILURE;
}

PS_GC_FUNC(uwsgi) {
	return SUCCESS;
}

ps_module ps_mod_uwsgi = {
	PS_MOD(uwsgi)
};

