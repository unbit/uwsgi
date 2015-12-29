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
#ifdef UWSGI_PHP7
	char *value = uwsgi_cache_magic_get(key->val, key->len , &valsize, NULL, cache);
#else
	char *value = uwsgi_cache_magic_get((char *)key, strlen((char *)key), &valsize, NULL, cache);
#endif
        if (!value) return FAILURE;
#ifdef UWSGI_PHP7
	*val = zend_string_init(value, valsize, 0);
#else
	char *new_val = emalloc(valsize);
	memcpy(new_val, value, valsize);
	free(value);
	*val = new_val;
	*vallen = valsize;
#endif
	return SUCCESS;
	
}

PS_WRITE_FUNC(uwsgi) {
	char *cache = PS_GET_MOD_DATA();
#ifdef UWSGI_PHP7
	if (val->len == 0) return SUCCESS;
	if (!uwsgi_cache_magic_set(key->val, key->len, val->val, val->len, 0, UWSGI_CACHE_FLAG_UPDATE, cache)) {
#else
	if (vallen == 0) return SUCCESS;
	if (!uwsgi_cache_magic_set((char *)key, strlen(key), (char *)val, vallen, 0, UWSGI_CACHE_FLAG_UPDATE, cache)) {
#endif
		return SUCCESS;	
	}
	return FAILURE;
}

PS_DESTROY_FUNC(uwsgi) {
	char *cache = PS_GET_MOD_DATA();
#ifdef UWSGI_PHP7
	if (!uwsgi_cache_magic_del(key->val, key->len, cache)) {
#else
	if (!uwsgi_cache_magic_del((char *)key, strlen(key), cache)) {
#endif
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

