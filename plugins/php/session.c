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
	char *value = uwsgi_cache_magic_get(key->val, key->len , &valsize, NULL, cache);
	if (!value) {
		*val = STR_EMPTY_ALLOC();
		return SUCCESS;
	}
	*val = zend_string_init(value, valsize, 0);
	return SUCCESS;
	
}

PS_WRITE_FUNC(uwsgi) {
	char *cache = PS_GET_MOD_DATA();
	if (val->len == 0) return SUCCESS;
	if (!uwsgi_cache_magic_set(key->val, key->len, val->val, val->len, 0, UWSGI_CACHE_FLAG_UPDATE, cache)) {
		return SUCCESS;	
	}
	return FAILURE;
}

PS_DESTROY_FUNC(uwsgi) {
	char *cache = PS_GET_MOD_DATA();
	if (!uwsgi_cache_magic_exists(key->val, key->len, cache))
		return SUCCESS;

	if (!uwsgi_cache_magic_del(key->val, key->len, cache)) {
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

