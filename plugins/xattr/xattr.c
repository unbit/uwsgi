#include <uwsgi.h>

/*

	xattr-related plugin

	exposes two routing vars:

	file is a var, key is a string
	${xattr[PATH_INFO:user.uwsgi.webdav.foobar]}
	
	file is a var, key is a var
	${xattr2[PATH_INFO:MYKEY]}

*/

#ifdef __linux__
#include <sys/xattr.h>
#endif

static char *uwsgi_route_var_xattr(struct wsgi_request *wsgi_req, char *key, uint16_t keylen, uint16_t *vallen) {
	char *colon = memchr(key, ':', keylen);
	if (!colon) return NULL;
        uint16_t var_vallen = 0;
        char *var_value = uwsgi_get_var(wsgi_req, key, colon-key, &var_vallen);
        if (var_value) {
		char *filename = uwsgi_concat2n(var_value, var_vallen, "", 0);
		char *name = uwsgi_concat2n(colon+1, (keylen-1) - (colon-key), "", 0);
		ssize_t rlen = getxattr(filename, name, NULL, 0);
		if (rlen > 0) {
			char *value = uwsgi_calloc(rlen);
			getxattr(filename, name, value, rlen);
			*vallen = rlen;
			free(filename);
			free(name);
			return value;
		}
		free(filename);
		free(name);
        }
        return NULL;
}

static char *uwsgi_route_var_xattr2(struct wsgi_request *wsgi_req, char *key, uint16_t keylen, uint16_t *vallen) {
        char *colon = memchr(key, ':', keylen);
        if (!colon) return NULL;
        uint16_t var_vallen = 0;
        char *var_value = uwsgi_get_var(wsgi_req, key, colon-key, &var_vallen);
        if (var_value) {
		uint16_t var2_vallen = 0;	
		char *var2_value = uwsgi_get_var(wsgi_req, colon+1, (keylen-1) - (colon-key), &var2_vallen);
		if (var2_value) {
                	char *filename = uwsgi_concat2n(var_value, var_vallen, "", 0);
                	char *name = uwsgi_concat2n(var2_value, var2_vallen, "", 0);
                	ssize_t rlen = getxattr(filename, name, NULL, 0);
                	if (rlen > 0) {
                        	char *value = uwsgi_calloc(rlen);
                        	getxattr(filename, name, value, rlen);
                        	*vallen = rlen;
                        	free(filename);
                        	free(name);
                        	return value;
                	}
                	free(filename);
                	free(name);
		}
        }
        return NULL;
}

static void register_route_vars_xattr() {
        struct uwsgi_route_var *urv = uwsgi_register_route_var("xattr", uwsgi_route_var_xattr);
        urv->need_free = 1;
        urv = uwsgi_register_route_var("xattr2", uwsgi_route_var_xattr2);
        urv->need_free = 1;
}

struct uwsgi_plugin xattr_plugin = {
        .name = "xattr",
        .on_load = register_route_vars_xattr,
};

