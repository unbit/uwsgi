#include <uwsgi.h>
#include <matheval.h>

static char *uwsgi_route_var_math(struct wsgi_request *wsgi_req, char *key, uint16_t keylen, uint16_t *vallen) {
        char *ret = NULL;
        // avoid crash
        if (!wsgi_req->var_cnt) return NULL;
        // we make a bit of fun here, we do a copy of the vars buffer (+1 byte for final zero) and zeor-pad all of the strings
        char *vars_buf = uwsgi_malloc(wsgi_req->uh->pktsize + keylen + 1);
        char **names = uwsgi_malloc(sizeof(char *) * (wsgi_req->var_cnt/2));
        double *values = uwsgi_calloc(sizeof(double) * (wsgi_req->var_cnt/2));
        int i,j = 0;
        char *ptr = vars_buf;
        for (i = wsgi_req->var_cnt-1; i > 0; i -= 2) {
                memcpy(ptr, wsgi_req->hvec[i-1].iov_base, wsgi_req->hvec[i-1].iov_len);
                names[j] = ptr;
                ptr += wsgi_req->hvec[i-1].iov_len;
                *ptr++=0;
                char *num = ptr;
                memcpy(ptr, wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len);
                ptr += wsgi_req->hvec[i].iov_len;
                *ptr++=0;
                values[j] = strtod(num, NULL);
                j++;
        }

        char *expr = ptr;
        memcpy(ptr, key, keylen); ptr += keylen;
        *ptr++=0;

        void *e = evaluator_create(expr);
        if (!e) goto end;
        double n = evaluator_evaluate(e, j, names, values);
        evaluator_destroy(e);
        ret = uwsgi_num2str((int)n);
        *vallen = strlen(ret);
end:
        free(vars_buf);
        free(names);
        free(values);
        return ret;
}

static void router_matheval_register() {
	struct uwsgi_route_var *urv = uwsgi_register_route_var("math", uwsgi_route_var_math);
        urv->need_free = 1;
}

struct uwsgi_plugin matheval_plugin = {
	.name = "matheval",
	.on_load = router_matheval_register,	
};
