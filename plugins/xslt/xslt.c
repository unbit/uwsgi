#include <uwsgi.h>

#include <libxslt/xsltutils.h>
#include <libxslt/transform.h>

/*

	XSLT request plugin

	it takes an XML file as input (taken from DOCUMENT_ROOT + PATH_INFO by default)
	it search for an XSLT stylesheet (by default in DOCUMENT_ROOT + PATH_INFO - ext + .xsl|.xslt)
	it applies params (by default taken from the QUERY_STRING)

	XSLT routing instruction

	xslt:doc=<path1>,stylesheet=<path2>,params=<params>

*/

struct uwsgi_xslt_config {
	struct uwsgi_string_list *docroot;
	struct uwsgi_string_list *ext;
	struct uwsgi_string_list *var;
	struct uwsgi_string_list *stylesheet;
	char *content_type;
	uint16_t content_type_len;
} uxslt;

struct uwsgi_router_xslt_conf {
	char *doc;
	uint16_t doc_len;
	char *stylesheet;
	uint16_t stylesheet_len;
	char *params;
	uint16_t params_len;
	char *content_type;
	uint16_t content_type_len;
};

struct uwsgi_option uwsgi_xslt_options[] = {
	{"xslt-docroot", required_argument, 0, "add a document_root for xslt processing", uwsgi_opt_add_string_list, &uxslt.docroot, 0},
	{"xslt-ext", required_argument, 0, "search for xslt stylesheets with the specified extension", uwsgi_opt_add_string_list, &uxslt.ext, 0},
	{"xslt-var", required_argument, 0, "get the xslt stylesheet path from the specified request var", uwsgi_opt_add_string_list, &uxslt.var, 0},
	{"xslt-stylesheet", required_argument, 0, "if no xslt stylesheet file can be found, use the specified one", uwsgi_opt_add_string_list, &uxslt.stylesheet, 0},
	{"xslt-content-type", required_argument, 0, "set the content-type for the xslt rsult (default: text/html)", uwsgi_opt_set_str, &uxslt.content_type, 0},
	{NULL, 0, 0, NULL, NULL, NULL, 0},
};

static char *uwsgi_xslt_apply(char *xmlfile, char *xsltfile, char *params, int *rlen) {

	char **vparams = NULL;
	char *tmp_params = NULL;
	uint16_t count = 0;
	if (params) {
		// first count the number of items
		size_t i;
		size_t params_len = strlen(params);
		for(i=0;i<params_len;i++) {
			if (params[i] == '=') {
				count++;
			}
		}
		vparams = uwsgi_calloc( sizeof(char *) * ((count * 2) + 1));
		tmp_params = uwsgi_str(params);
		char *p = strtok(tmp_params, "&");
		int pos = 0;
		while(p) {
			char *equal = strchr(p, '=');
			if (equal) {
				*equal = 0;
				vparams[pos] = p; pos++;
				vparams[pos] = uwsgi_concat3("\"", equal+1, "\""); pos++;	
			}
			p = strtok(NULL, "&");
		}
	}

	// we reset them every time to avoid collision with other xml engines
	xmlSubstituteEntitiesDefault(1);
	xmlLoadExtDtdDefaultValue = 1;

        xmlDocPtr doc = xmlParseFile(xmlfile);
        if (!doc) {
		if (vparams) {
			int i; for(i=1;i<(count*2);i+=2) free(vparams[i]);
			free(tmp_params);
			free(vparams);
		}
		return NULL;
	}

        xsltStylesheetPtr ss = xsltParseStylesheetFile((const xmlChar *) xsltfile);
        if (!ss) {
		xmlFreeDoc(doc);
		if (vparams) {
			int i; for(i=1;i<(count*2);i+=2) free(vparams[i]);
			free(tmp_params);
			free(vparams);
		}
                return NULL;
        }

        xmlDocPtr res = xsltApplyStylesheet(ss, doc, (const char **) vparams);
	if (!res) {
		xsltFreeStylesheet(ss);
		xmlFreeDoc(doc);
		if (vparams) {
			int i; for(i=1;i<(count*2);i+=2) free(vparams[i]);
			free(tmp_params);
			free(vparams);
		}
		return NULL;
	}

        xmlChar *output;
        int ret = xsltSaveResultToString(&output, rlen, res, ss);
	xsltFreeStylesheet(ss);
	xmlFreeDoc(res);
	xmlFreeDoc(doc);
	if (vparams) {
		int i; for(i=1;i<(count*2);i+=2) free(vparams[i]);
		free(tmp_params);
		free(vparams);
	}
	if (ret < 0) return NULL;
	return (char *) output;
}

static int uwsgi_request_xslt(struct wsgi_request *wsgi_req) {

	char *xmlfile = NULL;
	char *output = NULL;
        int output_rlen = 0;

	char filename[PATH_MAX+1];
	size_t filename_len = 0;
	char stylesheet[PATH_MAX+1];
	size_t stylesheet_len = 0;
	
	char *params = NULL;

	if (uwsgi_parse_vars(wsgi_req)) {
		return -1;
	}

	// set default values
	if (!uxslt.content_type_len) {
		if (!uxslt.content_type) {
			uxslt.content_type = "text/html";
		}
		uxslt.content_type_len = strlen(uxslt.content_type);
	}

	struct uwsgi_string_list *usl = uxslt.docroot;

	// first check for static docroots
	if (usl) {
		while(usl) {
			xmlfile = uwsgi_concat3n(usl->value, usl->len, "/", 1, wsgi_req->path_info, wsgi_req->path_info_len);
			if (uwsgi_is_file(xmlfile)) {
				break;
			}
			free(xmlfile);
			xmlfile = NULL;
			usl = usl->next;
		}	
	}
	// fallback to DOCUMENT_ROOT
	else {
		if (wsgi_req->document_root_len == 0) {
			uwsgi_403(wsgi_req);
			return UWSGI_OK;
		}

		xmlfile = uwsgi_concat3n(wsgi_req->document_root, wsgi_req->document_root_len, "/", 1, wsgi_req->path_info, wsgi_req->path_info_len);
	}

	if (!xmlfile) {
		uwsgi_404(wsgi_req);
		return UWSGI_OK;
	}

	// we have the full path, check if it is valid
	if (!uwsgi_expand_path(xmlfile, strlen(xmlfile), filename)) {
		free(xmlfile);
		uwsgi_404(wsgi_req);
		return UWSGI_OK;
	}

	free(xmlfile);

	if (!uwsgi_is_file(filename)) {
		uwsgi_403(wsgi_req);
		return UWSGI_OK;
	}
	filename_len = strlen(filename);

	// now search for the xslt file
	
	int found = 0;

	// first check for specific vars
	usl = uxslt.var;
	while(usl) {
		uint16_t rlen;
		char *value = uwsgi_get_var(wsgi_req, usl->value, usl->len, &rlen);
		if (value) {
			memcpy(stylesheet, value, rlen);
			stylesheet[rlen] = 0;
			stylesheet_len = rlen;
			found = 1;
			break;
		}
		usl = usl->next;
	}

	if (found) goto apply;

	// then check for custom extensions
	if (uxslt.ext) {
		usl = uxslt.ext;
		while(usl) {
			char *tmp_path = uwsgi_concat2n(filename, filename_len, usl->value, usl->len);
			if (uwsgi_is_file(tmp_path)) {
				stylesheet_len = filename_len + usl->len;
				memcpy(stylesheet, tmp_path, stylesheet_len);
				stylesheet[stylesheet_len] = 0;
				free(tmp_path);
				found = 1;
				break;
			}
			free(tmp_path);
			usl = usl->next;
		}
	}
	// use default extensions .xsl/.xslt
	else {
		char *tmp_path = uwsgi_concat2n(filename, filename_len, ".xsl", 4);
                if (uwsgi_is_file(tmp_path)) {
                	stylesheet_len = filename_len + 4;
                        memcpy(stylesheet, tmp_path, stylesheet_len);
			stylesheet[stylesheet_len] = 0;
                        free(tmp_path);
			goto apply;	
		}
                free(tmp_path);
		tmp_path = uwsgi_concat2n(filename, filename_len, ".xslt", 5);
                if (uwsgi_is_file(tmp_path)) {
                        stylesheet_len = filename_len + 5;
                        memcpy(stylesheet, tmp_path, stylesheet_len);
			stylesheet[stylesheet_len] = 0;
			found = 1;
                }
                free(tmp_path);
	}

	if (found) goto apply;

	// finally check for static stylesheets
	usl = uxslt.stylesheet;
	while(usl) {
		if (uwsgi_is_file(usl->value)) {
			memcpy(stylesheet, usl->value, usl->len);
			stylesheet_len = usl->len;
			stylesheet[stylesheet_len] = 0;
			found = 1;
			break;
		}
		usl = usl->next;
	}

	if (found) goto apply;
	
	uwsgi_404(wsgi_req);
	return UWSGI_OK;

apply:
	if (wsgi_req->query_string_len > 0) {
		params = uwsgi_concat2n(wsgi_req->query_string, wsgi_req->query_string_len, "", 0);
	}
	// we have both the file and the stylesheet, let's run the engine
	output = uwsgi_xslt_apply(filename, stylesheet, params, &output_rlen);
	if (params) free(params);
	if (!output) {
		uwsgi_500(wsgi_req);
		return UWSGI_OK;
	}

	// prepare headers
	if (uwsgi_response_prepare_headers(wsgi_req, "200 OK", 6)) {
		uwsgi_500(wsgi_req);
		goto end;
	}
	// content_length
	if (uwsgi_response_add_content_length(wsgi_req, output_rlen)) {
		uwsgi_500(wsgi_req);
		goto end;
	}
	// content_type
	if (uwsgi_response_add_content_type(wsgi_req, uxslt.content_type, uxslt.content_type_len)) {
		uwsgi_500(wsgi_req);
		goto end;
	}

	uwsgi_response_write_body_do(wsgi_req, output, output_rlen);

end:
	xmlFree(output);
	return UWSGI_OK;
}

static void uwsgi_xslt_log(struct wsgi_request *wsgi_req) {
	log_request(wsgi_req);
}

static int uwsgi_routing_func_xslt(struct wsgi_request *wsgi_req, struct uwsgi_route *ur){

        struct uwsgi_router_xslt_conf *urxc = (struct uwsgi_router_xslt_conf *) ur->data2;

	char **subject = (char **) (((char *)(wsgi_req))+ur->subject);
        uint16_t *subject_len = (uint16_t *) (((char *)(wsgi_req))+ur->subject_len);

	struct uwsgi_buffer *ub_doc = NULL;
	struct uwsgi_buffer *ub_stylesheet = NULL;
	struct uwsgi_buffer *ub_params = NULL;
	struct uwsgi_buffer *ub_content_type = NULL;

	ub_doc = uwsgi_routing_translate(wsgi_req, ur, *subject, *subject_len, urxc->doc, urxc->doc_len);
	if (!ub_doc) goto end;
	ub_stylesheet = uwsgi_routing_translate(wsgi_req, ur, *subject, *subject_len, urxc->stylesheet, urxc->stylesheet_len);
	if (!ub_stylesheet) goto end;

	if (urxc->params) {
		ub_params = uwsgi_routing_translate(wsgi_req, ur, *subject, *subject_len, urxc->params, urxc->params_len);
		if (!ub_params) goto end;
	}

	if (urxc->content_type) {
		ub_content_type = uwsgi_routing_translate(wsgi_req, ur, *subject, *subject_len, urxc->content_type, urxc->content_type_len);
		if (!ub_content_type) goto end;
	}

	int rlen;
        char *output = uwsgi_xslt_apply( ub_doc->buf, ub_stylesheet->buf, ub_params ? ub_params->buf : NULL, &rlen);
	if (!output) goto end;

        if (uwsgi_response_prepare_headers(wsgi_req, "200 OK", 6)) goto end;
        if (uwsgi_response_add_content_length(wsgi_req, rlen)) goto end;
        if (uwsgi_response_add_content_type(wsgi_req, urxc->content_type, urxc->content_type_len)) goto end;

        uwsgi_response_write_body_do(wsgi_req, output, rlen);
	xmlFree(output);

end:
	if (ub_doc) uwsgi_buffer_destroy(ub_doc);
	if (ub_stylesheet) uwsgi_buffer_destroy(ub_stylesheet);
	if (ub_params) uwsgi_buffer_destroy(ub_params);
	if (ub_content_type) uwsgi_buffer_destroy(ub_content_type);
        return UWSGI_ROUTE_BREAK;
}


static int uwsgi_router_xslt(struct uwsgi_route *ur, char *args) {
        ur->func = uwsgi_routing_func_xslt;
        ur->data = args;
        ur->data_len = strlen(args);
        struct uwsgi_router_xslt_conf *urxc = uwsgi_calloc(sizeof(struct uwsgi_router_xslt_conf));
        if (uwsgi_kvlist_parse(ur->data, ur->data_len, ',', '=',
                        "doc", &urxc->doc,
                        "stylesheet", &urxc->stylesheet,
                        "content_type", &urxc->content_type,
                        "params", &urxc->params,
                        NULL)) {
                        uwsgi_log("invalid route syntax: %s\n", args);
                        exit(1);
	}

	if (!urxc->doc && !urxc->stylesheet) {
                uwsgi_log("invalid route syntax: you need to specify a doc and a stylesheet\n");
        	exit(1);
	}

	urxc->doc_len = strlen(urxc->doc);
	urxc->stylesheet_len = strlen(urxc->stylesheet);

	if (urxc->params) urxc->params_len = strlen(urxc->params);
	if (!urxc->content_type) urxc->content_type = "text/html";
	urxc->content_type_len = strlen(urxc->content_type);
        ur->data2 = urxc;
        return 0;
}


static void router_xslt_register() {
        uwsgi_register_router("xslt", uwsgi_router_xslt);
}


struct uwsgi_plugin xslt_plugin = {
	.name = "xslt",
	.modifier1 = 23,
	.options = uwsgi_xslt_options,
	.request = uwsgi_request_xslt,
	.after_request = uwsgi_xslt_log,
        .on_load = router_xslt_register,
};
