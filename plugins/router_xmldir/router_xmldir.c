#include <uwsgi.h>

#ifndef UWSGI_XML_LIBXML2
#error you need a libxml2-enabled build of uWSGI to use the router_xmldir plugin
#endif

#include <libxml/tree.h>

static int uwsgi_routing_func_xmldir(struct wsgi_request *wsgi_req, struct uwsgi_route *ur){

        char **subject = (char **) (((char *)(wsgi_req))+ur->subject);
        uint16_t *subject_len = (uint16_t *)  (((char *)(wsgi_req))+ur->subject_len);
        struct uwsgi_buffer *ub = uwsgi_routing_translate(wsgi_req, ur, *subject, *subject_len, ur->data, ur->data_len);
        if (!ub) return UWSGI_ROUTE_BREAK;

	struct dirent **tasklist;
        int n = scandir(ub->buf, &tasklist, 0, versionsort);
	uwsgi_buffer_destroy(ub);
        if (n < 0) return UWSGI_ROUTE_BREAK;
        int i;
	xmlDoc *rdoc = xmlNewDoc(BAD_CAST "1.0");
        xmlNode *rtree = xmlNewNode(NULL, BAD_CAST "tree");
        xmlDocSetRootElement(rdoc, rtree);

        for(i=0;i<n;i++) {
                if (tasklist[i]->d_name[0] == '.') goto next;
		switch (tasklist[i]->d_type) {
			case DT_DIR:
				xmlNewTextChild(rtree, NULL, BAD_CAST "directory", BAD_CAST tasklist[i]->d_name);
				break;
			case DT_LNK:
				xmlNewTextChild(rtree, NULL, BAD_CAST "link", BAD_CAST tasklist[i]->d_name);
				break;
			case DT_REG:
				xmlNewTextChild(rtree, NULL, BAD_CAST "file", BAD_CAST tasklist[i]->d_name);
				break;
			default:
				xmlNewTextChild(rtree, NULL, BAD_CAST "unknown", BAD_CAST tasklist[i]->d_name);
                                break;
		}
next:
		free(tasklist[i]);
        }

        free(tasklist);

	xmlChar *xmlbuf;
        int xlen = 0;
        xmlDocDumpFormatMemory(rdoc, &xmlbuf, &xlen, 1);

	uwsgi_response_prepare_headers(wsgi_req,"200 OK", 6);
        uwsgi_response_write_body_do(wsgi_req, (char *) xmlbuf, xlen);

        xmlFreeDoc(rdoc);
        xmlFree(xmlbuf);

	return UWSGI_ROUTE_BREAK;
}


static int uwsgi_router_xmldir(struct uwsgi_route *ur, char *args) {
        ur->func = uwsgi_routing_func_xmldir;
        ur->data = args;
        ur->data_len = strlen(args);
	return 0;
}

static void router_xmldir_register() {
        uwsgi_register_router("xmldir", uwsgi_router_xmldir);
}

struct uwsgi_plugin router_xmldir_plugin = {
	.name = "router_xmldir",
	.on_load = router_xmldir_register,
};
