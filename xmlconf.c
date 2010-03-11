#ifdef UWSGI_XML

#include "uwsgi.h"

#include <libxml/parser.h>
#include <libxml/tree.h>

extern struct uwsgi_server uwsgi;

void uwsgi_xml_config(struct wsgi_request *wsgi_req, struct option *long_options) {
	xmlDoc *doc = NULL;
	xmlNode *element = NULL;
	xmlNode *node = NULL;
	xmlNode *node2 = NULL;

	xmlChar *xml_uwsgi_mountpoint = NULL;
	xmlChar *xml_uwsgi_script = NULL;
	struct option *lopt, *aopt;


	doc = xmlReadFile(uwsgi.xml_config, NULL, 0);
	if (doc == NULL) {
		fprintf(stderr, "[uWSGI] could not parse file %s.\n", uwsgi.xml_config);
		exit(1);
	}

	if (long_options) {
		fprintf(stderr, "[uWSGI] parsing config file %s\n", uwsgi.xml_config);
	}

	element = xmlDocGetRootElement(doc);
	if (element == NULL) {
		fprintf(stderr, "[uWSGI] invalid xml config file.\n");
		exit(1);
	}
	if (strcmp((char *) element->name, "uwsgi")) {
		fprintf(stderr, "[uWSGI] invalid xml root element, <uwsgi> expected.\n");
		exit(1);
	}


	if (long_options) {
		// first check for pythonpath
		for (node = element->children; node; node = node->next) {
			if (node->type == XML_ELEMENT_NODE) {
				lopt = long_options;
				while ((aopt = lopt)) {
					if (!aopt->name)
						break;
					if (!strcmp((char *) node->name, aopt->name)) {
						if (!node->children && aopt->has_arg) {
							fprintf(stderr, "[uWSGI] %s option need a value. skip.\n", aopt->name);
							exit(1);
						}

						if (node->children) {
							if (!node->children->content && aopt->has_arg) {
								fprintf(stderr, "[uWSGI] %s option need a value. skip.\n", aopt->name);
								exit(1);
							}
						}

						if (aopt->flag) {
							*aopt->flag = aopt->val;
						}
						else {
							if (node->children) {
								manage_opt(aopt->val, (char *) node->children->content);
							}
							else {
								manage_opt(aopt->val, NULL);
							}
						}
					}
					lopt++;
				}
			}
		}
	}
	else {

		// ... then for wsgi apps
		for (node = element->children; node; node = node->next) {
			if (node->type == XML_ELEMENT_NODE) {

				if (!strcmp((char *) node->name, "app")) {
					xml_uwsgi_mountpoint = xmlGetProp(node, (const xmlChar *) "mountpoint");
					if (xml_uwsgi_mountpoint == NULL) {
						fprintf(stderr, "no mountpoint defined for app. skip.\n");
						continue;
					}
					wsgi_req->script_name = (char *) xml_uwsgi_mountpoint;
					wsgi_req->script_name_len = strlen(wsgi_req->script_name);

					for (node2 = node->children; node2; node2 = node2->next) {
						if (node2->type == XML_ELEMENT_NODE) {
							if (!strcmp((char *) node2->name, "script")) {
								if (!node2->children) {
									fprintf(stderr, "no wsgi script defined. skip.\n");
									continue;
								}
								xml_uwsgi_script = node2->children->content;
								if (xml_uwsgi_script == NULL) {
									fprintf(stderr, "no wsgi script defined. skip.\n");
									continue;
								}
								wsgi_req->wsgi_script = (char *) xml_uwsgi_script;
								wsgi_req->wsgi_script_len = strlen(wsgi_req->wsgi_script);
								init_uwsgi_app(NULL, NULL);
							}
						}
					}
				}
			}
		}

	}

	/* We cannot free xml resources as the string pointer must be valid for all the server lifecycle */
	//xmlFreeDoc (doc);
	//xmlCleanupParser ();

}

#else
#warning "*** XML configuration support is disabled ***"
#endif
