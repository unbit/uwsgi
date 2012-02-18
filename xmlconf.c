#ifdef UWSGI_XML

#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

#ifdef UWSGI_XML_LIBXML2

#include <libxml/parser.h>
#include <libxml/tree.h>

void uwsgi_xml_config(char *filename, struct wsgi_request *wsgi_req, char *magic_table[]) {
	xmlDoc *doc = NULL;
	xmlNode *element = NULL;
	xmlNode *node = NULL;

	xmlChar *node_mode;

	char *colon;

	char *xml_id;
	char *xml_content;
	int xml_size = 0;

	if (uwsgi_check_scheme(filename)) {
		colon = uwsgi_get_last_char(filename, '/');
		colon = uwsgi_get_last_char(colon, ':');
	}
	else {
		colon = uwsgi_get_last_char(filename, ':');
	}
	if (colon) {
		colon[0] = 0;
		colon++;
		if (*colon == 0) {
			uwsgi_log("invalid xml id\n");
			exit(1);
		}
		uwsgi_log( "[uWSGI] using xml uwsgi id: %s\n", colon);
	}

	xml_content = uwsgi_open_and_read(filename, &xml_size, 0, magic_table);

	doc = xmlReadMemory(xml_content, xml_size, filename, NULL, 0);
	if (doc == NULL) {
		uwsgi_log( "[uWSGI] could not parse file %s.\n", filename);
		exit(1);
	}

	uwsgi_log( "[uWSGI] parsing config file %s\n", filename);

	element = xmlDocGetRootElement(doc);
	if (element == NULL) {
		uwsgi_log( "[uWSGI] invalid xml config file.\n");
		exit(1);
	}
	if (strcmp((char *) element->name, "uwsgi")) {
		for (node = element->children; node; node = node->next) {
			element = NULL;
			if (node->type == XML_ELEMENT_NODE) {
				if (!strcmp((char *) node->name, "uwsgi")) {
					xml_id = (char *) xmlGetProp(node, (const xmlChar *) "id");

					if (colon && xml_id) {
						if ( strcmp(colon, xml_id) ) {
							continue;
						}
					}
					element = node;
					break;
				}
			}
		}

		if (!element) {
			uwsgi_log( "[uWSGI] invalid xml root element, <uwsgi> expected.\n");
			exit(1);
		}
	}


		// first check for options
		for (node = element->children; node; node = node->next) {
			if (node->type == XML_CDATA_SECTION_NODE) {
				if (node->content) {
					uwsgi_manage_opt("eval", (char *) node->content);
				}
			}
			else if (node->type == XML_ELEMENT_NODE) {

				node_mode = xmlGetProp(node, (const xmlChar *) "mode");
				if (uwsgi.mode && node_mode) {
					if (strcmp(uwsgi.mode, (char *) node_mode)) {
						continue;	
					}	
				}

				xml_id = (char *) xmlGetProp(node, (const xmlChar *) "id");
				if (colon && xml_id) {
					if (strcmp(colon, xml_id)) {
						continue;	
					}	
				}

				if (node->children) {
					add_exported_option((char *) node->name, (char *) node->children->content, 0);
				}
				else {
					add_exported_option((char *) node->name, strdup("1"), 0);
				}
			}
		}
	}

	/* We cannot free xml resources on the first round (and with routing enabled) as the string pointer must be valid for all the server lifecycle */

#endif

#ifdef UWSGI_XML_EXPAT

#include <expat.h>


#endif

#else
#warning "*** XML configuration support is disabled ***"
#endif
