#ifdef UWSGI_XML

#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

#ifdef UWSGI_XML_LIBXML2

#include <libxml/parser.h>
#include <libxml/tree.h>

void uwsgi_xml_config(struct wsgi_request *wsgi_req, int app_tag, char *magic_table[]) {
	xmlDoc *doc = NULL;
	xmlNode *element = NULL;
	xmlNode *node = NULL;
	xmlNode *node2 = NULL;

	xmlChar *xml_uwsgi_mountpoint = NULL;
	xmlChar *xml_uwsgi_domain = NULL;
	xmlChar *node_mode;

	char *colon;

	int i;
	char *xml_id;
	char *xml_content;
	int xml_size = 0;

	colon = uwsgi_get_last_char(uwsgi.xml_config, ':');
	if (colon) {
		colon[0] = 0;
		colon++;
		if (*colon == 0) {
			uwsgi_log("invalid xml id\n");
			exit(1);
		}
		uwsgi_log( "[uWSGI] using xml uwsgi id: %s\n", colon);
	}

	xml_content = uwsgi_open_and_read(uwsgi.xml_config, &xml_size, 0, magic_table);

	doc = xmlReadMemory(xml_content, xml_size, uwsgi.xml_config, NULL, 0);
	if (doc == NULL) {
		uwsgi_log( "[uWSGI] could not parse file %s.\n", uwsgi.xml_config);
		exit(1);
	}

	if (!app_tag) {
		uwsgi_log( "[uWSGI] parsing config file %s\n", uwsgi.xml_config);
	}

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


	if (!app_tag) {
		// first check for options
		for (node = element->children; node; node = node->next) {
			if (node->type == XML_CDATA_SECTION_NODE) {
				if (node->content) {
					manage_opt(LONG_ARGS_EVAL_CONFIG, (char *) node->content);
				}
			}
			else if (node->type == XML_ELEMENT_NODE) {

				if (!strcmp((char *) node->name, "app")) {
					uwsgi.xml_round2 = 1;
					continue;
				}

#ifdef UWSGI_ROUTING
				if (!strcmp((char *) node->name, "route")) {
					uwsgi.xml_round2 = 1;
					continue;
				}
				if (!strcmp((char *) node->name, "routing")) {
					uwsgi.xml_round2 = 1;
					continue;
				}
#endif

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
					add_exported_option((char *) node->name, "1", 0);
				}
			}
		}
	}
	else {

		// ... then for apps and routing
		for (node = element->children; node; node = node->next) {
			if (node->type == XML_ELEMENT_NODE) {

				if (!strcmp((char *) node->name, "app")) {
					wsgi_req->script_name_len = 0;
					wsgi_req->host_len = 0;
					xml_uwsgi_mountpoint = xmlGetProp(node, (const xmlChar *) "mountpoint");
					if (xml_uwsgi_mountpoint) {
						wsgi_req->script_name = (char *) xml_uwsgi_mountpoint;
						wsgi_req->script_name_len = strlen(wsgi_req->script_name);
					}

					xml_uwsgi_domain = xmlGetProp(node, (const xmlChar *) "domain");
					if (xml_uwsgi_domain) {
						wsgi_req->host = (char *) xml_uwsgi_domain;
						wsgi_req->host_len = strlen(wsgi_req->host);
					}

					for (node2 = node->children; node2; node2 = node2->next) {
						if (node2->type == XML_ELEMENT_NODE) {
							//we have a mountpoint now pass every node to the xml handler of each plugin
							if (node2->children) {
								if (node2->children->content) {
									for(i=0;i<0xFF;i++) {
										if (uwsgi.p[i]->manage_xml) {
											if (uwsgi.p[i]->manage_xml( (char *)node2->name, (char *) node2->children->content)) break;
										}
									}		
								}
							}
						}
					}
				}
#ifdef UWSGI_ROUTING
				else if (!strcmp((char *) node->name, "routing")) {
					unsigned char *default_route_mountpoint = NULL;
					unsigned char *default_route_callbase = NULL;
					xmlChar *tmp_val;
					int default_route_modifier1 = 0;
					int default_route_modifier2 = 0;
					const char *errstr;
					int erroff;

					default_route_mountpoint = xmlGetProp(node, (const xmlChar *) "mountpoint");
					default_route_callbase = xmlGetProp(node, (const xmlChar *) "base");

					tmp_val = xmlGetProp(node, (const xmlChar *) "modifier1");
					if (tmp_val) {
						default_route_modifier1 = atoi( (char *)tmp_val);
					}

					tmp_val = xmlGetProp(node, (const xmlChar *) "modifier2");
					if (tmp_val) {
						default_route_modifier2 = atoi( (char *) tmp_val);
					}


					for (node2 = node->children; node2; node2 = node2->next) {
						if (node2->type == XML_ELEMENT_NODE) {
							if (!strcmp((char *) node2->name, "route") && uwsgi.nroutes < MAX_UWSGI_ROUTES) {
								if (!node2->children) {
									uwsgi_log( "no route callable defined. skip.\n");
									continue;
								}
								uwsgi.routes[uwsgi.nroutes].mountpoint = (char *) default_route_mountpoint;
								uwsgi.routes[uwsgi.nroutes].callbase = (char *) default_route_callbase;
								uwsgi.routes[uwsgi.nroutes].modifier1 = default_route_modifier1;
								uwsgi.routes[uwsgi.nroutes].modifier2 = default_route_modifier2;
								// TODO check for action
								uwsgi.routes[uwsgi.nroutes].action = NULL;
								uwsgi.routes[uwsgi.nroutes].call = (char *) node2->children->content;
								if (uwsgi.routes[uwsgi.nroutes].call == NULL) {
									uwsgi_log( "no route callable defined. skip.\n");
									continue;
								}

								tmp_val = xmlGetProp(node2, (const xmlChar *) "pattern");
								if (!tmp_val) {
									uwsgi_log( "no route pattern defined. skip.\n");
									continue;
								}

								uwsgi.routes[uwsgi.nroutes].pattern = pcre_compile( (char *) tmp_val, 0, &errstr, &erroff, NULL);
								uwsgi.routes[uwsgi.nroutes].pattern_extra = pcre_study(uwsgi.routes[uwsgi.nroutes].pattern, 0, &errstr);


								pcre_fullinfo(uwsgi.routes[uwsgi.nroutes].pattern, uwsgi.routes[uwsgi.nroutes].pattern_extra, PCRE_INFO_CAPTURECOUNT, &uwsgi.routes[uwsgi.nroutes].args);

								uwsgi_log("route call: %s %d\n", uwsgi.routes[uwsgi.nroutes].call, uwsgi.routes[uwsgi.nroutes].args);	

								uwsgi.nroutes++;
							}
						}
					}

				}
#endif
			}
		}

	}

	/* We cannot free xml resources on the first round (and with routing enabled) as the string pointer must be valid for all the server lifecycle */
#ifdef UWSGI_ROUTING
	if (app_tag && !uwsgi.routing) {
#else
		if (app_tag) {
#endif
			xmlFreeDoc (doc);
			xmlCleanupParser ();
		}

	}

#endif

#ifdef UWSGI_XML_EXPAT

#include <expat.h>

int current_xmlnode;
int current_xmlnode_has_arg;
char *current_xmlnode_text;
int current_xmlnode_text_len;

void uwsgi_endElement(void *userData, const char *name) {

	if (current_xmlnode && !current_xmlnode_has_arg) {
		manage_opt(current_xmlnode, NULL);
	}
	else if (current_xmlnode_has_arg) {
		if (!current_xmlnode_text_len) {
			uwsgi_log("option %s requires an argument\n", name);
			exit(1);
		}
		// HACK: use the first char of closing tag for nulling string
		current_xmlnode_text[current_xmlnode_text_len] = 0;
		manage_opt(current_xmlnode, current_xmlnode_text);
	}

	current_xmlnode = 0;
	current_xmlnode_has_arg = 0;
	current_xmlnode_text = NULL;
	current_xmlnode_text_len = 0;
}

void uwsgi_endApp(void *userData, const char *name) {}

void uwsgi_textHandler(void *userData, const char *s, int len) {

	if (current_xmlnode && current_xmlnode_has_arg) {
		current_xmlnode_text = (char *) s;
		current_xmlnode_text_len = len;
	}
}

void uwsgi_textApp(void *userData, const char *s, int len) {
	struct wsgi_request *wsgi_req = (struct wsgi_request *) userData;

	if (current_xmlnode) {
		wsgi_req->wsgi_script = (char *) s;
		wsgi_req->wsgi_script_len = len;
		//init_uwsgi_app(&uwsgi, NULL);
		current_xmlnode = 0;
	}
};

void uwsgi_startApp(void *userData, const char *name, const char **attrs) {

	struct wsgi_request *wsgi_req = (struct wsgi_request *) userData;

	if (!strcmp(name, "app")) {
		current_xmlnode = 0;
		uwsgi_log("%s = %s\n", attrs[0], attrs[1]);
		if (strcmp(attrs[0], "mountpoint")) {
			uwsgi_log("invalid attribute for app tag. must be 'mountpoint'\n");
			exit(1);
		}
		if (attrs[1]) {
			wsgi_req->script_name = (char *) attrs[1];
			wsgi_req->script_name_len = strlen(attrs[1]);
		}
		else {
			wsgi_req->script_name = "";
			wsgi_req->script_name_len = 0;
		}
	}
	else if (!strcmp(name, "script")) {
		current_xmlnode = 1;
	}
}

void uwsgi_startElement(void *userData, const char *name, const char **attrs) {

	struct option *long_options = (struct option *) userData;
	struct option *lopt, *aopt;


	lopt = uwsgi.long_options;
	while ((aopt = lopt)) {
		if (!aopt->name)
			break;
		if (!strcmp(name, aopt->name)) {
			if (aopt->flag) {
				*aopt->flag = aopt->val;
				break;
			}
			else {
				current_xmlnode = aopt->val;
				current_xmlnode_has_arg = aopt->has_arg;
				break;
			}
		}
		lopt++;
	}
}

void uwsgi_xml_config(struct wsgi_request *wsgi_req, struct option *long_options) {
	int xmlfd;
	size_t rlen;
	struct stat stat_buf;
	char *xmlbuf;

	XML_Parser parser = XML_ParserCreate(NULL);

	xmlfd = open(uwsgi.xml_config, O_RDONLY);
	if (xmlfd < 0) {
		uwsgi_error_open(uwsgi.xml_config);
		exit(1);
	}

	if (fstat(xmlfd, &stat_buf)) {
		uwsgi_error("fstat()");
		exit(1);
	}

	xmlbuf = malloc(stat_buf.st_size);
	if (!xmlbuf) {
		uwsgi_error("malloc()");
		exit(1);
	}

	rlen = read(xmlfd, xmlbuf, stat_buf.st_size);
	if (rlen != stat_buf.st_size) {
		uwsgi_error("read()");
		exit(1);
	}
	close(xmlfd);

	if (long_options) {
		XML_SetUserData(parser, long_options);
		XML_SetElementHandler(parser, uwsgi_startElement, uwsgi_endElement);
		XML_SetCharacterDataHandler(parser, uwsgi_textHandler);
	}
	else {
		XML_SetUserData(parser, wsgi_req);
		XML_SetElementHandler(parser, uwsgi_startApp, uwsgi_endApp);
		XML_SetCharacterDataHandler(parser, uwsgi_textApp);
	}

	if (!XML_Parse(parser, xmlbuf, stat_buf.st_size, 1)) {
		uwsgi_log( "%s at line %d\n", XML_ErrorString(XML_GetErrorCode(parser)), (int) XML_GetCurrentLineNumber(parser));
		exit(1);
	}

	if (!long_options) {
		XML_ParserFree(parser);
		free(xmlbuf);
	}
}

#endif

#else
#warning "*** XML configuration support is disabled ***"
#endif
