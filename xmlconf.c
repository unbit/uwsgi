#ifdef UWSGI_XML

#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

#ifdef UWSGI_XML_LIBXML2

#include <libxml/parser.h>
#include <libxml/tree.h>


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
		uwsgi_log( "[uWSGI] could not parse file %s.\n", uwsgi.xml_config);
		exit(1);
	}

	if (long_options) {
		uwsgi_log( "[uWSGI] parsing config file %s\n", uwsgi.xml_config);
	}

	element = xmlDocGetRootElement(doc);
	if (element == NULL) {
		uwsgi_log( "[uWSGI] invalid xml config file.\n");
		exit(1);
	}
	if (strcmp((char *) element->name, "uwsgi")) {
		uwsgi_log( "[uWSGI] invalid xml root element, <uwsgi> expected.\n");
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
							uwsgi_log( "[uWSGI] %s option need a value. skip.\n", aopt->name);
							exit(1);
						}

						if (node->children) {
							if (!node->children->content && aopt->has_arg) {
								uwsgi_log( "[uWSGI] %s option need a value. skip.\n", aopt->name);
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
						uwsgi_log( "no mountpoint defined for app. skip.\n");
						continue;
					}
					wsgi_req->script_name = (char *) xml_uwsgi_mountpoint;
					wsgi_req->script_name_len = strlen(wsgi_req->script_name);

					for (node2 = node->children; node2; node2 = node2->next) {
						if (node2->type == XML_ELEMENT_NODE) {
							if (!strcmp((char *) node2->name, "script")) {
								if (!node2->children) {
									uwsgi_log( "no wsgi script defined. skip.\n");
									continue;
								}
								xml_uwsgi_script = node2->children->content;
								if (xml_uwsgi_script == NULL) {
									uwsgi_log( "no wsgi script defined. skip.\n");
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

	/* We cannot free xml resources on the first round as the string pointer must be valid for all the server lifecycle */
	if (!long_options) {
		xmlFreeDoc (doc);
		xmlCleanupParser ();
	}

}

#endif

#ifdef UWSGI_XML_EXPAT

#include <expat.h>

int current_xmlnode ;
int current_xmlnode_has_arg ;
char *current_xmlnode_text ;
int current_xmlnode_text_len ;

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

	current_xmlnode = 0 ;
	current_xmlnode_has_arg = 0 ;
	current_xmlnode_text = NULL ;
	current_xmlnode_text_len = 0 ;
}

void uwsgi_endApp(void *userData, const char *name) {}

void uwsgi_textHandler(void *userData, const char *s, int len) {
	
	if (current_xmlnode && current_xmlnode_has_arg) {
		current_xmlnode_text = (char *) s;
		current_xmlnode_text_len = len;
	}
}

void uwsgi_textApp(void *userData, const char *s, int len) {

	struct wsgi_request *wsgi_req = (struct wsgi_request *) userData ;

	if (current_xmlnode) {
		wsgi_req->wsgi_script = (char *) s;
                wsgi_req->wsgi_script_len = len;
                init_uwsgi_app(NULL, NULL);
		current_xmlnode = 0;
	}
};

void uwsgi_startApp(void *userData, const char *name, const char **attrs) {

	struct wsgi_request *wsgi_req = (struct wsgi_request *) userData ;


	if (!strcmp(name, "app")) {
		current_xmlnode = 0 ;
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
			wsgi_req->script_name = "/";
			wsgi_req->script_name_len = 1;
		}
	}
	else if (!strcmp(name, "script")) {
		if (!wsgi_req->script_name_len) {
			uwsgi_log("you have not specified an app mountpoint.\n");
			exit(1);
		}
		current_xmlnode = 1 ;
	}
}

void uwsgi_startElement(void *userData, const char *name, const char **attrs) {

	struct option *long_options = (struct option *) userData;
	struct option *lopt, *aopt;


	lopt = long_options;
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
				current_xmlnode_has_arg = aopt->has_arg ;
				break;
			}
		}
                lopt++;
	}
}



void uwsgi_xml_config(struct wsgi_request *wsgi_req, struct option *long_options) {

	int xmlfd ;
	size_t rlen ;
	struct stat stat_buf;
	char *xmlbuf ;

	XML_Parser parser = XML_ParserCreate(NULL);

	xmlfd = open(uwsgi.xml_config, O_RDONLY);
	if (xmlfd < 0) {
		uwsgi_error("open()");
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
