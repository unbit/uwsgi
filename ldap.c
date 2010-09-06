#ifdef UWSGI_LDAP 

#include "uwsgi.h"

#include <ldap.h>

void ldap2uwsgi(char *ldapname, char *uwsginame) {

	char *ptr = uwsginame ;

	int i;

	for(i=0;i< (int) strlen(ldapname);i++) {
		if (isupper( (int)ldapname[i])) {
			*ptr++= '-';
			*ptr++= tolower( (int) ldapname[i]);
		}
		else {
			*ptr++= ldapname[i] ;
		}
	}

	*ptr++= 0;
}

int calc_ldap_name(char *name) {
	
	int i;
	int counter = 0;

	for(i=0;i< (int)strlen(name);i++) {
		if (isupper( (int) name[i])) {
			counter++;
		}
	}

	return strlen(name) + counter ;
}

void uwsgi_ldap_schema_dump_ldif(struct option *lo) {

        struct option *aopt, *lopt ;

        lopt = lo;
        int i;
        int counter = 30000;

	int pythonpath_found = 0 ;

	uwsgi_log("\n");
	uwsgi_log("dn: cn=uwsgi,cn=schema,cn=config\n");
	uwsgi_log("objectClass: olcSchemaConfig\n");
	uwsgi_log("cn: uwsgi\n");

        while( (aopt = lopt) ) {
                if (!aopt->name)
                        break;

		if (aopt->val == LONG_ARGS_PYTHONPATH) {
			if (pythonpath_found) {
				goto next;				
			}
			pythonpath_found = 1;
		}

                if (aopt->flag) {
                        uwsgi_log("olcAttributeTypes: ( 1.3.6.1.4.1.35156.17.4.%d NAME 'uWSGI", counter) ;
                        counter++;
                }
                else {
                        uwsgi_log("olcAttributeTypes: ( 1.3.6.1.4.1.35156.17.4.%d NAME 'uWSGI", aopt->val) ;
                }
                for(i=0;i< (int)strlen(aopt->name);i++) {
                        if (aopt->name[i] == '-') {
                                i++;
                                uwsgi_log("%c", toupper( (int) aopt->name[i]));
                        }
                        else {
                                uwsgi_log("%c", aopt->name[i]);
                        }
                }

                if (aopt->has_arg) {
                        uwsgi_log("' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )\n");
                }
                else {
                        uwsgi_log("' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )\n");
                }
next:
                lopt++;
        }

        uwsgi_log("olcAttributeTypes: ( 1.3.6.1.4.1.35156.17.4.50000 NAME 'uWSGInull' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )\n") ;

        lopt = lo;

        uwsgi_log("olcObjectClasses: ( 1.3.6.1.4.1.35156.17.3.1 NAME 'uWSGIConfig' SUP top AUXILIARY DESC 'uWSGI configuration' MAY ( ");

	pythonpath_found = 0;
        while( (aopt = lopt) ) {
                if (!aopt->name)
                        break;

		if (aopt->val == LONG_ARGS_PYTHONPATH) {
			if (pythonpath_found) {
				goto next2;				
			}
			pythonpath_found = 1;
		}

                uwsgi_log("uWSGI");

                for(i=0;i< (int)strlen(aopt->name);i++) {
                        if (aopt->name[i] == '-') {
                                i++;
                                uwsgi_log("%c", toupper( (int) aopt->name[i]));
                        }
                        else {
                                uwsgi_log("%c", aopt->name[i]);
                        }
                }
                uwsgi_log(" $ ");
next2:
                lopt++;
        }

        uwsgi_log("uWSGInull ))\n");

	uwsgi_log("\n");

        exit(0);
}


void uwsgi_ldap_schema_dump(struct option *lo) {

	struct option *aopt, *lopt ;

	lopt = lo;
	int i;
	int counter = 30000;
	int pythonpath_found = 0;

	while( (aopt = lopt) ) {
		if (!aopt->name)
			break;


		if (aopt->val == LONG_ARGS_PYTHONPATH) {
			if (pythonpath_found) {
				goto next;				
			}
			pythonpath_found = 1;
		}

		if (aopt->flag) {
			uwsgi_log("attributetype ( 1.3.6.1.4.1.35156.17.4.%d NAME 'uWSGI", counter) ;
			counter++;
		}
		else {
			uwsgi_log("attributetype ( 1.3.6.1.4.1.35156.17.4.%d NAME 'uWSGI", aopt->val) ;
		}
		for(i=0;i< (int)strlen(aopt->name);i++) {
			if (aopt->name[i] == '-') {
				i++;
				uwsgi_log("%c", toupper( (int) aopt->name[i]));
			}
			else {
				uwsgi_log("%c", aopt->name[i]);
			}
		}

		if (aopt->has_arg) {
			uwsgi_log("' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )\n");
		}
		else {
			uwsgi_log("' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )\n");
		}
next:
		lopt++;			
	}

	uwsgi_log("attributetype ( 1.3.6.1.4.1.35156.17.4.50000 NAME 'uWSGInull' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )\n") ;

	lopt = lo;

	uwsgi_log("objectclass ( 1.3.6.1.4.1.35156.17.3.1 NAME 'uWSGIConfig' SUP top AUXILIARY DESC 'uWSGI configuration' MAY ( ");

	pythonpath_found = 0;
	while( (aopt = lopt) ) {
		if (!aopt->name)
			break;

		if (aopt->val == LONG_ARGS_PYTHONPATH) {
			if (pythonpath_found) {
				goto next2;				
			}
			pythonpath_found = 1;
		}

		uwsgi_log("uWSGI");

		for(i=0;i< (int)strlen(aopt->name);i++) {
			if (aopt->name[i] == '-') {
				i++;
				uwsgi_log("%c", toupper( (int) aopt->name[i]));
			}
			else {
				uwsgi_log("%c", aopt->name[i]);
			}
		}
		uwsgi_log(" $ ");
next2:
		lopt++;			
	}

	uwsgi_log("uWSGInull ))\n");

	exit(0);
}

void uwsgi_ldap_config(struct uwsgi_server *uwsgi, struct option *long_options) {

	LDAP *ldp;
	LDAPMessage *results, *entry;
	BerElement *ber;
	struct berval **bervalues;
	char *attr;
	char *uwsgi_attr;

	char *url = "ldap:///";
	char *url_slash;

	int desired_version = LDAP_VERSION3;
	int ret;

	struct option *aopt, *lopt;

	LDAPURLDesc *ldap_url;

	if (uwsgi->ldap) {
		url = uwsgi->ldap;
	}

	if (!ldap_is_ldap_url(url)) {
		uwsgi_log("invalid LDAP url.\n");
		exit(1);
	}

	if (ldap_url_parse(url, &ldap_url) != LDAP_SUCCESS) {
		uwsgi_log("unable to parse LDAP url.\n");
		exit(1);
	}

	url_slash = strchr(url, '/');
	url_slash = strchr(url_slash + 1, '/');

	url_slash = strchr(url_slash + 1, '/');
	if (url_slash) {
		url_slash[0] = 0;
	}

#ifdef UWSGI_DEBUG
	uwsgi_debug("LDAP URL: %s\n", url);
	uwsgi_debug("LDAP BASE DN: %s\n", ldap_url->lud_dn);
#endif

	if ( (ret = ldap_initialize( &ldp, url)) != LDAP_SUCCESS) {
		uwsgi_log("LDAP: %s\n", ldap_err2string(ret));
		exit(1);
	}


	if ( (ret = ldap_set_option(ldp, LDAP_OPT_PROTOCOL_VERSION, &desired_version)) != LDAP_OPT_SUCCESS) {
		uwsgi_log("LDAP: %s\n", ldap_err2string(ret));
    		exit(1);
	}


	if ( (ret = ldap_search_ext_s(ldp, ldap_url->lud_dn, ldap_url->lud_scope, ldap_url->lud_filter, NULL, 0, NULL, NULL, NULL, 1, &results)) != LDAP_SUCCESS) {
		uwsgi_log("LDAP: %s\n", ldap_err2string(ret));
    		exit(1);
	}

#ifdef UWSGI_DEBUG
	uwsgi_debug("LDAP connection initialized %p\n", ldp);
#endif

	free(ldap_url);
	
	if (ldap_count_entries(ldp, results) < 1) {
		uwsgi_log("no LDAP entry found\n");
		exit(1);
	}

	entry = ldap_first_entry(ldp, results);

	for( attr = ldap_first_attribute(ldp, entry, &ber); attr != NULL; attr = ldap_next_attribute(ldp, entry, ber)) {
		if (!strncmp(attr,"uWSGI",5)) {
		
			uwsgi_attr = malloc( calc_ldap_name(attr) + 1 );
			if (!uwsgi_attr) {
				uwsgi_error("malloc()");
				exit(1);
			}

			ldap2uwsgi(attr+5, uwsgi_attr);

#ifdef UWSGI_DEBUG
			uwsgi_debug("LDAP attribute: %s = --%s\n", attr, uwsgi_attr);
#endif
			bervalues = ldap_get_values_len(ldp, entry, attr);
			if (bervalues) {
				// do not free uwsgi_val;	
				char *uwsgi_val = malloc( bervalues[0]->bv_len + 1 );
				if (!uwsgi_val) {
					uwsgi_error("malloc()");
					exit(1);
				}

				memcpy(uwsgi_val, bervalues[0]->bv_val, bervalues[0]->bv_len);
				uwsgi_val[bervalues[0]->bv_len] = 0;

				lopt = long_options;
                                while ((aopt = lopt)) {
                                	if (!aopt->name)
                                        	break;
                                        if (!strcmp(uwsgi_attr, aopt->name)) {
                                        	if (aopt->flag) {
                                                	*aopt->flag = aopt->val;
                                       		} 
                                                else {
                                                	manage_opt(aopt->val, uwsgi_val);
                                                }
                                        }
                                        lopt++;
                                }
			}

			free(bervalues);
			free(uwsgi_attr);
		}
		free(attr);
	}

	free(ber);
	free(results);
	
	ldap_unbind_ext_s(ldp, NULL, NULL);
	
}
#endif
