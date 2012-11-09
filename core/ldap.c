#ifdef UWSGI_LDAP

#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

#include <ldap.h>

#ifndef LDAP_OPT_SUCCESS
#define LDAP_OPT_SUCCESS LDAP_SUCCESS
#endif

#ifndef ldap_unbind_ext_s
#define ldap_unbind_ext_s ldap_unbind_ext
#endif

void ldap2uwsgi(char *ldapname, char *uwsginame) {
	char *ptr = uwsginame;

	int i;

	for (i = 0; i < (int) strlen(ldapname); i++) {
		if (isupper((int) ldapname[i])) {
			*ptr++ = '-';
			*ptr++ = tolower((int) ldapname[i]);
		}
		else {
			*ptr++ = ldapname[i];
		}
	}

	*ptr++ = 0;
}

int calc_ldap_name(char *name) {
	int i;
	int counter = 0;

	for (i = 0; i < (int) strlen(name); i++) {
		if (isupper((int) name[i])) {
			counter++;
		}
	}

	return strlen(name) + counter;
}

struct uwsgi_ldap_entry {
	int num;
	char names[1024];
	int has_arg;
};


void uwsgi_name_to_ldap(char *src, char *dst) {

	int i;
	char *ptr = dst;

	memset(dst, 0, 1024);

	strcat(dst, " 'uWSGI");

	ptr += 7;

	for (i = 0; i < (int) strlen(src); i++) {
		if (src[i] == '-') {
			i++;
			*ptr++ = toupper((int) src[i]);
		}
		else {
			*ptr++ = src[i];
		}
	}

	strcat(dst, "'");

}

struct uwsgi_ldap_entry *get_ldap_by_num(struct uwsgi_ldap_entry *root, int num, int count) {

	int i;
	struct uwsgi_ldap_entry *ule;

	for (i = 0; i < count; i++) {
		ule = &root[i];
		if (ule->num == num) {
			return ule;
		}
	}

	return NULL;
}

struct uwsgi_ldap_entry *search_ldap_cache(struct uwsgi_ldap_entry *root, char *name, int count) {
	int i;
	struct uwsgi_ldap_entry *ule;

	for (i = 0; i < count; i++) {
		ule = &root[i];
		if (uwsgi_list_has_str(ule->names, name + 1)) {
			return ule;
		}
	}

	return NULL;
}

struct uwsgi_ldap_entry *get_ldap_names(int *count) {

	struct uwsgi_option *op = uwsgi.options;
	struct uwsgi_ldap_entry *ule, *entry;
	char ldap_name[1024];

	*count = 0;

	ule = uwsgi_malloc(sizeof(struct uwsgi_ldap_entry) * uwsgi_count_options(op));

	while (op && op->name) {

		uwsgi_name_to_ldap((char *) op->name, ldap_name);

		entry = search_ldap_cache(ule, ldap_name, *count);

		if (entry)
			goto next;

		entry = &ule[*count];
		entry->num = *count;
		strcpy(entry->names, ldap_name);
		*count = *count + 1;

		entry->has_arg = op->type;

next:
		op++;
	}

	return ule;
}

void uwsgi_opt_ldap_dump_ldif(char *opt, char *foo, void *bar) {

	int i;
	int items;

	uwsgi_log("\n");
	uwsgi_log("dn: cn=uwsgi,cn=schema,cn=config\n");
	uwsgi_log("objectClass: olcSchemaConfig\n");
	uwsgi_log("cn: uwsgi\n");

	struct uwsgi_ldap_entry *entry, *ule = get_ldap_names(&items);

	for (i = 0; i < items; i++) {

		entry = &ule[i];
		uwsgi_log("olcAttributeTypes: ( 1.3.6.1.4.1.35156.17.4.%d NAME (%s", entry->num, entry->names);

		if (entry->has_arg) {
			uwsgi_log(" ) SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )\n");
		}
		else {
			uwsgi_log(" ) SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )\n");
		}
	}

	uwsgi_log("olcAttributeTypes: ( 1.3.6.1.4.1.35156.17.4.50000 NAME 'uWSGInull' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )\n");


	uwsgi_log("olcObjectClasses: ( 1.3.6.1.4.1.35156.17.3.1 NAME 'uWSGIConfig' SUP top AUXILIARY DESC 'uWSGI configuration' MAY ( ");


	for (i = 0; i < items; i++) {

		entry = &ule[i];

		char *list2 = uwsgi_concat2(entry->names + 1, "");
		char *p = strtok(list2, " ");
		while (p != NULL) {
			uwsgi_log("%.*s $ ", strlen(p) - 2, p + 1);
			p = strtok(NULL, " ");
		}

		free(list2);

	}

	uwsgi_log("uWSGInull ))\n");

	uwsgi_log("\n");

	exit(0);
}

void uwsgi_opt_ldap_dump(char *opt, char *foo, void *bar) {

	int i;
	int items;

	struct uwsgi_ldap_entry *entry, *ule = get_ldap_names(&items);

	for (i = 0; i < items; i++) {

		entry = &ule[i];
		uwsgi_log("attributetype ( 1.3.6.1.4.1.35156.17.4.%d NAME (%s", entry->num, entry->names);

		if (entry->has_arg) {
			uwsgi_log(" ) SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )\n");
		}
		else {
			uwsgi_log(" ) SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )\n");
		}
	}


	uwsgi_log("attributetype ( 1.3.6.1.4.1.35156.17.4.50000 NAME 'uWSGInull' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )\n");

	uwsgi_log("objectclass ( 1.3.6.1.4.1.35156.17.3.1 NAME 'uWSGIConfig' SUP top AUXILIARY DESC 'uWSGI configuration' MAY ( ");

	for (i = 0; i < items; i++) {

		entry = &ule[i];

		char *list2 = uwsgi_concat2(entry->names + 1, "");
		char *p = strtok(list2, " ");
		while (p != NULL) {
			uwsgi_log("%.*s $ ", strlen(p) - 2, p + 1);
			p = strtok(NULL, " ");
		}

		free(list2);

	}




	uwsgi_log("uWSGInull ))\n");

	exit(0);
}

void uwsgi_ldap_config(char *url) {

	LDAP *ldp;
	LDAPMessage *results, *entry;
	BerElement *ber;
	struct berval **bervalues;
	char *attr;
	char *uwsgi_attr;

	char *url_slash;

	int desired_version = LDAP_VERSION3;
	int ret;

	LDAPURLDesc *ldap_url;

	if (!ldap_is_ldap_url(url)) {
		uwsgi_log("invalid LDAP url.\n");
		exit(1);
	}

	if (ldap_url_parse(url, &ldap_url) != LDAP_SUCCESS) {
		uwsgi_log("unable to parse LDAP url.\n");
		exit(1);
	}

	uwsgi_log("[uWSGI] getting LDAP configuration from %s\n", url);

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

#if LDAP_API_VERSION >= 3000
	if ((ret = ldap_initialize(&ldp, url)) != LDAP_SUCCESS) {
		uwsgi_log("LDAP: %s\n", ldap_err2string(ret));
		exit(1);
	}
#else
	if ((ldp = ldap_init(ldap_url->lud_host, ldap_url->lud_port)) == NULL) {
		uwsgi_error("ldap_init()");
		exit(1);
	}
#endif


	if ((ret = ldap_set_option(ldp, LDAP_OPT_PROTOCOL_VERSION, &desired_version)) != LDAP_OPT_SUCCESS) {
		uwsgi_log("LDAP: %s\n", ldap_err2string(ret));
		exit(1);
	}


	if ((ret = ldap_search_ext_s(ldp, ldap_url->lud_dn, ldap_url->lud_scope, ldap_url->lud_filter, NULL, 0, NULL, NULL, NULL, 1, &results)) != LDAP_SUCCESS) {
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

	int found = 0;
	for (attr = ldap_first_attribute(ldp, entry, &ber); attr != NULL; attr = ldap_next_attribute(ldp, entry, ber)) {
		if (!strncmp(attr, "uWSGI", 5)) {

			found = 1;
			uwsgi_attr = malloc(calc_ldap_name(attr) + 1);
			if (!uwsgi_attr) {
				uwsgi_error("malloc()");
				exit(1);
			}

			ldap2uwsgi(attr + 5, uwsgi_attr);

#ifdef UWSGI_DEBUG
			uwsgi_debug("LDAP attribute: %s = --%s\n", attr, uwsgi_attr);
#endif
			bervalues = ldap_get_values_len(ldp, entry, attr);
			if (bervalues) {
				// do not free uwsgi_attr/uwsgi_val;
				char *uwsgi_val = malloc(bervalues[0]->bv_len + 1);
				if (!uwsgi_val) {
					uwsgi_error("malloc()");
					exit(1);
				}

				memcpy(uwsgi_val, bervalues[0]->bv_val, bervalues[0]->bv_len);
				uwsgi_val[bervalues[0]->bv_len] = 0;

				add_exported_option((char *) uwsgi_attr, uwsgi_val, 0);
				free(bervalues);
			}
			else {
				free(uwsgi_attr);
			}
		}
		free(attr);
	}

	if (!found) {
		uwsgi_log("no uWSGI LDAP entry found\n");
		exit(1);
	}

	free(ber);
	free(results);

	ldap_unbind_ext_s(ldp, NULL, NULL);

}
#endif
