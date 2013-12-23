#include <uwsgi.h>

/*
	Authors:

	Roberto De Ioris <roberto@unbit.it> - general LDAP support, reading uWSGI configuration from LDAP servers

	Łukasz Mierzwa <l.mierzwa@gmail.com> - LDAP auth router support
*/

extern struct uwsgi_server uwsgi;

#include <ldap.h>

#ifndef LDAP_OPT_SUCCESS
#define LDAP_OPT_SUCCESS LDAP_SUCCESS
#endif

#ifndef ldap_unbind_ext_s
#define ldap_unbind_ext_s ldap_unbind_ext
#endif

static void uwsgi_opt_ldap_dump(char *, char *, void *);
static void uwsgi_opt_ldap_dump_ldif(char *, char *, void *);
static void uwsgi_ldap_config(char *);

static void uwsgi_opt_load_ldap(char *opt, char *url, void *none) {
        uwsgi_ldap_config(url);
}

static struct uwsgi_option uwsgi_ldap_options[] = {
	{"ldap", required_argument, 0, "load configuration from ldap server", uwsgi_opt_load_ldap, NULL, UWSGI_OPT_IMMEDIATE},
        {"ldap-schema", no_argument, 0, "dump uWSGI ldap schema", uwsgi_opt_ldap_dump, NULL, UWSGI_OPT_IMMEDIATE},
        {"ldap-schema-ldif", no_argument, 0, "dump uWSGI ldap schema in ldif format", uwsgi_opt_ldap_dump_ldif, NULL, UWSGI_OPT_IMMEDIATE},
        {0, 0, 0, 0, 0, 0, 0},
};

static void ldap2uwsgi(char *ldapname, char *uwsginame) {
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

static int calc_ldap_name(char *name) {
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


static void uwsgi_name_to_ldap(char *src, char *dst) {

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

static struct uwsgi_ldap_entry *search_ldap_cache(struct uwsgi_ldap_entry *root, char *name, int count) {
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

static struct uwsgi_ldap_entry *get_ldap_names(int *count) {

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

static void uwsgi_opt_ldap_dump_ldif(char *opt, char *foo, void *bar) {

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
		char *p, *ctx = NULL;
		uwsgi_foreach_token(list2, " ", p, ctx) {
			uwsgi_log("%.*s $ ", strlen(p) - 2, p + 1);
		}

		free(list2);

	}

	uwsgi_log("uWSGInull ))\n");

	uwsgi_log("\n");

	exit(0);
}

static void uwsgi_opt_ldap_dump(char *opt, char *foo, void *bar) {

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
		char *p, *ctx = NULL;
		uwsgi_foreach_token(list2, " ", p, ctx) {
			uwsgi_log("%.*s $ ", strlen(p) - 2, p + 1);
		}

		free(list2);

	}




	uwsgi_log("uWSGInull ))\n");

	exit(0);
}

static void uwsgi_ldap_config(char *url) {

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

#ifdef UWSGI_ROUTING

struct uwsgi_ldapauth_config {
	char *url;
	LDAPURLDesc *ldap_url;
	char *binddn;
	char *bindpw;
	char *basedn;
	char *filter;
	char *login_attr;
	int loglevel;
};

static uint16_t ldap_passwd_check(struct uwsgi_ldapauth_config *ulc, char *auth) {

	char *colon = strchr(auth, ':');
	if (!colon) return 0;

	int ret;
	uint16_t ulen = 0;
	LDAP *ldp;
	int desired_version = LDAP_VERSION3;

#if LDAP_API_VERSION >= 3000
        if ((ret = ldap_initialize(&ldp, ulc->url)) != LDAP_SUCCESS) {
		uwsgi_log("[router-ldapauth] can't connect to LDAP server at %s\n", ulc->url);
		return 0;
        }
#else
	if ((ldp = ldap_init(ulc->ldap_url->lud_host, ulc->ldap_url->lud_port)) == NULL) {
		uwsgi_log("[router-ldapauth] can't connect to LDAP server at %s\n", ulc->url);
		return 0;
	}
#endif

	if ((ret = ldap_set_option(ldp, LDAP_OPT_PROTOCOL_VERSION, &desired_version)) != LDAP_OPT_SUCCESS) {
		uwsgi_log("[router-ldapauth] LDAP protocol version mismatch: %s\n", ldap_err2string(ret));
		goto close;
	}

	// first bind if needed
	if (ulc->binddn && ulc->bindpw) {
#if LDAP_API_VERSION >= 3000
		struct berval bval;
		bval.bv_val = ulc->bindpw;
		bval.bv_len = strlen(bval.bv_val);
		if ((ret = ldap_sasl_bind_s(ldp, ulc->binddn, LDAP_SASL_SIMPLE, &bval, NULL, NULL, NULL)) != LDAP_OPT_SUCCESS) {
#else
		if ((ret = ldap_bind_s(ldp, ulc->binddn, ulc->bindpw, LDAP_AUTH_SIMPLE)) != LDAP_OPT_SUCCESS) {
#endif
			uwsgi_log("[router-ldapauth] can't bind as user '%s' to '%s': %s\n", ulc->binddn, ulc->url, ldap_err2string(ret));
			goto close;
		}
	}

	// search for user
	char *userdn = NULL;
	LDAPMessage *msg, *entry;
	// use the minimal amount of memory
	char *filter = uwsgi_malloc( strlen(ulc->login_attr) + (colon-auth) + strlen(ulc->filter) + 7);
	ret = snprintf(filter, 1024, "(&(%s=%.*s)%s)", ulc->login_attr, (int) (colon-auth), auth, ulc->filter);
	if (ret <= 0 || ret >= 1024) {
		free(filter);
		uwsgi_error("ldap_passwd_check()/sprintfn(filter)");
		goto close;
	}

	if ((ret = ldap_search_ext_s(ldp, ulc->basedn, LDAP_SCOPE_SUBTREE, filter, NULL, 0, NULL, NULL, NULL, 0, &msg)) != LDAP_SUCCESS) {
		free(filter);
		uwsgi_log("[router-ldapauth] search error on '%s': %s\n", ulc->url, ldap_err2string(ret));
		goto close;
	}
	else {
		free(filter);
		entry = ldap_first_entry(ldp, msg);
		while (entry) {
			struct berval **vals = ldap_get_values_len(ldp, entry, ulc->login_attr);
			if (!uwsgi_strncmp(auth, colon-auth, vals[0]->bv_val, vals[0]->bv_len)) {
				userdn = ldap_get_dn(ldp, entry);
				free(vals);
				break;
			}
			free(vals);
			entry = ldap_next_entry(ldp, entry);
		}
		ldap_msgfree(msg);
	}

	if (userdn) {
		// user found in ldap, try to bind

#if LDAP_API_VERSION >= 3000
                struct berval bval;
                bval.bv_val = colon+1;
                bval.bv_len = strlen(bval.bv_val);
                if ((ret = ldap_sasl_bind_s(ldp, userdn, LDAP_SASL_SIMPLE, &bval, NULL, NULL, NULL)) != LDAP_OPT_SUCCESS) {
#else
		if ((ret = ldap_bind_s(ldp, userdn, colon+1, LDAP_AUTH_SIMPLE)) != LDAP_OPT_SUCCESS) {
#endif
			if (ulc->loglevel)
				uwsgi_log("[router-ldapauth] can't bind as user '%s' to '%s': %s\n", userdn, ulc->url, ldap_err2string(ret));
		}
		else {
			if (ulc->loglevel > 1)
				uwsgi_log("[router-ldapauth] successful bind as user '%s' to '%s'\n", userdn, ulc->url);
			ulen = colon-auth;
		}

		ldap_memfree(userdn);
	}
	else if (ulc->loglevel) {
		uwsgi_log("router-ldapauth] user '%.*s' not found in LDAP server at '%s'\n", colon-auth, auth, ulc->url);
	}

close:
	if ((ret = ldap_unbind_ext_s(ldp, NULL, NULL)) != LDAP_OPT_SUCCESS) {
		uwsgi_log("[router-ldapauth] LDAP unbind error: %s\n", ldap_err2string(ret));
	}

	return ulen;
}

int uwsgi_routing_func_ldapauth(struct wsgi_request *wsgi_req, struct uwsgi_route *ur) {

	// skip if already authenticated
	if (wsgi_req->remote_user_len > 0) {
		return UWSGI_ROUTE_NEXT;
	}

	if (wsgi_req->authorization_len > 7 && ur->data2) {
		if (strncmp(wsgi_req->authorization, "Basic ", 6))
			goto forbidden;

		size_t auth_len = 0;
		char *auth = uwsgi_base64_decode(wsgi_req->authorization+6, wsgi_req->authorization_len-6, &auth_len);
		if (auth) {
			if (!ur->custom) {
				uint16_t ulen = ldap_passwd_check(ur->data2, auth);
				if (ulen > 0) {
					wsgi_req->remote_user = uwsgi_req_append(wsgi_req, "REMOTE_USER", 11, auth, ulen); 
					if (wsgi_req->remote_user)
						wsgi_req->remote_user_len = ulen;
				}
				else if (ur->data3_len == 0) {
					free(auth);
					goto forbidden;
				}
			}
			free(auth);
			return UWSGI_ROUTE_NEXT;
		}
	}

forbidden:
	if (uwsgi_response_prepare_headers(wsgi_req, "401 Authorization Required", 26)) goto end;
	char *realm = uwsgi_concat3n("Basic realm=\"", 13, ur->data, ur->data_len, "\"", 1);
	int ret = uwsgi_response_add_header(wsgi_req, "WWW-Authenticate", 16, realm, 13 + ur->data_len + 1);
	free(realm);
	if (ret) goto end;
	uwsgi_response_write_body_do(wsgi_req, "Unauthorized", 12);
end:
	return UWSGI_ROUTE_BREAK;
}

static int uwsgi_router_ldapauth(struct uwsgi_route *ur, char *args) {

	ur->func = uwsgi_routing_func_ldapauth;

	char *comma = strchr(args, ',');
	if (!comma) {
		uwsgi_log("invalid route syntax: %s\n", args);
		exit(1);
	}
	*comma = 0;

	ur->data = args;
	ur->data_len = strlen(args);

	char *url = NULL;
	char *binddn = NULL;
	char *bindpw = NULL;
	char *basedn = NULL;
	char *filter = NULL;
	char *attr = NULL;
	char *loglevel = NULL;
	if (uwsgi_kvlist_parse(comma+1, strlen(comma+1), ';', '=',
		"url", &url,
		"binddn", &binddn,
		"bindpw", &bindpw,
		"basedn", &basedn,
		"filter", &filter,
		"attr", &attr,
		"loglevel", &loglevel,
		NULL)) {
			uwsgi_log("[router-ldapauth] unable to parse options: %s\n", comma+1);
			exit(1);
	}
	else {
		struct uwsgi_ldapauth_config *ulc = uwsgi_malloc(sizeof(struct uwsgi_ldapauth_config));

		if (!basedn) {
			uwsgi_log("[router-ldapauth] missing LDAP base dn (basedn option) on line: %s\n", comma+1);
			exit(1);
		}
		else {
			ulc->basedn = basedn;
		}

		if (!url) {
			uwsgi_log("[router-ldapauth] missing LDAP server url (url option) on line: %s\n", comma+1);
			exit(1);
		}
		else {
			if (!ldap_is_ldap_url(url)) {
				uwsgi_log("[router-ldapauth] invalid LDAP url: %s\n", url);
				exit(1);
			}
			if (ldap_url_parse(url, &ulc->ldap_url) != LDAP_SUCCESS) {
				uwsgi_log("[router-ldapauth] unable to parse LDAP url: %s\n", url);
				exit(1);
				}
		}

		if (!filter) {
			ulc->filter = uwsgi_str("(objectClass=*)");
		}
		else {
			ulc->filter = filter;
		}

		if (!attr) {
			ulc->login_attr = uwsgi_str("uid");
		}
		else {
			ulc->login_attr = attr;
		}

		ulc->url = url;

		ulc->binddn = binddn;
		ulc->bindpw = bindpw;

		if (loglevel) {
			ulc->loglevel = atoi(loglevel);
		}
		else {
			ulc->loglevel = 0;
		}

		ur->data2 = ulc;
	}

	return 0;
}

static int uwsgi_router_ldapauth_next(struct uwsgi_route *ur, char *args) {
	ur->data3_len = 1;
	return uwsgi_router_ldapauth(ur, args);
}
#endif

void uwsgi_ldap_register(void) {
#ifdef UWSGI_ROUTING
	uwsgi_register_router("ldapauth", uwsgi_router_ldapauth);
	uwsgi_register_router("ldapauth-next", uwsgi_router_ldapauth_next);
#endif
}

struct uwsgi_plugin ldap_plugin = {
	.name = "ldap",
	.options = uwsgi_ldap_options,
	.on_load = uwsgi_ldap_register,
};

