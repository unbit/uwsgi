#include <uwsgi.h>
#include <libxml/parser.h>
#include <curl/curl.h>

extern struct uwsgi_server uwsgi;

struct uwsgi_airbrake_config {
	int first;
	char *arg;
	char *apikey;
};

struct uwsgi_airbrake_opt {
	char *name;
	CURLoption option;
	void (*func)(CURL *, CURLoption, char *, struct uwsgi_airbrake_config*);
};

static void uwsgi_airbrake_ssl(CURL *curl, CURLoption option, char *arg, struct uwsgi_airbrake_config *uacc) {
	curl_easy_setopt(curl, option, (long)CURLUSESSL_ALL);
}

static void uwsgi_airbrake_int(CURL *curl, CURLoption option, char *arg, struct uwsgi_airbrake_config *uacc) {
        curl_easy_setopt(curl, option, atoi(arg));
}

static void uwsgi_airbrake_set_apikey(CURL *curl, CURLoption option, char *arg, struct uwsgi_airbrake_config *uacc) {
	uacc->apikey = arg;
}

static struct uwsgi_airbrake_opt uaco[] = {
	{"url", CURLOPT_URL, NULL},
	{"apikey", 0, uwsgi_airbrake_set_apikey},
	{"ssl", CURLOPT_USE_SSL, uwsgi_airbrake_ssl},
	{"timeout", CURLOPT_TIMEOUT, uwsgi_airbrake_int},
	{"conn_timeout", CURLOPT_CONNECTTIMEOUT, uwsgi_airbrake_int},
	{NULL, 0, NULL},
};

static void uwsgi_airbrake_setopt(CURL *curl, char *opt, struct uwsgi_airbrake_config *uacc) {
	struct uwsgi_airbrake_opt *o = uaco;
	char *equal = strchr(opt,'=');
	if (!equal) {
		if (!uacc->first) {
			curl_easy_setopt(curl, CURLOPT_URL, opt);
			uacc->first = 1;
		}
		return;
	}
	uacc->first = 1;
	*equal = 0;
	while(o->name) {
		if (!strcmp(o->name, opt)) {
			if (o->func) {
				o->func(curl, o->option, equal+1, uacc);
			}
			else {
				curl_easy_setopt(curl, o->option, equal+1);
			}
			goto end;
		}
		o++;
	}
end:
	*equal = '=';
}

static size_t uwsgi_airbrake_read_callback(void *ptr, size_t size, size_t nmemb, void *userp) {
	struct uwsgi_thread *ut = (struct uwsgi_thread *) userp;
	size_t full_size = size * nmemb;
	size_t remains = ut->len - ut->pos;

	if (remains == 0) return 0;

	if (ut->custom0 == 0) {
		size_t newline = 0;
		size_t required = 1;
		char *addr = ptr;
		if (required > full_size) goto skip;

skip:
		if (newline > 0) {
			*addr = '\n';
		}
		ut->custom0 = 1;
		return required;
	}

	if (full_size < remains) {
		remains = full_size;
	}

	memcpy(ptr, ut->buf + ut->pos, remains);
	ut->pos += remains;

	return remains;
}

static void uwsgi_format_airbrake_backtrace(struct uwsgi_thread *ut, char *apikey) {

	xmlChar *xmlbuff;
	int buffersize;
	xmlDocPtr doc = NULL;
	xmlNodePtr notice_node = NULL, node = NULL, line_node = NULL, errnode = NULL;
	char *msg = uwsgi_str("uWSGI segfault");

	doc = xmlNewDoc(BAD_CAST "1.0");
	notice_node = xmlNewNode(NULL, BAD_CAST "notice");
	xmlNewProp(notice_node, BAD_CAST "version", BAD_CAST "2.3");
	xmlDocSetRootElement(doc, notice_node);

	xmlNewChild(notice_node, NULL, BAD_CAST "api-key", BAD_CAST apikey);

	node = xmlNewChild(notice_node, NULL, BAD_CAST "notifier", NULL);
	xmlNewChild(node, NULL, BAD_CAST "name", BAD_CAST "uWSGI");
	xmlNewChild(node, NULL, BAD_CAST "version", BAD_CAST UWSGI_VERSION);
	xmlNewChild(node, NULL, BAD_CAST "url", BAD_CAST "https://github.com/unbit/uwsgi");

	errnode = xmlNewChild(notice_node, NULL, BAD_CAST "error", NULL);
	xmlNewChild(errnode, NULL, BAD_CAST "class", BAD_CAST "RuntimeError");
	node = xmlNewChild(errnode, NULL, BAD_CAST "backtrace", NULL);

	char *p = strtok(ut->buf, "\n");
	int i = 0;
	while (p) {
		// skip log messages
		if (!uwsgi_startswith(p, "***", 3))
			goto next;
		i++;
		// skip last 2 backtrace lines, real bt starts after them
		if (i <= 2) {
			goto next;
		}
		// backtrace line looks like this: uwsgi(simple_loop_run+0xc5) [0x451555]
		// we take binary/lib as filename
		// and extract method name from remaining string
		char *n = strchr(p, '(');
		if (n) {
			line_node = xmlNewChild(node, NULL, BAD_CAST "line", NULL);
			*n = 0;

			char *pls = strchr(n+1, '+');
			if (pls) {
				*pls = 0;
			}

			if (i == 3) {
				free(msg);
				if (strlen(n+1)) {
					msg = uwsgi_concat4("uWSGI segfault at ", n+1, " in ", p);
				}
				else {
					// method name might be missing
					msg = uwsgi_concat2("uWSGI segfault in ", p);
				}
			}

			if ((n+1)[0] == ')') {
				xmlNewProp(line_node, BAD_CAST "method", BAD_CAST "()");
			}
			else {
				xmlNewProp(line_node, BAD_CAST "method", BAD_CAST n+1);
			}

			xmlNewProp(line_node, BAD_CAST "file", BAD_CAST p);

			xmlNewProp(line_node, BAD_CAST "number", BAD_CAST "0");
		}
next:
		p = strtok(NULL, "\n");
	}

	xmlNewChild(errnode, NULL, BAD_CAST "message", BAD_CAST msg);

	node = xmlNewChild(notice_node, NULL, BAD_CAST "server-environment", NULL);
	xmlNewChild(node, NULL, BAD_CAST "environment-name", BAD_CAST UWSGI_VERSION);
	xmlNewChild(node, NULL, BAD_CAST "app-version", BAD_CAST UWSGI_VERSION);

	xmlDocDumpFormatMemory(doc, &xmlbuff, &buffersize, 1);

	xmlFreeDoc(doc);
	xmlCleanupParser();
	xmlMemoryDump();

	free(ut->buf);
	free(msg);
	ut->buf = (char *) xmlbuff;
	ut->len = strlen(ut->buf);
}


static void uwsgi_airbrake_loop(struct uwsgi_thread *ut) {
	int interesting_fd;
	ut->buf = uwsgi_malloc(uwsgi.log_master_bufsize);

	CURL *curl = curl_easy_init();
	// ARGH !!!
	if (!curl) return;

	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, uwsgi_airbrake_read_callback);
	curl_easy_setopt(curl, CURLOPT_READDATA, ut);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	struct curl_slist *expect = NULL; expect = curl_slist_append(expect, "Expect:");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, expect);

	struct uwsgi_airbrake_config *uacc = (struct uwsgi_airbrake_config *) ut->data;
	char *opts = uwsgi_str(uacc->arg);

	// fill curl options
	char *ctx = NULL;
	char *p = strtok_r(opts, ";", &ctx);
	while(p) {
		uwsgi_airbrake_setopt(curl, uwsgi_str(p), uacc);
		p = strtok_r(NULL, ";", &ctx);
	}

	for(;;) {
		int ret = event_queue_wait(ut->queue, -1, &interesting_fd);
		if (ret <= 0) continue;
		if (interesting_fd != ut->pipe[1]) continue;
		ssize_t rlen = read(ut->pipe[1], ut->buf, uwsgi.log_master_bufsize);
		if (rlen <= 0) continue;
		ut->pos = 0;
		ut->len = (size_t) rlen;
		ut->custom0 = 0;

		uwsgi_format_airbrake_backtrace(ut, uacc->apikey);

		curl_slist_append(expect, "Accept: */*");
		curl_slist_append(expect, "Content-Type: text/xml; charset=utf-8");
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, expect);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, ut->buf);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, ut->len);

		curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t) ut->len);
		CURLcode res = curl_easy_perform(curl);
		if (res != CURLE_OK) {
			uwsgi_log_alarm("-curl] curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		}
	}
}

static void uwsgi_airbrake_init(struct uwsgi_alarm_instance *uai) {
	struct uwsgi_thread *ut = uwsgi_thread_new(uwsgi_airbrake_loop);
	if (!ut) return;
	uai->data_ptr = ut;
	struct uwsgi_airbrake_config *uacc = uwsgi_calloc(sizeof(struct uwsgi_airbrake_config));
	uacc->arg = uai->arg;
	ut->data = uacc;
}

static void uwsgi_airbrake_func(struct uwsgi_alarm_instance *uai, char *msg, size_t len) {
	struct uwsgi_thread *ut = (struct uwsgi_thread *) uai->data_ptr;
	ut->rlen = write(ut->pipe[0], msg, len);
}

static void uwsgi_airbrake_load(void) {
	uwsgi_register_alarm("airbrake", uwsgi_airbrake_init, uwsgi_airbrake_func);
}

struct uwsgi_plugin airbrake_plugin = {
	.name = "airbrake",
	.on_load = uwsgi_airbrake_load,
};

