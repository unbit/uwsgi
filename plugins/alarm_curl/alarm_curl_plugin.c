#include <uwsgi.h>
#include <curl/curl.h>

extern struct uwsgi_server uwsgi;

struct uwsgi_alarm_curl {
	CURL	*curl;
	struct uwsgi_thread *ut;
	int	pos;
	int	blen;
	char	*body;
	int	hlen;
	char	hdr[];
};

struct uwsgi_alarm_curl_config {
	char *url;
	char *subject;
	char *to;
};

struct uwsgi_alarm_curl_opt {
	char *name;
	CURLoption option;
	void (*func)(CURL *, CURLoption, char *, struct uwsgi_alarm_curl_config*);
};


#ifdef CURLPROTO_SMTP
static void uwsgi_alarm_curl_to(CURL *curl, CURLoption option, char *arg, struct uwsgi_alarm_curl_config *uacc) {
	uacc->to = arg;
	struct curl_slist *list = NULL;
	char *items = uwsgi_str(arg);
	char *ctx = NULL;
	char *p = strtok_r(items, ",", &ctx);
	while(p) {
		list = curl_slist_append(list, p);
		p = strtok_r(NULL, ",", &ctx);
	}
	curl_easy_setopt(curl, option, list);
	free(items);
}
#endif

static void uwsgi_alarm_curl_ssl(CURL *curl, CURLoption option, char *arg, struct uwsgi_alarm_curl_config *uacc) {
	curl_easy_setopt(curl, option, (long)CURLUSESSL_ALL);
}

static void uwsgi_alarm_curl_int(CURL *curl, CURLoption option, char *arg, struct uwsgi_alarm_curl_config *uacc) {
        curl_easy_setopt(curl, option, atoi(arg));
}

static void uwsgi_alarm_curl_set_subject(CURL *curl, CURLoption option, char *arg, struct uwsgi_alarm_curl_config *uacc) {
	uacc->subject = arg;	
}

static void uwsgi_alarm_curl_url(CURL *curl, CURLoption option, char *arg, struct uwsgi_alarm_curl_config *uacc)
{
#ifndef CURLPROTO_SMTP
	if (!uwsgi_strnicmp(arg, 4, "smtp", 4)) {
		uwsgi_error("Please update libcurl to use SMTP protocol.\n");
		exit(1);
	}
#endif
	uacc->url = arg;
	curl_easy_setopt(curl, option, arg);
}

static void uwsgi_alarm_curl_ssl_insecure(CURL *curl, CURLoption option, char *arg, struct uwsgi_alarm_curl_config *uacc)
{
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
}

static struct uwsgi_alarm_curl_opt uaco[] = {
	{"url", CURLOPT_URL, uwsgi_alarm_curl_url},
#ifdef CURLPROTO_SMTP
	{"mail_to", CURLOPT_MAIL_RCPT, uwsgi_alarm_curl_to},
	{"mail_from", CURLOPT_MAIL_FROM, NULL},
#endif
	{"subject", 0, uwsgi_alarm_curl_set_subject},
	{"ssl", CURLOPT_USE_SSL, uwsgi_alarm_curl_ssl},
	{"ssl_insecure", 0, uwsgi_alarm_curl_ssl_insecure},
	{"auth_user", CURLOPT_USERNAME, NULL},
	{"auth_pass", CURLOPT_PASSWORD, NULL},
	{"method", CURLOPT_CUSTOMREQUEST, NULL},
	{"timeout", CURLOPT_TIMEOUT, uwsgi_alarm_curl_int},
	{"conn_timeout", CURLOPT_CONNECTTIMEOUT, uwsgi_alarm_curl_int},
	{NULL, 0, NULL},
};

static void uwsgi_alarm_curl_setopt(CURL *curl, char *opt, struct uwsgi_alarm_curl_config *uacc) {
	struct uwsgi_alarm_curl_opt *o = uaco;
	char *equal = strchr(opt,'=');
	if (!equal || !uacc->url) {
		uwsgi_alarm_curl_url(curl, CURLOPT_URL, opt, uacc);
		return;
	}
	*equal = 0;
	while(o->name) {
		if (!strcmp(o->name, opt)) {
			if (o->func) {
				o->func(curl, o->option, equal+1, uacc);
			}
			else {
				curl_easy_setopt(curl, o->option, equal+1);
			}
			break;
		}
		o++;
	}
}

static size_t uwsgi_alarm_curl_read_callback(void *ptr, size_t size, size_t nmemb, void *userp) {
	struct uwsgi_alarm_curl *uac = userp;
	size_t full_size = size * nmemb;
	int remains = full_size;

	if (uac->pos < uac->hlen) {
		if (remains > uac->hlen - uac->pos) {
			memcpy(ptr, uac->hdr + uac->pos, uac->hlen - uac->pos);
			ptr += uac->hlen - uac->pos;
			remains -= uac->hlen - uac->pos;
			uac->pos = uac->hlen;
		} else {
			memcpy(ptr, uac->hdr + uac->pos, remains);
			uac->pos += remains;
			return full_size;
		}
	}

	if (remains > uac->blen + uac->hlen - uac->pos) {
		memcpy(ptr, uac->body + uac->pos - uac->hlen, uac->blen + uac->hlen - uac->pos);
		remains -= uac->blen + uac->hlen - uac->pos;
		uac->pos = uac->blen + uac->hlen;
		return full_size - remains;
	}

	memcpy(ptr, uac->body + uac->pos - uac->hlen, remains);
	uac->pos += remains;
	return full_size;
}

static struct uwsgi_alarm_curl *uwsgi_alarm_curl_alloc(struct uwsgi_alarm_curl_config *uacc)
{
	char *addr;
	struct uwsgi_alarm_curl *uac;
	size_t required = 0;

	if (uacc->to) required += 4 + strlen(uacc->to) + 2;
	if (uacc->subject) required += 9 + strlen(uacc->subject) + 2;
	if (required)
		required += 2;	/* newline between MIME header and body */

	uac = uwsgi_malloc(sizeof(*uac) + required);
	uac->hlen = required;
	addr = uac->hdr;

	if (uacc->to) {
		memcpy(addr, "To: ", 4); addr += 4;
		memcpy(addr, uacc->to, strlen(uacc->to)); addr += strlen(uacc->to);
		*addr++ = '\r';
		*addr++ = '\n';
	}

	if (uacc->subject) {
		memcpy(addr, "Subject: ", 9); addr += 9;
		memcpy(addr, uacc->subject, strlen(uacc->subject)); addr += strlen(uacc->subject);
		*addr++ = '\r';
		*addr++ = '\n';
	}

	if (required) {
		*addr++ = '\r';
		*addr = '\n';
	}

	return uac;
}

static struct uwsgi_alarm_curl *uwsgi_alarm_curl_init_curl(struct uwsgi_alarm_instance *uai) {
	CURL *curl = curl_easy_init();
	if (!curl) {
		uwsgi_error("Failed to initialize libcurl.\n");
		exit(1);
	}

	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, uwsgi.socket_timeout);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, uwsgi.socket_timeout);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, uwsgi_alarm_curl_read_callback);
	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	struct curl_slist *expect = NULL; expect = curl_slist_append(expect, "Expect:");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, expect);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);

	struct uwsgi_alarm_curl_config uacc;
	memset(&uacc, 0, sizeof(uacc));
	char *opts = uwsgi_str(uai->arg);

	// fill curl options
	char *ctx = NULL;
	char *p = strtok_r(opts, ";", &ctx);
	while(p) {
		uwsgi_alarm_curl_setopt(curl, p, &uacc);
		p = strtok_r(NULL, ";", &ctx);
	}

	if (!uacc.url) {
		uwsgi_error("An URL is required to trigger curl-based alarm.\n");
		exit(1);
	}

	struct uwsgi_alarm_curl *uac = uwsgi_alarm_curl_alloc(&uacc);
	curl_easy_setopt(curl, CURLOPT_READDATA, uac);
	free(opts);
	uac->curl = curl;
	uai->data_ptr = uac;

	return uac;
}

static void uwsgi_alarm_curl_call_curl(struct uwsgi_alarm_curl *uac, char *msg, int len)
{
	uac->pos = 0;
	uac->body = msg;
	uac->blen = len;
	curl_easy_setopt(uac->curl, CURLOPT_INFILESIZE, uac->hlen + uac->blen);
	CURLcode res = curl_easy_perform(uac->curl);
	if (res != CURLE_OK)
		uwsgi_log_alarm("-curl] curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
}

static void uwsgi_alarm_curl_loop(struct uwsgi_thread *ut) {
	int interesting_fd;
	struct uwsgi_alarm_curl *uac = uwsgi_alarm_curl_init_curl(ut->data);
	uac->ut = ut;
	ut->buf = uwsgi_malloc(uwsgi.log_master_bufsize);
	for(;;) {
		int ret = event_queue_wait(ut->queue, -1, &interesting_fd);	
		if (ret < 0) return;
		if (ret == 0) continue;
		if (interesting_fd != ut->pipe[1]) continue;
		ssize_t rlen = read(ut->pipe[1], ut->buf, uwsgi.log_master_bufsize);
		if (rlen <= 0) continue;
		uwsgi_alarm_curl_call_curl(uac, ut->buf, rlen);
	}
}

static void uwsgi_alarm_curl_init(struct uwsgi_alarm_instance *uai) {
	if (uwsgi.alarm_cheap)
		uwsgi_alarm_curl_init_curl(uai);
	else
		uwsgi_thread_new_with_data(uwsgi_alarm_curl_loop, uai);
}

// pipe the message into the thread;
static void uwsgi_alarm_curl_func(struct uwsgi_alarm_instance *uai, char *msg, size_t len) {
	struct uwsgi_alarm_curl *uac = uai->data_ptr;
	if (uwsgi.alarm_cheap)
		uwsgi_alarm_curl_call_curl(uac, msg, len);
	else {
		struct uwsgi_thread *ut = uac->ut;
		ut->rlen = write(ut->pipe[0], msg, len);
	}
}

static void uwsgi_alarm_curl_load(void) {
	uwsgi_register_alarm("curl", uwsgi_alarm_curl_init, uwsgi_alarm_curl_func);
}

struct uwsgi_plugin alarm_curl_plugin = {
	.name = "alarm_curl",
	.on_load = uwsgi_alarm_curl_load,
};
