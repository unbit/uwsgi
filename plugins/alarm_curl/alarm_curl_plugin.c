#include "../../uwsgi.h"
#include <curl/curl.h>

extern struct uwsgi_server uwsgi;

struct uwsgi_alarm_curl_config {
	int first;
	char *arg;
	char *subject;
	char *to;
};

struct uwsgi_alarm_curl_opt {
	char *name;
	CURLoption option;
	void (*func)(CURL *, CURLoption, char *, struct uwsgi_alarm_curl_config*);
};


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
}

static void uwsgi_alarm_curl_ssl(CURL *curl, CURLoption option, char *arg, struct uwsgi_alarm_curl_config *uacc) {
	curl_easy_setopt(curl, option, (long)CURLUSESSL_ALL);
}

static void uwsgi_alarm_curl_int(CURL *curl, CURLoption option, char *arg, struct uwsgi_alarm_curl_config *uacc) {
        curl_easy_setopt(curl, option, atoi(arg));
}

static void uwsgi_alarm_curl_set_subject(CURL *curl, CURLoption option, char *arg, struct uwsgi_alarm_curl_config *uacc) {
	uacc->subject = arg;	
}

static struct uwsgi_alarm_curl_opt uaco[] = {
	{"url", CURLOPT_URL, NULL},
	{"mail_to", CURLOPT_MAIL_RCPT, uwsgi_alarm_curl_to },
	{"mail_from", CURLOPT_MAIL_FROM, NULL},
	{"subject", 0, uwsgi_alarm_curl_set_subject},
	{"ssl", CURLOPT_USE_SSL, uwsgi_alarm_curl_ssl},
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

static size_t uwsgi_alarm_curl_read_callback(void *ptr, size_t size, size_t nmemb, void *userp) {
	struct uwsgi_thread *ut = (struct uwsgi_thread *) userp;
	size_t full_size = size * nmemb;
	size_t remains = ut->len - ut->pos;
	struct uwsgi_alarm_curl_config *uacc = ut->data;

	if (remains == 0) return 0;

	if (ut->custom0 == 0) {
		size_t newline = 0;
		size_t required = 1;
		char *addr = ptr;
		if (uacc->to) required += 4 + strlen(uacc->to) + 1;
		if (uacc->subject) required += 9 + strlen(uacc->subject) + 1;
		if (required > full_size) goto skip;


		if (uacc->to) {
			memcpy(addr, "To: ", 4); addr+=4;
			memcpy(addr, uacc->to, strlen(uacc->to)); addr += strlen(uacc->to);
			*addr ++= '\n';
			newline = 1;
		}

		if (uacc->subject) {
			memcpy(addr, "Subject: ", 9); addr+=9;
			memcpy(addr, uacc->subject, strlen(uacc->subject)); addr += strlen(uacc->subject);
			*addr ++= '\n';
			newline = 1;
		}
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

static void uwsgi_alarm_curl_loop(struct uwsgi_thread *ut) {
	int interesting_fd;
	ut->buf = uwsgi_malloc(uwsgi.log_master_bufsize);

	CURL *curl = curl_easy_init();
	// ARGH !!!
	if (!curl) return;

	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, uwsgi.shared->options[UWSGI_OPTION_SOCKET_TIMEOUT]);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, uwsgi_alarm_curl_read_callback);
	curl_easy_setopt(curl, CURLOPT_READDATA, ut);
	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	struct curl_slist *expect = NULL; expect = curl_slist_append(expect, "Expect:");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, expect);

	struct uwsgi_alarm_curl_config *uacc = (struct uwsgi_alarm_curl_config *) ut->data;
	char *opts = uwsgi_str(uacc->arg);

	// fill curl options
	char *ctx = NULL;
	char *p = strtok_r(opts, ";", &ctx);
	while(p) {
		uwsgi_alarm_curl_setopt(curl, uwsgi_str(p), uacc);
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
		curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t) ut->len);
		CURLcode res = curl_easy_perform(curl);
		if (res != CURLE_OK) {
			uwsgi_log_alarm("-curl] curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		}
		
	}
}

static void uwsgi_alarm_curl_init(struct uwsgi_alarm_instance *uai) {
	struct uwsgi_thread *ut = uwsgi_thread_new(uwsgi_alarm_curl_loop);
	if (!ut) return;
	uai->data_ptr = ut;
	struct uwsgi_alarm_curl_config *uacc = uwsgi_calloc(sizeof(struct uwsgi_alarm_curl_config));
	uacc->arg = uai->arg;
	ut->data = uacc;
}

// pipe the message into the thread;
static void uwsgi_alarm_curl_func(struct uwsgi_alarm_instance *uai, char *msg, size_t len) {
	struct uwsgi_thread *ut = (struct uwsgi_thread *) uai->data_ptr;
	ut->rlen = write(ut->pipe[0], msg, len);
}

static void uwsgi_alarm_curl_load(void) {
	uwsgi_register_alarm("curl", uwsgi_alarm_curl_init, uwsgi_alarm_curl_func);
}

struct uwsgi_plugin alarm_curl_plugin = {
	.name = "alarm_curl",
	.on_load = uwsgi_alarm_curl_load,
};
