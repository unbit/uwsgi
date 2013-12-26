#include <uwsgi.h>
#include <curl/curl.h>

extern struct uwsgi_server uwsgi;

static void curl_cron_func(struct uwsgi_cron *uc, time_t now) {
        CURL *curl = curl_easy_init();
        // ARGH !!!
        if (!curl) return;

        curl_easy_setopt(curl, CURLOPT_URL, uc->command);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, uwsgi.socket_timeout);
        // use 1 minute as the cron resolution
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60);
        uwsgi_log("[uwsgi-curl-cron] requesting %s\n", uc->command);
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
                uwsgi_log("[uwsgi-curl-cron] curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        curl_easy_cleanup(curl);
}

static void uwsgi_opt_add_cron_curl(char *opt, char *value, void *foobar) {
	struct uwsgi_cron *uc = uwsgi_cron_add(value);
	uc->func = curl_cron_func;
}

#ifdef UWSGI_SSL
static void uwsgi_opt_add_legion_cron_curl(char *opt, char *value, void *foobar) {
        char *space = strchr(value, ' ');
        if (!space) {
                uwsgi_log("invalid %s syntax, must be prefixed with a legion name\n", opt);
                exit(1);
        }
        char *legion = uwsgi_concat2n(value, space-value, "", 0);
        struct uwsgi_cron *uc = uwsgi_cron_add(space+1);
        uc->legion = legion;
	uc->func = curl_cron_func;
}
#endif

static struct uwsgi_option curl_cron_options[] = {
	{"curl-cron", required_argument, 0, "add a cron task invoking the specified url via CURL", uwsgi_opt_add_cron_curl, NULL, UWSGI_OPT_MASTER},
	{"cron-curl", required_argument, 0, "add a cron task invoking the specified url via CURL", uwsgi_opt_add_cron_curl, NULL, UWSGI_OPT_MASTER},
#ifdef UWSGI_SSL
        {"legion-curl-cron", required_argument, 0, "add a cron task invoking the specified url via CURL runnable only when the instance is a lord of the specified legion", uwsgi_opt_add_legion_cron_curl, NULL, UWSGI_OPT_MASTER},
        {"legion-cron-curl", required_argument, 0, "add a cron task invoking the specified url via CURL runnable only when the instance is a lord of the specified legion", uwsgi_opt_add_legion_cron_curl, NULL, UWSGI_OPT_MASTER},
        {"curl-cron-legion", required_argument, 0, "add a cron task invoking the specified url via CURL runnable only when the instance is a lord of the specified legion", uwsgi_opt_add_legion_cron_curl, NULL, UWSGI_OPT_MASTER},
        {"cron-curl-legion", required_argument, 0, "add a cron task invoking the specified url via CURL runnable only when the instance is a lord of the specified legion", uwsgi_opt_add_legion_cron_curl, NULL, UWSGI_OPT_MASTER},
#endif
	{ 0, 0, 0, 0, 0, 0, 0},
};

struct uwsgi_plugin curl_cron_plugin = {
	.name = "curl_cron",
	.options = curl_cron_options,
};
