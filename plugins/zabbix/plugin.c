#include <uwsgi.h>

/*

this is a stats pusher plugin for the zabbix server:

--stats-push zabbix:address[,prefix]

example:

--stats-push zabbix:127.0.0.1:10051,myinstance

it exports values exposed by the metric subsystem

*/

extern struct uwsgi_server uwsgi;

static char *zabbix_template = NULL;

static void uwsgi_opt_zabbix_template(char *opt, char *value, void *none) {
	if (value) {
		zabbix_template = value;
	}
	else {
		zabbix_template = "";
	}
}

static struct uwsgi_option zabbix_options[] = {
	{"zabbix-template", optional_argument, 0, "print (or store to a file) the zabbix template for the current metrics setup", uwsgi_opt_zabbix_template, NULL, UWSGI_OPT_METRICS},
        {0, 0, 0, 0, 0, 0, 0},
};

// configuration of a zabbix node
struct zabbix_node {
	char *addr;
	char *prefix;
	uint16_t prefix_len;
	// we reuse the same buffer
	struct uwsgi_buffer *ub;
};

/*
{
	"request":"sender data",
	"data": [
		{"host":uwsgi.hostname, "key":"foo", "value":"bar"},
		...
	]
}
*/

static void stats_pusher_zabbix(struct uwsgi_stats_pusher_instance *uspi, time_t now, char *json, size_t json_len) {

	if (!uspi->configured) {
		struct zabbix_node *zn = uwsgi_calloc(sizeof(struct zabbix_node));
		if (!uspi->arg || strlen(uspi->arg) == 0) {
			zn->addr = uwsgi_str("127.0.0.1:10051");
		}
		else {
			zn->addr = uwsgi_str(uspi->arg);
		}
		char *comma = strchr(zn->addr, ',');
		if (comma) {
			zn->prefix = comma+1;
			zn->prefix_len = strlen(zn->prefix);
			*comma = 0;
		}
		else {
			zn->prefix = "uwsgi";
			zn->prefix_len = 5;
		}

		zn->ub = uwsgi_buffer_new(uwsgi.page_size);
		uwsgi_buffer_append(zn->ub, "ZBXD\1\0\0\0\0\0\0\0\0{\"request\":\"sender data\",\"data\":[", 46);
		uspi->data = zn;
		uspi->configured = 1;
	}

	struct zabbix_node *zn = (struct zabbix_node *) uspi->data ;
	// we use the same buffer for all of the packets
	zn->ub->pos = 46;
	struct uwsgi_metric *um = uwsgi.metrics;
	int error = 0;
	uwsgi_rlock(uwsgi.metrics_lock);
	while(um) {
		if (uwsgi_buffer_append(zn->ub, "{\"host\":\"", 9)) { error = 1; goto end;} 	
		if (uwsgi_buffer_append(zn->ub, uwsgi.hostname, uwsgi.hostname_len)) { error = 1; goto end;} 	
		if (uwsgi_buffer_append(zn->ub, "\",\"key\":\"", 9)) { error = 1; goto end;} 	
		if (uwsgi_buffer_append(zn->ub, zn->prefix, zn->prefix_len)) { error = 1; goto end;}
		if (uwsgi_buffer_append(zn->ub, ".", 1)) { error = 1; goto end;} 
		if (uwsgi_buffer_append(zn->ub, um->name, um->name_len)) { error = 1; goto end;} 	
		if (uwsgi_buffer_append(zn->ub, "\",\"value\":\"", 11)) { error = 1; goto end;} 	
		if (uwsgi_buffer_num64(zn->ub, *um->value)) { error = 1; goto end;} 	
		if (uwsgi_buffer_append(zn->ub, "\"}", 2)) { error = 1; goto end;} 	
		if (um->reset_after_push){
			uwsgi_rwunlock(uwsgi.metrics_lock);
			uwsgi_wlock(uwsgi.metrics_lock);
			*um->value = um->initial_value;
			uwsgi_rwunlock(uwsgi.metrics_lock);
			uwsgi_rlock(uwsgi.metrics_lock);
		}
		um = um->next;
		if (um) {
			if (uwsgi_buffer_append(zn->ub, ",", 1)) { error = 1; goto end;} 
		}
	}
	if (uwsgi_buffer_append(zn->ub, "]}", 2))  error = 1;
end:
	uwsgi_rwunlock(uwsgi.metrics_lock);

	if (error) return;
	uint64_t pktsize  = zn->ub->pos - 13;
	zn->ub->pos = 5;
	if (uwsgi_buffer_u64le(zn->ub, pktsize)) error = 1;

	if (error) return;

	int fd = uwsgi_connect(zn->addr, uwsgi.socket_timeout, 0);
	if (fd < 0) {
		uwsgi_error("stats_pusher_zabbix()/connect()");
		return;
	}

	if (write(fd, zn->ub->buf, pktsize + 13) != (ssize_t) (pktsize + 13)) {
		uwsgi_error("stats_pusher_zabbix()/write()");
	}

	// fake read for simplify debug with strace
	char buf[4096];
	if (read(fd, buf, 4096) <= 0) {
		uwsgi_error("stats_pusher_zabbix()/read()");
	}
	close(fd);
}

static void stats_pusher_zabbix_init(void) {
        struct uwsgi_stats_pusher *usp = uwsgi_register_stats_pusher("zabbix", stats_pusher_zabbix);
	// we use a custom format not the JSON one
	usp->raw = 1;
}

static void zabbix_template_print() {
	if (!zabbix_template) return;

	int fd = 1 ;

	if (zabbix_template[0] != 0) {
		fd = open(zabbix_template, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP);
		if (fd < 0) {
			uwsgi_error_open(zabbix_template);
			exit(1);
		}
	}

	struct uwsgi_metric *um = uwsgi.metrics;
	struct uwsgi_buffer *ub = uwsgi_buffer_new(uwsgi.page_size);
	if (uwsgi_buffer_append(ub,"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n", 39)) goto error;
	if (uwsgi_buffer_append(ub,"<zabbix_export>\n", 16)) goto error;
	if (uwsgi_buffer_append(ub,"<version>2.0</version><groups><group><name>uWSGI</name></group></groups>\n", 73)) goto error;
	if (uwsgi_buffer_append(ub,"\t<templates><template><template>uWSGI metrics</template><name>uWSGI metrics</name>\n", 83)) goto error;
	if (uwsgi_buffer_append(ub,"\t<groups><group><name>uWSGI</name></group></groups>\n", 52)) goto error;
	if (uwsgi_buffer_append(ub,"\t<items>\n", 9)) goto error;
	while(um) {
		if (uwsgi_buffer_append(ub,"\t\t<item>\n", 9)) goto error;
		if (uwsgi_buffer_append(ub,"\t\t\t<name>", 9)) goto error;
		if (uwsgi_buffer_append(ub, um->name, um->name_len)) goto error;
		if (uwsgi_buffer_append(ub,"</name>\n", 8)) goto error;
		if (uwsgi_buffer_append(ub,"\t\t\t<type>2</type>\n", 18)) goto error;
		if (uwsgi_buffer_append(ub,"\t\t\t<key>", 8)) goto error;
		if (uwsgi_buffer_append(ub, um->name, um->name_len)) goto error;
		if (uwsgi_buffer_append(ub,"</key>\n", 7)) goto error;
		if (uwsgi_buffer_append(ub,"\t\t\t<value_type>3</value_type>\n", 30)) goto error;
		if (uwsgi_buffer_append(ub,"\t\t</item>\n", 10)) goto error;
		um = um->next;
	}
	if (uwsgi_buffer_append(ub,"\t</items></template></templates>\n", 33)) goto error;
	if (uwsgi_buffer_append(ub,"</zabbix_export>\n", 17)) goto error;

	if (write(fd, ub->buf, ub->pos) != (ssize_t) ub->pos) {
		uwsgi_error("zabbix_template_print()/wrtie()");
		exit(1);
	}

	uwsgi_buffer_destroy(ub);
	if (zabbix_template[0] != 0) {
		uwsgi_log("zabbix template written to %s\n", zabbix_template);
		close(fd);
	}
	return;
error:
	uwsgi_buffer_destroy(ub);
	uwsgi_log("error generating zabbix template\n");
	exit(1);
}

struct uwsgi_plugin zabbix_plugin = {

        .name = "zabbix",
	.options = zabbix_options,
        .on_load = stats_pusher_zabbix_init,
	.preinit_apps = zabbix_template_print,
};

