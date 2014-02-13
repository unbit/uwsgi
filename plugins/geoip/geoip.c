#include <uwsgi.h>

#include <GeoIP.h>
#include <GeoIPCity.h>

struct uwsgi_geoip {
	char *country_db;
	char *city_db;
	GeoIP *country;
	GeoIP *city;
	int use_disk;
	
} ugeoip;

struct uwsgi_option uwsgi_geoip_options[] = {
        {"geoip-country", required_argument, 0, "load the specified geoip country database", uwsgi_opt_set_str, &ugeoip.country_db, 0},
        {"geoip-city", required_argument, 0, "load the specified geoip city database", uwsgi_opt_set_str, &ugeoip.city_db, 0},
        {"geoip-use-disk", no_argument, 0, "do not cache geoip databases in memory", uwsgi_opt_true, &ugeoip.use_disk, 0},
	UWSGI_END_OF_OPTIONS
};

static int uwsgi_geoip_init() {
	if (ugeoip.country_db) {
		ugeoip.country = GeoIP_open(ugeoip.country_db, ugeoip.use_disk ? GEOIP_STANDARD : GEOIP_MEMORY_CACHE);
		if (!ugeoip.country) {
			uwsgi_log("unable to open GeoIP country database: %s\n", ugeoip.country_db);
			exit(1);
		}
	}

	if (ugeoip.city_db) {
                ugeoip.city = GeoIP_open(ugeoip.city_db, ugeoip.use_disk ? GEOIP_STANDARD : GEOIP_MEMORY_CACHE);
                if (!ugeoip.city) {
                        uwsgi_log("unable to open GeoIP city database: %s\n", ugeoip.city_db);
                        exit(1);
                }
        }
	return 0;
}

static char *uwsgi_route_var_geoip(struct wsgi_request *wsgi_req, char *key, uint16_t keylen, uint16_t *vallen) {
	uint32_t ip;
	char ip_str[16];
	// should be enough for geo coords
	char lonlat[64];
	memset(ip_str, 0, 16);
	memcpy(ip_str, wsgi_req->remote_addr, wsgi_req->remote_addr_len);
	if (inet_pton(AF_INET, ip_str, &ip) <= 0) {
		return NULL;
	}
	ip = htonl(ip);
	char *value = NULL;
	// always prefer the city database;
	GeoIP *g = ugeoip.city;
	if (!g) {
		g = ugeoip.country;
		if (g) {
			if (!uwsgi_strncmp(key, keylen, "country_code", 12)) {
				value = (char *) GeoIP_country_code_by_ipnum(g, ip);
			}
			else if (!uwsgi_strncmp(key, keylen, "country_code3", 13)) {
				value = (char *) GeoIP_country_code3_by_ipnum(g, ip);
			}
			else if (!uwsgi_strncmp(key, keylen, "country_name", 12)) {
				value = (char *) GeoIP_country_name_by_ipnum(g, ip);
			}

			if (value) {
				*vallen = strlen(value);
				return uwsgi_str(value);
			}
		}
		return NULL;
	}

	GeoIPRecord  *gr = GeoIP_record_by_ipnum(g, ip);
	if (!gr) return NULL; 

	// ok let's generate the output
	if (!uwsgi_strncmp(key, keylen, "continent", 9)) {
		value = gr->continent_code;
	}
	else if (!uwsgi_strncmp(key, keylen, "country_code", 12)) {
		value = gr->country_code;
	}
	else if (!uwsgi_strncmp(key, keylen, "country_code3", 13)) {
		value = gr->country_code3;
	}
	else if (!uwsgi_strncmp(key, keylen, "country_name", 12)) {
		value = gr->country_name;
	}
	else if (!uwsgi_strncmp(key, keylen, "region", 6)) {
		value = gr->region;
	}
	else if (!uwsgi_strncmp(key, keylen, "region_name", 11)) {
		value = (char *) GeoIP_region_name_by_code(gr->country_code, gr->region);
	}
	else if (!uwsgi_strncmp(key, keylen, "city", 4)) {
		value = gr->city;
	}
	else if (!uwsgi_strncmp(key, keylen, "postal_code", 11)) {
		value = gr->postal_code;
	}
	else if (!uwsgi_strncmp(key, keylen, "latitude", 8) || !uwsgi_strncmp(key, keylen, "lat", 3)) {
		snprintf(lonlat, 64, "%f", gr->latitude);
		value = lonlat;
	}
	else if (!uwsgi_strncmp(key, keylen, "longitude", 9) || !uwsgi_strncmp(key, keylen, "lon", 3)) {
		snprintf(lonlat, 64, "%f", gr->longitude);
		value = lonlat;
	}
	else if (!uwsgi_strncmp(key, keylen, "dma", 3)) {
		snprintf(lonlat, 64, "%d", gr->dma_code);
		value = lonlat;
	}
	else if (!uwsgi_strncmp(key, keylen, "area", 4)) {
		snprintf(lonlat, 64, "%d", gr->area_code);
		value = lonlat;
	}

	
	if (value) {
		*vallen = strlen(value);
                char *ret = uwsgi_str(value);
		GeoIPRecord_delete(gr);
		return ret;
	}

	GeoIPRecord_delete(gr);
	return NULL;
}

static void register_route_vars_geoip() {
	struct uwsgi_route_var *urv = uwsgi_register_route_var("geoip", uwsgi_route_var_geoip);
	urv->need_free = 1;
}

struct uwsgi_plugin geoip_plugin = {
	.name = "geoip",
	.options = uwsgi_geoip_options,
	.init = uwsgi_geoip_init,
	.on_load = register_route_vars_geoip,
};
