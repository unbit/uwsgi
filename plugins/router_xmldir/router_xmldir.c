/*
 * Copyright (C) 2013 Unbit S.a.s. <info@unbit.it>
 * Copyright (C) 2013 Guido Berhoerster <guido+uwsgi@berhoerster.name>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,  USA.
 *
 */

#include <uwsgi.h>
#include <locale.h>
#include <iconv.h>
#include <langinfo.h>

#ifndef UWSGI_XML_LIBXML2
#error you need a libxml2-enabled build of uWSGI to use the router_xmldir plugin
#endif

#include <libxml/tree.h>

static struct router_xmldir_conf {
	char *codeset;
} conf;

void *xrealloc(void *ptr, size_t size) {
	void *tmp;

	tmp = realloc(ptr, size);
	if (tmp == NULL) {
		uwsgi_error("realloc()");
		exit(1);
	}

	return (tmp);
}

char *to_utf8(char *codeset, char *in) {
	size_t buf_size;
	size_t buf_offset;
	size_t in_remaining;
	size_t buf_remaining;
	size_t ret;
	char *buf = NULL;
	char *buf_ptr;
	char *in_ptr = in;
	static iconv_t cd = (iconv_t)-1;
	/* UTF-8 encoded Unicode replacement char (U+FFFD) */
	const char repl[] = "\xef\xbf\xbd";

	if (cd == (iconv_t)-1) {
		if ((cd = iconv_open("UTF-8", codeset)) == (iconv_t)-1) {
			uwsgi_error("iconv_open");
			return (NULL);
		}
	}

	in_remaining = strlen(in) + 1;
	buf_size = buf_remaining = in_remaining;
	buf = buf_ptr = uwsgi_malloc(buf_size);

	while (in_remaining > (size_t)0) {
		ret = iconv(cd, &in_ptr, &in_remaining, &buf_ptr,
		    &buf_remaining);
		if (ret == (size_t)-1) {
			switch (errno) {
			case EINVAL:
				/* truncate */
				in_remaining = 0;
				*buf_ptr = '\0';
				break;
			case EILSEQ:
				/*
				 * insert a replacement character for each
				 * illegal sequence
				 */
				in_ptr++;
				in_remaining--;
				if (buf_remaining < sizeof (repl)) {
					buf_size += in_remaining +
					    sizeof (repl) - 1;
					buf_remaining += in_remaining +
					    sizeof (repl) - 1;
					buf_offset = buf_ptr - buf;
					buf = xrealloc(buf, buf_size);
					buf_ptr = buf + buf_offset;
				}
				strcat(buf_ptr, repl);
				buf_ptr += sizeof (repl) - 1;
				buf_remaining -= sizeof (repl) - 1;
				break;
			case E2BIG:
				buf_size += in_remaining;
				buf_remaining += in_remaining;
				buf_offset = buf_ptr - buf;
				buf = xrealloc(buf, buf_size);
				buf_ptr = buf + buf_offset;
				break;
			default:
				uwsgi_error("iconv");
				free(buf);
				return (NULL);
			}
		}
	}

	buf = xrealloc(buf, strlen(buf) + 1);
	return (buf);
}

static int uwsgi_routing_func_xmldir(struct wsgi_request *wsgi_req, struct uwsgi_route *ur){
	char **subject;
	uint16_t *subject_len;
	char *dirname;
	struct uwsgi_buffer *ub;
	char *name = NULL;
	char *path = NULL;
	int i;
	int n;
	struct dirent **tasklist;
	xmlDoc *rdoc;
	xmlNode *rtree;
	xmlNodePtr entrynode;
	char *path_info = NULL;
	struct stat sb;
	size_t sizebuf_len;
	char *sizebuf;
	char timebuf[20];
	int xlen = 0;

	subject = (char **) (((char *)(wsgi_req))+ur->subject);
	subject_len = (uint16_t *) (((char *)(wsgi_req))+ur->subject_len);
	ub = uwsgi_routing_translate(wsgi_req, ur, *subject, *subject_len,
	    ur->data, ur->data_len);
	if (!ub) {
		uwsgi_500(wsgi_req);
		return UWSGI_ROUTE_BREAK;
	}
	dirname = ub->buf;

	path_info = uwsgi_concat2n(wsgi_req->path_info, wsgi_req->path_info_len,
	    "", 1);

	n = scandir(dirname, &tasklist, 0, alphasort);
	if (n < 0) {
		uwsgi_404(wsgi_req);
		goto out;
	}

	rdoc = xmlNewDoc(BAD_CAST "1.0");
	rtree = xmlNewNode(NULL, BAD_CAST "index");
	xmlNewProp(rtree, BAD_CAST "path", BAD_CAST path_info);
	xmlDocSetRootElement(rdoc, rtree);

	for(i = 0; i < n; i++) {
		if ((strcmp(tasklist[i]->d_name, ".") == 0) ||
		    (strcmp(tasklist[i]->d_name, "..") == 0)) {
			goto next_entry;
		}

		path = uwsgi_concat3(dirname, "/", tasklist[i]->d_name);
		if (lstat(path, &sb) == -1) {
			goto next_entry;
		}

		name = to_utf8(conf.codeset, tasklist[i]->d_name);
		if (name == NULL) {
			goto next_entry;
		}

		if (S_ISDIR(sb.st_mode)) {
			entrynode = xmlNewTextChild(rtree, NULL,
			    BAD_CAST "directory", BAD_CAST name);
		} else if (S_ISREG(sb.st_mode)) {
			entrynode = xmlNewTextChild(rtree, NULL,
			    BAD_CAST "file", BAD_CAST name);
		} else {
			/* skip everything but directories and regular files */
			goto next_entry;
		}

		sizebuf_len = snprintf(NULL, 0, "%jd", (intmax_t) sb.st_size);
		sizebuf = uwsgi_malloc(sizebuf_len + 1);
		snprintf(sizebuf, sizebuf_len + 1, "%jd", (intmax_t) sb.st_size);
		xmlNewProp(entrynode, BAD_CAST "size", BAD_CAST sizebuf);
		free(sizebuf);

		strftime(timebuf, sizeof (timebuf), "%Y-%m-%dT%H:%M:%S",
		    localtime(&sb.st_mtime));
		xmlNewProp(entrynode, BAD_CAST "mtime", BAD_CAST timebuf);

next_entry:
		free(path);
		path = NULL;
		free(tasklist[i]);
		free(name);
		name = NULL;
	}

	free(tasklist);

	xmlChar *xmlbuf;
	xmlDocDumpFormatMemory(rdoc, &xmlbuf, &xlen, 1);

	uwsgi_response_prepare_headers(wsgi_req,"200 OK", 6);
	uwsgi_response_write_body_do(wsgi_req, (char *) xmlbuf, xlen);

	xmlFreeDoc(rdoc);
	xmlFree(xmlbuf);

out:
	uwsgi_buffer_destroy(ub);
	free(path_info);

	return UWSGI_ROUTE_BREAK;
}


static int uwsgi_router_xmldir(struct uwsgi_route *ur, char *args) {
	ur->func = uwsgi_routing_func_xmldir;
	ur->data = args;
	ur->data_len = strlen(args);

	return 0;
}

static void router_xmldir_register(void) {
	char *codeset;

	uwsgi_register_router("xmldir", uwsgi_router_xmldir);

	setlocale(LC_ALL, "");

	codeset = nl_langinfo(CODESET);
	if (*codeset == '\0') {
		codeset = "ASCII";
	}

	conf.codeset = uwsgi_str(codeset);
	if (conf.codeset == NULL) {
		uwsgi_error("strdup()");
		exit(1);
	}
}

struct uwsgi_plugin router_xmldir_plugin = {
	.name = "router_xmldir",
	.on_load = router_xmldir_register,
};
