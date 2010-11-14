#ifdef UWSGI_YAML

#include "uwsgi.h"

extern struct uwsgi_server uwsgi;

/*
   yaml file must be read ALL into memory.
   This memory must not be freed for all the server lifecycle
   */

void yaml_rstrip(char *line) {

	off_t i;

	for(i = strlen(line)-1;i>=0; i--) {
		if (line[i] == ' ' || line[i] == '\t') {
			line[i] = 0;
			continue;
		}
		break;
	}
}

char *yaml_lstrip(char *line) {

        off_t i;
        char *ptr = line;

        for(i=0;i< (int) strlen(line);i++) {
                if (line[i] == ' ' || line[i] == '\t') {
                        ptr++;
                        continue;
                }
                break;
        }

        return ptr;
}


int yaml_get_depth(char *line) {

	off_t i;
	int depth = 0;

	for(i=0;i< (int) strlen(line);i++) {
		if (line[i] == ' ') {
			depth++;
			continue;
		}
		else if (line[i] == '\t') {
			depth+=8;
			continue;
		}
		break;
	}

	return depth;
}

char *yaml_get_line(char *yaml, off_t size) {

	off_t i;
	char *ptr = yaml;
	int comment = 0;

	for(i=0;i<size;i++) {
		ptr++;
		if (yaml[i] == '#') {
			yaml[i] = 0;
			comment = 1;	
		}
		else if (yaml[i] == '\n') {
			yaml[i] = 0;
			return ptr;
		}
		else if (comment) {
			yaml[i] = 0;
		}
	}

	return NULL;

}

void uwsgi_yaml_config(char *file) {

	int fd;
	ssize_t len;
	char *yaml;
	struct stat sb;

	int depth;
	int current_depth = 0;
	int in_uwsgi_section = 0;

	char *yaml_line;

	char *section = "";
	char *key;
	char *val;

	int lines = 1;

	struct option *lopt, *aopt;
	char *section_asked = "uwsgi";
	char *colon;

	colon = strchr(file, ':');
	if (colon) {
		colon[0] = 0;
		if (colon[1] != 0) {
			section_asked = colon+1;
		}
	}

	uwsgi_log("[uWSGI] getting YAML configuration from %s\n", file);

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		uwsgi_error("open()");
		exit(1);
	}

	if (fstat(fd, &sb)) {
		uwsgi_error("fstat()");
		exit(1);
	}


	yaml = malloc(sb.st_size+1);

	if (!yaml) {
		uwsgi_error("malloc()");
		exit(1);
	}


	len = read(fd, yaml, sb.st_size);
	if (len != sb.st_size) {
		uwsgi_error("read()");
		exit(1);
	}

	yaml[sb.st_size] = 0;

	while(sb.st_size) {
		yaml_line = yaml_get_line(yaml, sb.st_size);
		if (yaml_line == NULL) {
			break;
		}
		lines++;

		// skip empty line
		if (yaml[0] == 0) goto next;
		depth = yaml_get_depth(yaml);
		if (depth <= current_depth) {
			current_depth = depth;
			// end the parsing cycle
			if (in_uwsgi_section) goto end;
		}
		else if (depth > current_depth && !in_uwsgi_section) {
			goto next;
		}

		key = yaml_lstrip(yaml);
		// skip empty line
		if (key[0] == 0) goto next;

		// skip list and {} defined dict
		if (key[0] == '-' || key[0] == '[' || key[0] == '{') {
			if (in_uwsgi_section) goto end;
			goto next;
		}
		
		if (!in_uwsgi_section) {
			section = strchr(key,':');
			if (!section) goto next;		
			section[0] = 0;
			if (!strcmp(key, section_asked)) {
				in_uwsgi_section = 1;
			}
		}
		else {
			// get dict value	
			val = strstr(key, ": ");
			if (!val) {
				val = strstr(key, ":\t");
			}
			if (!val) goto end;
			// get the right key
			val[0] = 0;
			// yeah overengeneering....
			yaml_rstrip(key);

			val = yaml_lstrip(val+2);
			yaml_rstrip(val);
			
			//uwsgi_log("YAML: %s = %s\n", key, val);

			lopt = uwsgi.long_options;
			while ((aopt = lopt)) {
				if (!aopt->name)
					break;
				if (!strcmp(key, aopt->name)) {
					if (aopt->flag) {
						*aopt->flag = aopt->val;
						add_exported_option(0, (char *)key);
					}
					else {
						manage_opt(aopt->val, val);
					}
				}
				lopt++;
			}
		}
next:
		sb.st_size -= (yaml_line - yaml);
		yaml += (yaml_line - yaml);

	}

end:

	close(fd);

}

#endif
