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

void uwsgi_yaml_config(char *file, char *magic_table[]) {

	int len = 0;
	char *yaml;

	int depth;
	int current_depth = 0;
	int in_uwsgi_section = 0;

	char *yaml_line;

	char *section = "";
	char *key;
	char *val;

	int lines = 1;

	char *section_asked = "uwsgi";
	char *colon;

	colon = uwsgi_get_last_char(file, ':');
	if (colon) {
		colon[0] = 0;
		if (colon[1] != 0) {
			section_asked = colon+1;
		}
	}

	uwsgi_log("[uWSGI] getting YAML configuration from %s\n", file);

	yaml = uwsgi_open_and_read(file, &len, 1, magic_table);

	while(len) {
		yaml_line = yaml_get_line(yaml, len);
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
			if (in_uwsgi_section) return;
		}
		else if (depth > current_depth && !in_uwsgi_section) {
			goto next;
		}

		key = yaml_lstrip(yaml);
		// skip empty line
		if (key[0] == 0) goto next;

		// skip list and {} defined dict
		if (key[0] == '-' || key[0] == '[' || key[0] == '{') {
			if (in_uwsgi_section) return;
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
			if (!val) return; 
			// get the right key
			val[0] = 0;
			// yeah overengeneering....
			yaml_rstrip(key);

			val = yaml_lstrip(val+2);
			yaml_rstrip(val);
			
			//uwsgi_log("YAML: %s = %s\n", key, val);

			add_exported_option((char *)key, val, 0);
		}
next:
		len -= (yaml_line - yaml);
		yaml += (yaml_line - yaml);

	}


}

#endif
