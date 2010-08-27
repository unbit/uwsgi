#ifdef UWSGI_INI

#include "uwsgi.h"

/*
	ini file must be read ALL into memory.
	This memory must not be freed for all the server lifecycle
*/

enum {
	ini_key_start,
	ini_val_start,
};

void ini_rstrip(char *line) {

	off_t i ;

	for(i = strlen(line)-1;i>=0; i--) {
		if (line[i] == ' ' || line[i] == '\t') {
			line[i] = 0;
			continue;
		}
		break;
	} 
}

char *ini_lstrip(char *line) {
	
	off_t i ;
	char *ptr = line;

	for(i=0;i<strlen(line);i++) {
		if (line[i] == ' ' || line[i] == '\t') {
			ptr++;
			continue;
		}
		break;
	}

	return ptr;
}

char *ini_get_key(char *key) {

	off_t i;
	char *ptr = key ;

	for(i=0;i<strlen(key);i++) {
		ptr++ ;	
		if (key[i] == '=') {
			key[i] = 0;
			return ptr;
		}
	}

	return ptr;
}

char *ini_get_line(char *ini, off_t size) {

	off_t i ;
	char *ptr = ini;
	
	for(i=0;i<size;i++) {
		ptr++;
		if (ini[i] == '\n') {
			ini[i] = 0;
			return ptr;
		}
	}

	return NULL;
	
}

void uwsgi_ini_config(char *file, struct option *long_options) {

	int fd;
	ssize_t len;
	char *ini;
	struct stat sb;

	char *ini_line;

	char *section = "";
	char *key;
	char *val;

	int lines = 1 ;

	struct option *lopt, *aopt;
	char *section_asked = "uwsgi";
	char *colon ;

	colon = strchr(file, ':');
	if (colon) {
		colon[0] = 0;
		if (colon[1] != 0) {
			section_asked = colon+1 ;
		}
	}

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		uwsgi_error("open()");
		exit(1);
	}
	
	if (fstat(fd, &sb)) {
		uwsgi_error("fstat()");
		exit(1);
	}

	ini = malloc(sb.st_size+1);

	if (!ini) {
		uwsgi_error("malloc()");
		exit(1);
	}

	len = read(fd, ini, sb.st_size);
	if (len != sb.st_size) {
		uwsgi_error("read()");
		exit(1);
	}

	ini[sb.st_size+1] = 0 ;

	while(sb.st_size) {
		ini_line = ini_get_line(ini, sb.st_size);
		if (ini_line == NULL) {
			break;
		}
		lines++;

		// skip empty line
		key = ini_lstrip(ini);
		ini_rstrip(key);
		if (key[0] != 0) {
			if (key[0] == '[') {
				section = key+1;
				section[strlen(section)-1] = 0;
			}
			else if (key[0] == ';' || key[0] == '#') {
				// this is a comment
			}
			else {
				// val is always valid, but (obviously can be ignored)
				val = ini_get_key(key);

				if (!strcmp(section, section_asked)) {
					ini_rstrip(key);
					val = ini_lstrip(val);
					ini_rstrip(val);
					lopt = long_options;
                                	while ((aopt = lopt)) {
                                       		if (!aopt->name)
                                               	break;
                                       		if (!strcmp(key, aopt->name)) {
                                               		if (aopt->flag) {
                                                       		*aopt->flag = aopt->val;
                                              		}
                                               		else {
                                                              		manage_opt(aopt->val, val);
                                               		}
                                       		}
                                       		lopt++;
                                	}
				}
			}
		}
		

		ini += (ini_line - ini);
		sb.st_size -= (ini_line - ini);

	}

	close(fd);
	
}


#endif
