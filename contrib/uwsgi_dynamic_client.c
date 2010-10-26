/*

 *** uWSGI cgi client ***

 to compile:
 gcc -Wall -o uwsgi_client.cgi uwsgi_dynamic_client.c

*/

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>


#define UWSGI_SOCK "/tmp/uwsgi.sock"
#define UWSGI_SCRIPT "myapp_wsgi"

int main() {
	extern char **environ;
	char *env;
	struct sockaddr_un s_addr;
	int uwsgi_socket;
	int res, cnt;
	char *place_holder;

	unsigned short len;
	char message[4096];
	char *mptr;

	memset(&s_addr, 0, sizeof(struct sockaddr_un));

	s_addr.sun_family = AF_UNIX;
	strcpy(s_addr.sun_path, UWSGI_SOCK);

	uwsgi_socket = socket(AF_UNIX, SOCK_STREAM, 0);
	if (uwsgi_socket < 0) {
		perror("socket()");
		exit(1);
	}

	if (connect(uwsgi_socket, (struct sockaddr *) &s_addr, strlen(UWSGI_SOCK) + ( (void *)&s_addr.sun_path - (void *)&s_addr) ) != 0) {
		perror("connect()");
		exit(1);
	}

	memset(message, 0, 4096);

	mptr = message+4;
	if (setenv("UWSGI_SCRIPT", UWSGI_SCRIPT, 1) != 0) {
		perror("setenv()");
		exit(1);
	}
	if (**environ) {
		while( (env = *environ) ) {
			place_holder = strchr(env,'=');
			// key
			len = place_holder-env;
			memcpy(mptr, &len, 2);
			mptr+=2;
			memcpy(mptr, env, len);
			mptr+=len;
			// value
			len = (unsigned short) (env+strlen(env) - (place_holder+1));
			memcpy(mptr, &len, 2);
			mptr+=2;
			memcpy(mptr, place_holder+1, len);
			mptr+= len;
			*environ++;
		}
	}

	message[0] = 0;
	len = (mptr-message)-4;
	memcpy(message+1, &len, 2);
	message[3] = 0;

	res = send(uwsgi_socket, message, mptr-message, 0);

	while( (cnt = read(0, message, 4096)) ) {
		send(uwsgi_socket, message, cnt, 0);
	}

	if (res == mptr-message) {
		while( (res = recv(uwsgi_socket, message, 4096,0)) ) {
			write(1, message, res);
		}
	}

	return 0;

}

