int uwsgi_init(int, char **, char **);

int main(int argc, char *argv[], char **environ) {
	return uwsgi_init(argc, argv, environ);
}
