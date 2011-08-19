/* this is a skeleton to use libuwsgi in external projects */

extern char **environ;

int uwsgi_init(int, char **, char **);

int main(int argc, char **argv, char **environ) {

	uwsgi_init(argc, argv, environ);
}
