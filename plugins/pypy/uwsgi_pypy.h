#ifndef _UWSGI_PYPY_H
#define _UWSGI_PYPY_H

struct uwsgi_pypy {
  char *homedir;
  char *wsgi_app;
};

extern struct uwsgi_plugin pypy_plugin;
extern struct uwsgi_pypy uwsgi_pypy_settings;

#endif
