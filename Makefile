CC=gcc

PYTHON_CFLAGS=`python-config --cflags`
PYTHON_LIBS=`python-config --libs`

UWSGI_CFLAGS=`python uwsgiconfig.py --cflags`
UWSGI_LDFLAGS=`python uwsgiconfig.py --ldflags`

CFLAGS=$(PYTHON_CFLAGS) $(UWSGI_CFLAGS)
LD_FLAGS=$(PYTHON_LIBS) $(UWSGI_LDFLAGS) -export-dynamic

PROGRAM=uwsgi

include base.mk
