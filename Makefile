CC=gcc

PYTHON_CFLAGS=`python2.5-config --cflags`
PYTHON_LIBS=`python2.5-config --libs`

UWSGI_CFLAGS=`python2.5 uconfig.py --cflags`
UWSGI_LDFLAGS=`python2.5 uconfig.py --ldflags`

CFLAGS=$(PYTHON_CFLAGS) $(UWSGI_CFLAGS)
LD_FLAGS=$(PYTHON_LIBS) $(UWSGI_LDFLAGS)

PROGRAM=uwsgi

include base.mk
