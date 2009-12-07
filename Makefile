CC=gcc

PYTHON_CFLAGS=`python-config --cflags`
PYTHON_LIBS=`python-config --libs`
XML_CFLAGS=`xml2-config --cflags`
XML_LIBS=`xml2-config --libs`

CFLAGS=$(PYTHON_CFLAGS) $(XML_CFLAGS)
LD_FLAGS=$(PYTHON_LIBS) $(XML_LIBS)

PROGRAM=uwsgi

include base.mk
