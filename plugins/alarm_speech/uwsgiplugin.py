import os

NAME='alarm_speech'

uwsgi_os = os.uname()[0]

LDFLAGS = []
if uwsgi_os == "Darwin":
    CFLAGS = []
    LIBS = ['-framework AppKit']
else:
    CFLAGS = ['-I /usr/include/GNUstep']
    LIBS = []

GCC_LIST = ['alarm_speech.m']
