import os

NAME = 'systemd_logger'

CFLAGS = os.popen('pkg-config --cflags libsystemd-journal').read().rstrip().split()
CFLAGS += os.popen('pkg-config --cflags libsystemd').read().rstrip().split()
LDFLAGS = []
LIBS = os.popen('pkg-config --libs libsystemd-journal').read().rstrip().split()
LIBS += os.popen('pkg-config --libs libsystemd').read().rstrip().split()
GCC_LIST = ['systemd_logger']
