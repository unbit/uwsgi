import os

NAME = 'systemd_logger'

if os.popen('pkg-config --exists libsystemd-journal').close() is None:
	CFLAGS = os.popen('pkg-config --cflags libsystemd-journal').read().rstrip().split()
	LIBS = os.popen('pkg-config --libs libsystemd-journal').read().rstrip().split()
else:
	CFLAGS = os.popen('pkg-config --cflags libsystemd').read().rstrip().split()
	LIBS = os.popen('pkg-config --libs libsystemd').read().rstrip().split()

LDFLAGS = []

GCC_LIST = ['systemd_logger']
