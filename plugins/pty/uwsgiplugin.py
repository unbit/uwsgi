NAME='pty'

import os
uwsgi_os = os.uname()[0]

CFLAGS = []
LDFLAGS = []
if uwsgi_os == 'Linux':
    LIBS = ['-lutil']
else:
    LIBS = []
GCC_LIST = ['pty']
