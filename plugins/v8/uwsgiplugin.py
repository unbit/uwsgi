NAME='v8'

CFLAGS = ['-Wno-deprecated-declarations']
LDFLAGS = []
LIBS = ['-lv8']
GCC_LIST = ['plugin', 'v8_uwsgi.cc', 'v8_commonjs.cc', 'v8_jsgi.cc']
