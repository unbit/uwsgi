import os
NAME='v8'

CFLAGS = ['-Wno-deprecated-declarations']
LDFLAGS = []
LIBS = ['-lstdc++', '-lv8']
engine = os.environ.get('UWSGICONFIG_V8_ENGINE', '')
if engine == 'teajs':
    CFLAGS.append('-DUWSGI_V8_TEAJS -fexceptions')
    LIBS.append('-lteajs')
GCC_LIST = ['plugin', 'v8_uwsgi.cc', 'v8_commonjs.cc', 'v8_jsgi.cc']
