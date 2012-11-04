import os
NAME='go'

CFLAGS = []
LDFLAGS = []
LIBS = []
GCC_LIST = ['go_plugin']

def post_build(config):
    os.environ['GOPATH'] = 'plugins/go'
    cflags = ['-I'+os.getcwd(),'-Wno-implicit-function-declaration','-Wno-implicit-int','-Wno-unused-function'] 
    for c in config.cflags:
        if not c.startswith('-DUWSGI_BUILD_DATE') and not c.startswith('-DUWSGI_CFLAGS'):
            cflags.append(c)
    
    os.environ['CGO_CFLAGS'] = ' '.join(cflags).replace('\\"', '')
    base = os.path.dirname(config.get('bin_name'))
    if not base:
        base = "."
    os.environ['CGO_LDFLAGS'] = '-L' + base + ' -L'+os.getcwd() + ' -luwsgi'
    if os.system("go install uwsgi") != 0:
        os._exit(1)
