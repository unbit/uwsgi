NAME='mongodb'

CFLAGS = []
LDFLAGS = []
LIBS = ['-Wl,-whole-archive', '-lmongoclient', '-Wl,-no-whole-archive', '-lboost_thread', '-lboost_system', '-lboost_filesystem']

GCC_LIST = ['plugin']

