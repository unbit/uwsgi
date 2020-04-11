NAME = "pyexample"

CFLAGS = [
    "-pthread",
    "-DNDEBUG",
    "-I/home/vagrant/opt/pypy3/include",
    "-I/home/vagrant/opt/pypy3.6-v7.3.0-linux64/include",
]
LDFLAGS = [
    "-L/home/vagrant/opt/pypy3/bin/",
    "-Wl,-rpath=/home/vagrant/opt/pypy3/bin/",
    "-lpypy3-c",
    "-L/home/vagrant/opt/pypy3/bin/",
]
LIBS = []
GCC_LIST = ["pyexample_plugin"]
