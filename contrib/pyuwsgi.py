import sys
import os
import pyuwsgi

orig_args = sys.argv
orig_executable = sys.executable
orig_args.insert(0, orig_executable)

uwsgi_args = []

for arg in sys.argv[2:]:
    uwsgi_args.append(arg)

# pyuwsgi.run('welcome.ini')
pyuwsgi.run(uwsgi_args)

# if you are here uWSGI has been reloaded
os.execv(orig_executable, orig_args)
