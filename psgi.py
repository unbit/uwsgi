import uwsgi
import sys

if uwsgi.load_plugin(0, "plugins/psgi/psgi_plugin.so", "mojoapp.pl"):
    print "PSGI plugin loaded"
else:
    print "unable to load PSGI plugin"
    sys.exit(1)
