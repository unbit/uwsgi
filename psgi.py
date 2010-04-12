import uwsgi

uwsgi.load_plugin(0, "plugins/psgi/psgi_plugin.so", "test.psgi")
