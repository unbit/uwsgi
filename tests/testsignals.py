import uwsgi

# send a raw signal to register with file_monitor subsystem
# uwsgi.signal(10, "/tmp/topolino")
uwsgi.signal(10, "/tmp")
# uwsgi.signal(10, "/root")

# send a raw signal to register with timer subsystem
uwsgi.signal(11, "3")
uwsgi.signal(11, "4")
uwsgi.signal(11, "8")


def application(e, s):
        s('200 Ok', [('Content-Type', 'text/html')])
        return "<h1>Hello World</h1>"
